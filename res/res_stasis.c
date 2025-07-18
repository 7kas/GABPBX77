/*
 * GABpbx -- An open source telephony toolkit.
 *
 * Copyright (C) 2012 - 2013, Digium, Inc.
 *
 * David M. Lee, II <dlee@digium.com>
 *
 * See http://www.gabpbx.org for more information about
 * the GABpbx project. Please do not directly contact
 * any of the maintainers of this project for assistance;
 * the project provides a web site, mailing lists and IRC
 * channels for your use.
 *
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 */

/*! \file
 *
 * \brief Stasis application support.
 *
 * \author David M. Lee, II <dlee@digium.com>
 *
 * <code>res_stasis.so</code> brings together the various components of the
 * Stasis application infrastructure.
 *
 * First, there's the Stasis application handler, stasis_app_exec(). This is
 * called by <code>app_stasis.so</code> to give control of a channel to the
 * Stasis application code from the dialplan.
 *
 * While a channel is in stasis_app_exec(), it has a \ref stasis_app_control
 * object, which may be used to control the channel.
 *
 * To control the channel, commands may be sent to channel using
 * stasis_app_send_command() and stasis_app_send_async_command().
 *
 * Alongside this, applications may be registered/unregistered using
 * stasis_app_register()/stasis_app_unregister(). While a channel is in Stasis,
 * events received on the channel's topic are converted to JSON and forwarded to
 * the \ref stasis_app_cb. The application may also subscribe to the channel to
 * continue to receive messages even after the channel has left Stasis, but it
 * will not be able to control it.
 *
 * Given all the stuff that comes together in this module, it's been broken up
 * into several pieces that are in <code>res/stasis/</code> and compiled into
 * <code>res_stasis.so</code>.
 */

/*** MODULEINFO
	<support_level>core</support_level>
 ***/

#include "gabpbx.h"

#include "gabpbx/astobj2.h"
#include "gabpbx/callerid.h"
#include "gabpbx/module.h"
#include "gabpbx/stasis_app_impl.h"
#include "gabpbx/stasis_channels.h"
#include "gabpbx/stasis_bridges.h"
#include "gabpbx/stasis_endpoints.h"
#include "gabpbx/stasis_message_router.h"
#include "gabpbx/strings.h"
#include "stasis/app.h"
#include "stasis/control.h"
#include "stasis/messaging.h"
#include "stasis/stasis_bridge.h"
#include "gabpbx/core_unreal.h"
#include "gabpbx/musiconhold.h"
#include "gabpbx/causes.h"
#include "gabpbx/stringfields.h"
#include "gabpbx/bridge_after.h"
#include "gabpbx/format_cache.h"

/*! Time to wait for a frame in the application */
#define MAX_WAIT_MS 200

/*!
 * \brief Number of buckets for the Stasis application hash table.  Remember to
 * keep it a prime number!
 */
#define APPS_NUM_BUCKETS 127

/*!
 * \brief Number of buckets for the Stasis application hash table.  Remember to
 * keep it a prime number!
 */
#define CONTROLS_NUM_BUCKETS 127

/*!
 * \brief Number of buckets for the Stasis bridges hash table.  Remember to
 * keep it a prime number!
 */
#define BRIDGES_NUM_BUCKETS 127

/*!
 * \brief Stasis application container.
 */
struct ao2_container *apps_registry;

struct ao2_container *app_controls;

struct ao2_container *app_bridges;

struct ao2_container *app_bridges_moh;

struct ao2_container *app_bridges_playback;

/*!
 * \internal \brief List of registered event sources.
 */
AST_RWLIST_HEAD_STATIC(event_sources, stasis_app_event_source);

static struct ast_json *stasis_end_to_json(struct stasis_message *message,
		const struct stasis_message_sanitizer *sanitize)
{
	struct ast_channel_blob *payload = stasis_message_data(message);
	struct ast_json *msg;

	if (sanitize && sanitize->channel_snapshot &&
			sanitize->channel_snapshot(payload->snapshot)) {
		return NULL;
	}

	msg = ast_json_pack("{s: s, s: O, s: o}",
		"type", "StasisEnd",
		"timestamp", ast_json_object_get(payload->blob, "timestamp"),
		"channel", ast_channel_snapshot_to_json(payload->snapshot, sanitize));
	if (!msg) {
		ast_log_chan(NULL, LOG_ERROR, "Failed to pack JSON for StasisEnd message\n");
		return NULL;
	}

	return msg;
}

STASIS_MESSAGE_TYPE_DEFN_LOCAL(end_message_type,
	.to_json = stasis_end_to_json);

struct start_message_blob {
	struct ast_channel_snapshot *channel;		/*!< Channel that is entering Stasis() */
	struct ast_channel_snapshot *replace_channel;	/*!< Channel that is being replaced (optional) */
	struct ast_json *blob;				/*!< JSON blob containing timestamp and args */
};

static struct ast_json *stasis_start_to_json(struct stasis_message *message,
		const struct stasis_message_sanitizer *sanitize)
{
	struct start_message_blob *payload = stasis_message_data(message);
	struct ast_json *msg;

	if (sanitize && sanitize->channel_snapshot &&
			sanitize->channel_snapshot(payload->channel)) {
		return NULL;
	}

	msg = ast_json_pack("{s: s, s: O, s: O, s: o}",
		"type", "StasisStart",
		"timestamp", ast_json_object_get(payload->blob, "timestamp"),
		"args", ast_json_object_get(payload->blob, "args"),
		"channel", ast_channel_snapshot_to_json(payload->channel, NULL));
	if (!msg) {
		ast_log_chan(NULL, LOG_ERROR, "Failed to pack JSON for StasisStart message\n");
		return NULL;
	}

	if (payload->replace_channel) {
		int res = ast_json_object_set(msg, "replace_channel",
			ast_channel_snapshot_to_json(payload->replace_channel, NULL));

		if (res) {
			ast_json_unref(msg);
			ast_log_chan(NULL, LOG_ERROR, "Failed to append JSON for StasisStart message\n");
			return NULL;
		}
	}

	return msg;
}

STASIS_MESSAGE_TYPE_DEFN_LOCAL(start_message_type,
	.to_json = stasis_start_to_json);

/*! AO2 hash function for \ref app */
static int app_hash(const void *obj, const int flags)
{
	const struct stasis_app *app;
	const char *key;

	switch (flags & OBJ_SEARCH_MASK) {
	case OBJ_SEARCH_KEY:
		key = obj;
		break;
	case OBJ_SEARCH_OBJECT:
		app = obj;
		key = stasis_app_name(app);
		break;
	default:
		/* Hash can only work on something with a full key. */
		ast_assert(0);
		return 0;
	}
	return ast_str_hash(key);
}

/*! AO2 comparison function for \ref app */
static int app_compare(void *obj, void *arg, int flags)
{
	const struct stasis_app *object_left = obj;
	const struct stasis_app *object_right = arg;
	const char *right_key = arg;
	int cmp;

	switch (flags & OBJ_SEARCH_MASK) {
	case OBJ_SEARCH_OBJECT:
		right_key = stasis_app_name(object_right);
		/* Fall through */
	case OBJ_SEARCH_KEY:
		cmp = strcmp(stasis_app_name(object_left), right_key);
		break;
	case OBJ_SEARCH_PARTIAL_KEY:
		/*
		 * We could also use a partial key struct containing a length
		 * so strlen() does not get called for every comparison instead.
		 */
		cmp = strncmp(stasis_app_name(object_left), right_key, strlen(right_key));
		break;
	default:
		/*
		 * What arg points to is specific to this traversal callback
		 * and has no special meaning to astobj2.
		 */
		cmp = 0;
		break;
	}
	if (cmp) {
		return 0;
	}
	/*
	 * At this point the traversal callback is identical to a sorted
	 * container.
	 */
	return CMP_MATCH;
}

/*! AO2 hash function for \ref stasis_app_control */
static int control_hash(const void *obj, const int flags)
{
	const struct stasis_app_control *control;
	const char *key;

	switch (flags & OBJ_SEARCH_MASK) {
	case OBJ_SEARCH_KEY:
		key = obj;
		break;
	case OBJ_SEARCH_OBJECT:
		control = obj;
		key = stasis_app_control_get_channel_id(control);
		break;
	default:
		/* Hash can only work on something with a full key. */
		ast_assert(0);
		return 0;
	}
	return ast_str_hash(key);
}

/*! AO2 comparison function for \ref stasis_app_control */
static int control_compare(void *obj, void *arg, int flags)
{
	const struct stasis_app_control *object_left = obj;
	const struct stasis_app_control *object_right = arg;
	const char *right_key = arg;
	int cmp;

	switch (flags & OBJ_SEARCH_MASK) {
	case OBJ_SEARCH_OBJECT:
		right_key = stasis_app_control_get_channel_id(object_right);
		/* Fall through */
	case OBJ_SEARCH_KEY:
		cmp = strcmp(stasis_app_control_get_channel_id(object_left), right_key);
		break;
	case OBJ_SEARCH_PARTIAL_KEY:
		/*
		 * We could also use a partial key struct containing a length
		 * so strlen() does not get called for every comparison instead.
		 */
		cmp = strncmp(stasis_app_control_get_channel_id(object_left), right_key, strlen(right_key));
		break;
	default:
		/*
		 * What arg points to is specific to this traversal callback
		 * and has no special meaning to astobj2.
		 */
		cmp = 0;
		break;
	}
	if (cmp) {
		return 0;
	}
	/*
	 * At this point the traversal callback is identical to a sorted
	 * container.
	 */
	return CMP_MATCH;
}

static int cleanup_cb(void *obj, void *arg, int flags)
{
	struct stasis_app *app = obj;

	if (!app_is_finished(app)) {
		return 0;
	}

	ast_verb_chan(NULL, 1, "Shutting down application '%s'\n", stasis_app_name(app));
	app_shutdown(app);

	return CMP_MATCH;

}

/*!
 * \brief Clean up any old apps that we don't need any more.
 */
static void cleanup(void)
{
	ao2_callback(apps_registry, OBJ_MULTIPLE | OBJ_NODATA | OBJ_UNLINK,
		cleanup_cb, NULL);
}

struct stasis_app_control *stasis_app_control_create(struct ast_channel *chan)
{
	return control_create(chan, NULL);
}

struct stasis_app_control *stasis_app_control_find_by_channel(
	const struct ast_channel *chan)
{
	if (chan == NULL) {
		return NULL;
	}

	return stasis_app_control_find_by_channel_id(
		ast_channel_uniqueid(chan));
}

struct stasis_app_control *stasis_app_control_find_by_channel_id(
	const char *channel_id)
{
	return ao2_find(app_controls, channel_id, OBJ_SEARCH_KEY);
}

/*! AO2 hash function for bridges container  */
static int bridges_hash(const void *obj, const int flags)
{
	const struct ast_bridge *bridge;
	const char *key;

	switch (flags & OBJ_SEARCH_MASK) {
	case OBJ_SEARCH_KEY:
		key = obj;
		break;
	case OBJ_SEARCH_OBJECT:
		bridge = obj;
		key = bridge->uniqueid;
		break;
	default:
		/* Hash can only work on something with a full key. */
		ast_assert(0);
		return 0;
	}
	return ast_str_hash(key);
}

/*! AO2 comparison function for bridges container */
static int bridges_compare(void *obj, void *arg, int flags)
{
	const struct ast_bridge *object_left = obj;
	const struct ast_bridge *object_right = arg;
	const char *right_key = arg;
	int cmp;

	switch (flags & OBJ_SEARCH_MASK) {
	case OBJ_SEARCH_OBJECT:
		right_key = object_right->uniqueid;
		/* Fall through */
	case OBJ_SEARCH_KEY:
		cmp = strcmp(object_left->uniqueid, right_key);
		break;
	case OBJ_SEARCH_PARTIAL_KEY:
		/*
		 * We could also use a partial key struct containing a length
		 * so strlen() does not get called for every comparison instead.
		 */
		cmp = strncmp(object_left->uniqueid, right_key, strlen(right_key));
		break;
	default:
		/*
		 * What arg points to is specific to this traversal callback
		 * and has no special meaning to astobj2.
		 */
		cmp = 0;
		break;
	}
	if (cmp) {
		return 0;
	}
	/*
	 * At this point the traversal callback is identical to a sorted
	 * container.
	 */
	return CMP_MATCH;
}

/*! AO2 sort function for bridges container */
static int bridges_sort (const void *left, const void *right, const int flags)
{
	const struct ast_bridge *object_left = left;
	const struct ast_bridge *object_right = right;
	const char *right_key = right;
	int cmp;

	switch (flags & OBJ_SEARCH_MASK) {
	case OBJ_SEARCH_OBJECT:
		right_key = object_right->uniqueid;
		/* Fall through */
	case OBJ_SEARCH_KEY:
		cmp = strcmp(object_left->uniqueid, right_key);
		break;
	case OBJ_SEARCH_PARTIAL_KEY:
		cmp = strncmp(object_left->uniqueid, right_key, strlen(right_key));
		break;
	default:
		ast_assert(0);
		cmp = 0;
		break;
	}
	return cmp;
}

/*!
 *  Used with app_bridges_moh and app_bridge_control, they provide links
 *  between bridges and channels used for ARI application purposes
 */
struct stasis_app_bridge_channel_wrapper {
	AST_DECLARE_STRING_FIELDS(
		AST_STRING_FIELD(channel_id);
		AST_STRING_FIELD(bridge_id);
	);
};

/*! AO2 comparison function for bridges moh container */
static int bridges_channel_compare(void *obj, void *arg, int flags)
{
	const struct stasis_app_bridge_channel_wrapper *object_left = obj;
	const struct stasis_app_bridge_channel_wrapper *object_right = arg;
	const char *right_key = arg;
	int cmp;

	switch (flags & OBJ_SEARCH_MASK) {
	case OBJ_SEARCH_OBJECT:
			right_key = object_right->bridge_id;
	case OBJ_SEARCH_KEY:
			cmp = strcmp(object_left->bridge_id, right_key);
			break;
	case OBJ_SEARCH_PARTIAL_KEY:
			cmp = strncmp(object_left->bridge_id, right_key, strlen(right_key));
			break;
	default:
			cmp = 0;
			break;
	}
	if (cmp) {
		return 0;
	}
	return CMP_MATCH;
}

static void stasis_app_bridge_channel_wrapper_destructor(void *obj)
{
	struct stasis_app_bridge_channel_wrapper *wrapper = obj;
	ast_string_field_free_memory(wrapper);
}

/*! AO2 hash function for the bridges moh container */
static int bridges_channel_hash_fn(const void *obj, const int flags)
{
	const struct stasis_app_bridge_channel_wrapper *wrapper;
	const char *key;

	switch (flags & OBJ_SEARCH_MASK) {
	case OBJ_SEARCH_KEY:
		key = obj;
		break;
	case OBJ_SEARCH_OBJECT:
		wrapper = obj;
		key = wrapper->bridge_id;
		break;
	default:
		/* Hash can only work on something with a full key. */
		ast_assert(0);
		return 0;
	}
	return ast_str_hash(key);
}

static int bridges_channel_sort_fn(const void *obj_left, const void *obj_right, const int flags)
{
	const struct stasis_app_bridge_channel_wrapper *left = obj_left;
	const struct stasis_app_bridge_channel_wrapper *right = obj_right;
	const char *right_key = obj_right;
	int cmp;

	switch (flags & OBJ_SEARCH_MASK) {
	case OBJ_SEARCH_OBJECT:
		right_key = right->bridge_id;
		/* Fall through */
	case OBJ_SEARCH_KEY:
		cmp = strcmp(left->bridge_id, right_key);
		break;
	case OBJ_SEARCH_PARTIAL_KEY:
		cmp = strncmp(left->bridge_id, right_key, strlen(right_key));
		break;
	default:
		/* Sort can only work on something with a full or partial key. */
		ast_assert(0);
		cmp = 0;
		break;
	}
	return cmp;
}

/*! Request a bridge MOH channel */
static struct ast_channel *prepare_bridge_moh_channel(void)
{
	struct ast_channel *chan;
	struct ast_format_cap *cap;

	cap = ast_format_cap_alloc(AST_FORMAT_CAP_FLAG_DEFAULT);
	if (!cap) {
		return NULL;
	}

	ast_format_cap_append(cap, ast_format_slin, 0);

	chan = ast_request("Announcer", cap, NULL, NULL, "ARI_MOH", NULL);
	ao2_ref(cap, -1);

	return chan;
}

/*! Provides the moh channel with a thread so it can actually play its music */
static void *moh_channel_thread(void *data)
{
	struct stasis_app_bridge_channel_wrapper *moh_wrapper = data;
	struct ast_channel *moh_channel = ast_channel_get_by_name(moh_wrapper->channel_id);
	struct ast_frame *f;

	if (!moh_channel) {
		ao2_unlink(app_bridges_moh, moh_wrapper);
		ao2_ref(moh_wrapper, -1);
		return NULL;
	}

	/* Read and discard any frame coming from the stasis bridge. */
	for (;;) {
		if (ast_waitfor(moh_channel, -1) < 0) {
			/* Error or hungup */
			break;
		}

		f = ast_read(moh_channel);
		if (!f) {
			/* Hungup */
			break;
		}
		ast_frfree(f);
	}

	ao2_unlink(app_bridges_moh, moh_wrapper);
	ao2_ref(moh_wrapper, -1);

	ast_moh_stop(moh_channel);
	ast_hangup(moh_channel);

	return NULL;
}

/*!
 * \internal
 * \brief Creates, pushes, and links a channel for playing music on hold to bridge
 *
 * \param bridge Which bridge this moh channel exists for
 *
 * \retval NULL if the channel could not be created, pushed, or linked
 * \retval Reference to the channel on success
 */
static struct ast_channel *bridge_moh_create(struct ast_bridge *bridge)
{
	struct stasis_app_bridge_channel_wrapper *new_wrapper;
	struct ast_channel *chan;
	pthread_t threadid;

	chan = prepare_bridge_moh_channel();
	if (!chan) {
		return NULL;
	}

	if (stasis_app_channel_unreal_set_internal(chan)) {
		ast_hangup(chan);
		return NULL;
	}

	if (ast_unreal_channel_push_to_bridge(chan, bridge,
		AST_BRIDGE_CHANNEL_FLAG_IMMOVABLE | AST_BRIDGE_CHANNEL_FLAG_LONELY)) {
		ast_hangup(chan);
		return NULL;
	}

	new_wrapper = ao2_alloc_options(sizeof(*new_wrapper),
		stasis_app_bridge_channel_wrapper_destructor, AO2_ALLOC_OPT_LOCK_NOLOCK);
	if (!new_wrapper) {
		ast_hangup(chan);
		return NULL;
	}

	if (ast_string_field_init(new_wrapper, AST_UUID_STR_LEN + AST_CHANNEL_NAME)
		|| ast_string_field_set(new_wrapper, bridge_id, bridge->uniqueid)
		|| ast_string_field_set(new_wrapper, channel_id, ast_channel_uniqueid(chan))) {
		ao2_ref(new_wrapper, -1);
		ast_hangup(chan);
		return NULL;
	}

	if (!ao2_link_flags(app_bridges_moh, new_wrapper, OBJ_NOLOCK)) {
		ao2_ref(new_wrapper, -1);
		ast_hangup(chan);
		return NULL;
	}

	/* Pass the new_wrapper ref to moh_channel_thread() */
	if (ast_pthread_create_detached(&threadid, NULL, moh_channel_thread, new_wrapper)) {
		ast_log_chan(NULL, LOG_ERROR, "Failed to create channel thread. Abandoning MOH channel creation.\n");
		ao2_unlink_flags(app_bridges_moh, new_wrapper, OBJ_NOLOCK);
		ao2_ref(new_wrapper, -1);
		ast_hangup(chan);
		return NULL;
	}

	return chan;
}

struct ast_channel *stasis_app_bridge_moh_channel(struct ast_bridge *bridge)
{
	struct ast_channel *chan;
	struct stasis_app_bridge_channel_wrapper *moh_wrapper;

	ao2_lock(app_bridges_moh);
	moh_wrapper = ao2_find(app_bridges_moh, bridge->uniqueid, OBJ_SEARCH_KEY | OBJ_NOLOCK);
	if (!moh_wrapper) {
		chan = bridge_moh_create(bridge);
	}
	ao2_unlock(app_bridges_moh);

	if (moh_wrapper) {
		chan = ast_channel_get_by_name(moh_wrapper->channel_id);
		ao2_ref(moh_wrapper, -1);
	}

	return chan;
}

int stasis_app_bridge_moh_stop(struct ast_bridge *bridge)
{
	struct stasis_app_bridge_channel_wrapper *moh_wrapper;
	struct ast_channel *chan;

	moh_wrapper = ao2_find(app_bridges_moh, bridge->uniqueid, OBJ_SEARCH_KEY | OBJ_UNLINK);
	if (!moh_wrapper) {
		return -1;
	}

	chan = ast_channel_get_by_name(moh_wrapper->channel_id);
	ao2_ref(moh_wrapper, -1);
	if (!chan) {
		return -1;
	}

	ast_moh_stop(chan);
	ast_softhangup(chan, AST_CAUSE_NORMAL_CLEARING);
	ao2_cleanup(chan);

	return 0;
}

/*! Removes the bridge to playback channel link */
static void remove_bridge_playback(char *bridge_id)
{
	struct stasis_app_bridge_channel_wrapper *wrapper;
	struct stasis_app_control *control;

	wrapper = ao2_find(app_bridges_playback, bridge_id, OBJ_SEARCH_KEY | OBJ_UNLINK);

	if (wrapper) {
		control = stasis_app_control_find_by_channel_id(wrapper->channel_id);
		if (control) {
			ao2_unlink(app_controls, control);
			ao2_ref(control, -1);
		}
		ao2_ref(wrapper, -1);
	}
	ast_free(bridge_id);
}

static void playback_after_bridge_cb_failed(enum ast_bridge_after_cb_reason reason, void *data)
{
	char *bridge_id = data;

	remove_bridge_playback(bridge_id);
}

static void playback_after_bridge_cb(struct ast_channel *chan, void *data)
{
	char *bridge_id = data;

	remove_bridge_playback(bridge_id);
}

int stasis_app_bridge_playback_channel_add(struct ast_bridge *bridge,
	struct ast_channel *chan,
	struct stasis_app_control *control)
{
	RAII_VAR(struct stasis_app_bridge_channel_wrapper *, new_wrapper, NULL, ao2_cleanup);
	char *bridge_id = ast_strdup(bridge->uniqueid);

	if (!bridge_id) {
		return -1;
	}

	if (ast_bridge_set_after_callback(chan,
		playback_after_bridge_cb, playback_after_bridge_cb_failed, bridge_id)) {
		ast_free(bridge_id);
		return -1;
	}

	new_wrapper = ao2_alloc_options(sizeof(*new_wrapper),
		stasis_app_bridge_channel_wrapper_destructor, AO2_ALLOC_OPT_LOCK_NOLOCK);
	if (!new_wrapper) {
		return -1;
	}

	if (ast_string_field_init(new_wrapper, 32)) {
		return -1;
	}

	ast_string_field_set(new_wrapper, bridge_id, bridge->uniqueid);
	ast_string_field_set(new_wrapper, channel_id, ast_channel_uniqueid(chan));

	if (!ao2_link(app_bridges_playback, new_wrapper)) {
		return -1;
	}

	ao2_link(app_controls, control);
	return 0;
}

void stasis_app_bridge_playback_channel_remove(char *bridge_id,
	struct stasis_app_control *control)
{
	struct stasis_app_bridge_channel_wrapper *wrapper;

	wrapper = ao2_find(app_bridges_playback, bridge_id, OBJ_SEARCH_KEY | OBJ_UNLINK);
	if (wrapper) {
		/* If wrapper is not found, then that means the after bridge callback has been
		 * called or is in progress. No need to unlink the control here since that has
		 * been done or is about to be done in the after bridge callback
		 */
		ao2_unlink(app_controls, control);
		ao2_ref(wrapper, -1);
	}
}

struct ast_channel *stasis_app_bridge_playback_channel_find(struct ast_bridge *bridge)
{
	struct stasis_app_bridge_channel_wrapper *playback_wrapper;
	struct ast_channel *chan;

	playback_wrapper = ao2_find(app_bridges_playback, bridge->uniqueid, OBJ_SEARCH_KEY);
	if (!playback_wrapper) {
		return NULL;
	}

	chan = ast_channel_get_by_name(playback_wrapper->channel_id);
	ao2_ref(playback_wrapper, -1);
	return chan;
}

struct ast_bridge *stasis_app_bridge_find_by_id(
	const char *bridge_id)
{
	return ao2_find(app_bridges, bridge_id, OBJ_SEARCH_KEY);
}


/*!
 * \brief In addition to running ao2_cleanup(), this function also removes the
 * object from the app_controls container.
 */
static void control_unlink(struct stasis_app_control *control)
{
	if (!control) {
		return;
	}

	ao2_unlink(app_controls, control);
	ao2_cleanup(control);
}

static struct ast_bridge *bridge_create_common(const char *type, const char *name, const char *id, int invisible)
{
	struct ast_bridge *bridge;
	char *requested_type, *requested_types = ast_strdupa(S_OR(type, "mixing"));
	int capabilities = 0;
	int flags = AST_BRIDGE_FLAG_MERGE_INHIBIT_FROM | AST_BRIDGE_FLAG_MERGE_INHIBIT_TO
		| AST_BRIDGE_FLAG_SWAP_INHIBIT_FROM | AST_BRIDGE_FLAG_SWAP_INHIBIT_TO
		| AST_BRIDGE_FLAG_TRANSFER_BRIDGE_ONLY;
	enum ast_bridge_video_mode_type video_mode = AST_BRIDGE_VIDEO_MODE_TALKER_SRC;
	int send_sdp_label = 0;

	ast_debug(1, "Creating bridge of type '%s' with name '%s' and id '%s'\n",
		type, S_OR(name, "<unknown>"), S_OR(id, "<unknown>"));
	if (invisible) {
		flags |= AST_BRIDGE_FLAG_INVISIBLE;
	}

	if (!ast_strlen_zero(id)) {
		bridge = stasis_app_bridge_find_by_id(id);
		if (bridge) {
			ast_log_chan(NULL, LOG_WARNING, "Bridge with id '%s' already exists\n", id);
			ao2_ref(bridge, -1);
			return NULL;
		}
	}

	while ((requested_type = strsep(&requested_types, ","))) {
		requested_type = ast_strip(requested_type);

		if (!strcmp(requested_type, "mixing")) {
			capabilities |= STASIS_BRIDGE_MIXING_CAPABILITIES;
			flags |= AST_BRIDGE_FLAG_SMART;
		} else if (!strcmp(requested_type, "holding")) {
			capabilities |= AST_BRIDGE_CAPABILITY_HOLDING;
		} else if (!strcmp(requested_type, "dtmf_events") ||
			!strcmp(requested_type, "proxy_media")) {
			capabilities &= ~AST_BRIDGE_CAPABILITY_NATIVE;
		} else if (!strcmp(requested_type, "video_sfu")) {
			video_mode = AST_BRIDGE_VIDEO_MODE_SFU;
		} else if (!strcmp(requested_type, "video_single")) {
			video_mode = AST_BRIDGE_VIDEO_MODE_SINGLE_SRC;
		} else if (!strcmp(requested_type, "sdp_label")) {
			send_sdp_label = 1;
		}
	}

	/* For an SFU video bridge we ensure it always remains in multimix for the best experience. */
	if (video_mode == AST_BRIDGE_VIDEO_MODE_SFU) {
		capabilities = AST_BRIDGE_CAPABILITY_MULTIMIX;
		flags &= ~AST_BRIDGE_FLAG_SMART;
	}

	if (!capabilities
		/* Holding and mixing capabilities don't mix. */
		|| ((capabilities & AST_BRIDGE_CAPABILITY_HOLDING)
			&& (capabilities & (STASIS_BRIDGE_MIXING_CAPABILITIES)))) {
		return NULL;
	}

	bridge = bridge_stasis_new(capabilities, flags, name, id, video_mode, send_sdp_label);
	if (bridge) {
		if (!ao2_link(app_bridges, bridge)) {
			ast_bridge_destroy(bridge, 0);
			bridge = NULL;
		}
	}

	return bridge;
}

struct ast_bridge *stasis_app_bridge_create(const char *type, const char *name, const char *id)
{
	return bridge_create_common(type, name, id, 0);
}

struct ast_bridge *stasis_app_bridge_create_invisible(const char *type, const char *name, const char *id)
{
	return bridge_create_common(type, name, id, 1);
}

void stasis_app_bridge_destroy(const char *bridge_id)
{
	struct ast_bridge *bridge = stasis_app_bridge_find_by_id(bridge_id);
	if (!bridge) {
		return;
	}
	ast_debug(1, "Bridge " BRIDGE_PRINTF_SPEC ": destroying bridge\n",
		BRIDGE_PRINTF_VARS(bridge));

	ao2_unlink(app_bridges, bridge);
	ast_debug(1, "Bridge " BRIDGE_PRINTF_SPEC ": unlinked from app_bridges.  current refcount: %d\n",
		BRIDGE_PRINTF_VARS(bridge), ao2_ref(bridge, 0));
	ast_bridge_destroy(bridge, 0);
}

struct replace_channel_store {
	struct ast_channel_snapshot *snapshot;
	char *app;
};

static void replace_channel_destroy(void *obj)
{
	struct replace_channel_store *replace = obj;

	ao2_cleanup(replace->snapshot);
	ast_free(replace->app);
	ast_free(replace);
}

static const struct ast_datastore_info replace_channel_store_info = {
	.type = "replace-channel-store",
	.destroy = replace_channel_destroy,
};

static struct replace_channel_store *get_replace_channel_store(struct ast_channel *chan, int no_create)
{
	struct ast_datastore *datastore;
	struct replace_channel_store *ret;

	ast_channel_lock(chan);
	datastore = ast_channel_datastore_find(chan, &replace_channel_store_info, NULL);
	if (!datastore && !no_create) {
		datastore = ast_datastore_alloc(&replace_channel_store_info, NULL);
		if (datastore) {
			ast_channel_datastore_add(chan, datastore);
		}
	}

	if (!datastore) {
		ast_channel_unlock(chan);
		return NULL;
	}

	if (!datastore->data) {
		datastore->data = ast_calloc(1, sizeof(struct replace_channel_store));
	}

	ret = datastore->data;
	ast_channel_unlock(chan);

	return ret;
}

int app_set_replace_channel_snapshot(struct ast_channel *chan, struct ast_channel_snapshot *replace_snapshot)
{
	struct replace_channel_store *replace = get_replace_channel_store(chan, 0);

	if (!replace) {
		return -1;
	}

	ao2_replace(replace->snapshot, replace_snapshot);
	return 0;
}

int app_set_replace_channel_app(struct ast_channel *chan, const char *replace_app)
{
	struct replace_channel_store *replace = get_replace_channel_store(chan, 0);

	if (!replace) {
		return -1;
	}

	ast_free(replace->app);
	replace->app = NULL;

	if (replace_app) {
		replace->app = ast_strdup(replace_app);
		if (!replace->app) {
			return -1;
		}
	}

	return 0;
}

static struct ast_channel_snapshot *get_replace_channel_snapshot(struct ast_channel *chan)
{
	struct replace_channel_store *replace = get_replace_channel_store(chan, 1);
	struct ast_channel_snapshot *replace_channel_snapshot;

	if (!replace) {
		return NULL;
	}

	replace_channel_snapshot = replace->snapshot;
	replace->snapshot = NULL;

	return replace_channel_snapshot;
}

char *app_get_replace_channel_app(struct ast_channel *chan)
{
	struct replace_channel_store *replace = get_replace_channel_store(chan, 1);
	char *replace_channel_app;

	if (!replace) {
		return NULL;
	}

	replace_channel_app = replace->app;
	replace->app = NULL;

	return replace_channel_app;
}

static void start_message_blob_dtor(void *obj)
{
	struct start_message_blob *payload = obj;

	ao2_cleanup(payload->channel);
	ao2_cleanup(payload->replace_channel);
	ast_json_unref(payload->blob);
}

static int send_start_msg_snapshots(struct ast_channel *chan, struct stasis_app *app,
	int argc, char *argv[], struct ast_channel_snapshot *snapshot,
	struct ast_channel_snapshot *replace_channel_snapshot)
{
	struct ast_json *json_blob;
	struct ast_json *json_args;
	struct start_message_blob *payload;
	struct stasis_message *msg;
	int i;

	if (app_subscribe_channel(app, chan)) {
		ast_log_chan(NULL, LOG_ERROR, "Error subscribing app '%s' to channel '%s'\n",
			stasis_app_name(app), ast_channel_name(chan));
		return -1;
	}

	payload = ao2_alloc(sizeof(*payload), start_message_blob_dtor);
	if (!payload) {
		ast_log_chan(NULL, LOG_ERROR, "Error packing JSON for StasisStart message\n");
		return -1;
	}

	payload->channel = ao2_bump(snapshot);
	payload->replace_channel = ao2_bump(replace_channel_snapshot);

	json_blob = ast_json_pack("{s: s, s: o, s: []}",
		"app", stasis_app_name(app),
		"timestamp", ast_json_timeval(ast_tvnow(), NULL),
		"args");
	if (!json_blob) {
		ast_log_chan(NULL, LOG_ERROR, "Error packing JSON for StasisStart message\n");
		ao2_ref(payload, -1);
		return -1;
	}
	payload->blob = json_blob;


	/* Append arguments to args array */
	json_args = ast_json_object_get(json_blob, "args");
	ast_assert(json_args != NULL);
	for (i = 0; i < argc; ++i) {
		int r = ast_json_array_append(json_args,
					      ast_json_string_create(argv[i]));
		if (r != 0) {
			ast_log_chan(NULL, LOG_ERROR, "Error appending to StasisStart message\n");
			ao2_ref(payload, -1);
			return -1;
		}
	}


	msg = stasis_message_create(start_message_type(), payload);
	ao2_ref(payload, -1);
	if (!msg) {
		ast_log_chan(NULL, LOG_ERROR, "Error sending StasisStart message\n");
		return -1;
	}

	if (replace_channel_snapshot) {
		app_unsubscribe_channel_id(app, replace_channel_snapshot->base->uniqueid);
	}
	stasis_publish(ast_app_get_topic(app), msg);
	ao2_ref(msg, -1);
	return 0;
}

static int send_start_msg(struct stasis_app *app, struct ast_channel *chan,
	int argc, char *argv[])
{
	int ret = -1;
	struct ast_channel_snapshot *snapshot;
	struct ast_channel_snapshot *replace_channel_snapshot;

	ast_assert(chan != NULL);

	replace_channel_snapshot = get_replace_channel_snapshot(chan);

	/* Set channel info */
	ast_channel_lock(chan);
	snapshot = ast_channel_snapshot_create(chan);
	ast_channel_unlock(chan);
	if (snapshot) {
		ret = send_start_msg_snapshots(chan, app, argc, argv, snapshot, replace_channel_snapshot);
		ao2_ref(snapshot, -1);
	}
	ao2_cleanup(replace_channel_snapshot);

	return ret;
}

static void remove_masquerade_store(struct ast_channel *chan);

int app_send_end_msg(struct stasis_app *app, struct ast_channel *chan)
{
	struct stasis_message_sanitizer *sanitize = stasis_app_get_sanitizer();
	struct ast_json *blob;
	struct stasis_message *msg;

	if (sanitize && sanitize->channel
		&& sanitize->channel(chan)) {
		return 0;
	}

	blob = ast_json_pack("{s: s, s: o}",
		"app", stasis_app_name(app),
		"timestamp", ast_json_timeval(ast_tvnow(), NULL)
		);
	if (!blob) {
		ast_log_chan(NULL, LOG_ERROR, "Error packing JSON for StasisEnd message\n");
		return -1;
	}

	remove_masquerade_store(chan);
	app_unsubscribe_channel(app, chan);
	msg = ast_channel_blob_create(chan, end_message_type(), blob);
	if (msg) {
		stasis_publish(ast_app_get_topic(app), msg);
	}
	ao2_cleanup(msg);
	ast_json_unref(blob);

	return 0;
}

static int masq_match_cb(void *obj, void *data, int flags)
{
	struct stasis_app_control *control = obj;
	struct ast_channel *chan = data;

	if (!strcmp(ast_channel_uniqueid(chan),
		stasis_app_control_get_channel_id(control))) {
		return CMP_MATCH;
	}

	return 0;
}

static void channel_stolen_cb(void *data, struct ast_channel *old_chan, struct ast_channel *new_chan)
{
	struct stasis_app_control *control;

	/*
	 * At this point, old_chan is the channel pointer that is in Stasis() and
	 * has the unknown channel's name in it while new_chan is the channel pointer
	 * that is not in Stasis(), but has the guts of the channel that Stasis() knows
	 * about.
	 *
	 * Find and unlink control since the channel has a new name/uniqueid
	 * and its hash has changed.  Since the channel is leaving stasis don't
	 * bother putting it back into the container.  Nobody is going to
	 * remove it from the container later.
	 */
	control = ao2_callback(app_controls, OBJ_UNLINK, masq_match_cb, old_chan);
	if (!control) {
		ast_log_chan(NULL, LOG_ERROR, "Could not find control for masqueraded channel\n");
		return;
	}

	/* send the StasisEnd message to the app */
	stasis_app_channel_set_stasis_end_published(new_chan);
	app_send_end_msg(control_app(control), new_chan);

	/* remove the datastore */
	remove_masquerade_store(old_chan);

	ao2_cleanup(control);
}

static void channel_replaced_cb(void *data, struct ast_channel *old_chan, struct ast_channel *new_chan)
{
	RAII_VAR(struct ast_channel_snapshot *, new_snapshot, NULL, ao2_cleanup);
	RAII_VAR(struct ast_channel_snapshot *, old_snapshot, NULL, ao2_cleanup);
	struct stasis_app_control *control;

	/* At this point, new_chan is the channel pointer that is in Stasis() and
	 * has the unknown channel's name in it while old_chan is the channel pointer
	 * that is not in Stasis(), but has the guts of the channel that Stasis() knows
	 * about */

	/* grab a snapshot for the channel that is jumping into Stasis() */
	new_snapshot = ast_channel_snapshot_get_latest(ast_channel_uniqueid(new_chan));
	if (!new_snapshot) {
		ast_log_chan(NULL, LOG_ERROR, "Could not get snapshot for masquerading channel\n");
		return;
	}

	/* grab a snapshot for the channel that has been kicked out of Stasis() */
	old_snapshot = ast_channel_snapshot_get_latest(ast_channel_uniqueid(old_chan));
	if (!old_snapshot) {
		ast_log_chan(NULL, LOG_ERROR, "Could not get snapshot for masqueraded channel\n");
		return;
	}

	/*
	 * Find, unlink, and relink control since the channel has a new
	 * name/uniqueid and its hash has changed.
	 */
	control = ao2_callback(app_controls, OBJ_UNLINK, masq_match_cb, new_chan);
	if (!control) {
		ast_log_chan(NULL, LOG_ERROR, "Could not find control for masquerading channel\n");
		return;
	}
	ao2_link(app_controls, control);


	/* send the StasisStart with replace_channel to the app */
	send_start_msg_snapshots(new_chan, control_app(control), 0, NULL, new_snapshot,
		old_snapshot);
	/* send the StasisEnd message to the app */
	app_send_end_msg(control_app(control), old_chan);

	ao2_cleanup(control);
}

static const struct ast_datastore_info masquerade_store_info = {
	.type = "stasis-masquerade",
	.chan_fixup = channel_stolen_cb,
	.chan_breakdown = channel_replaced_cb,
};

static int has_masquerade_store(struct ast_channel *chan)
{
	SCOPED_CHANNELLOCK(lock, chan);
	return !!ast_channel_datastore_find(chan, &masquerade_store_info, NULL);
}

static int add_masquerade_store(struct ast_channel *chan)
{
	struct ast_datastore *datastore;

	SCOPED_CHANNELLOCK(lock, chan);
	if (ast_channel_datastore_find(chan, &masquerade_store_info, NULL)) {
		return 0;
	}

	datastore = ast_datastore_alloc(&masquerade_store_info, NULL);
	if (!datastore) {
		return -1;
	}

	ast_channel_datastore_add(chan, datastore);

	return 0;
}

static void remove_masquerade_store(struct ast_channel *chan)
{
	struct ast_datastore *datastore;

	SCOPED_CHANNELLOCK(lock, chan);
	datastore = ast_channel_datastore_find(chan, &masquerade_store_info, NULL);
	if (!datastore) {
		return;
	}

	ast_channel_datastore_remove(chan, datastore);
	ast_datastore_free(datastore);
}

void stasis_app_control_execute_until_exhausted(struct ast_channel *chan, struct stasis_app_control *control)
{
	while (!control_is_done(control)) {
		int command_count;
		command_count = control_dispatch_all(control, chan);

		ao2_lock(control);

		if (control_command_count(control)) {
			/* If the command queue isn't empty, something added to the queue before it was locked. */
			ao2_unlock(control);
			continue;
		}

		if (command_count == 0 || ast_channel_fdno(chan) == -1) {
			control_mark_done(control);
			ao2_unlock(control);
			break;
		}
		ao2_unlock(control);
	}
}

int stasis_app_control_is_done(struct stasis_app_control *control)
{
	return control_is_done(control);
}

void stasis_app_control_flush_queue(struct stasis_app_control *control)
{
	control_flush_queue(control);
}

struct ast_datastore_info set_end_published_info = {
	.type = "stasis_end_published",
};

void stasis_app_channel_set_stasis_end_published(struct ast_channel *chan)
{
	struct ast_datastore *datastore;

	datastore = ast_datastore_alloc(&set_end_published_info, NULL);
	if (datastore) {
		ast_channel_lock(chan);
		ast_channel_datastore_add(chan, datastore);
		ast_channel_unlock(chan);
	}
}

int stasis_app_channel_is_stasis_end_published(struct ast_channel *chan)
{
	struct ast_datastore *datastore;

	ast_channel_lock(chan);
	datastore = ast_channel_datastore_find(chan, &set_end_published_info, NULL);
	ast_channel_unlock(chan);

	return datastore ? 1 : 0;
}

static void remove_stasis_end_published(struct ast_channel *chan)
{
	struct ast_datastore *datastore;

	ast_channel_lock(chan);
	datastore = ast_channel_datastore_find(chan, &set_end_published_info, NULL);
	if (datastore) {
		ast_channel_datastore_remove(chan, datastore);
		ast_datastore_free(datastore);
	}
	ast_channel_unlock(chan);
}

/*! \brief Stasis dialplan application callback */
int stasis_app_exec(struct ast_channel *chan, const char *app_name, int argc,
		    char *argv[])
{
	RAII_VAR(struct stasis_app *, app, NULL, ao2_cleanup);
	RAII_VAR(struct stasis_app_control *, control, NULL, control_unlink);
	struct ast_bridge *bridge = NULL;
	int res = 0;
	int needs_depart;

	ast_assert(chan != NULL);

	/* Just in case there's a lingering indication that the channel has had a stasis
	 * end published on it, remove that now.
	 */
	remove_stasis_end_published(chan);

	if (!apps_registry) {
		return -1;
	}

	app = ao2_find(apps_registry, app_name, OBJ_SEARCH_KEY);
	if (!app) {
		ast_log_chan(NULL, LOG_ERROR,
			"Stasis app '%s' not registered\n", app_name);
		return -1;
	}
	if (!app_is_active(app)) {
		ast_log_chan(NULL, LOG_ERROR,
			"Stasis app '%s' not active\n", app_name);
		return -1;
	}

	control = control_create(chan, app);
	if (!control) {
		ast_log_chan(NULL, LOG_ERROR, "Control allocation failed or Stasis app '%s' not registered\n", app_name);
		return -1;
	}

	if (!control_app(control)) {
		ast_log_chan(NULL, LOG_ERROR, "Stasis app '%s' not registered\n", app_name);
		return -1;
	}

	if (!app_is_active(control_app(control))) {
		ast_log_chan(NULL, LOG_ERROR, "Stasis app '%s' not active\n", app_name);
		return -1;
	}
	ao2_link(app_controls, control);

	if (add_masquerade_store(chan)) {
		ast_log_chan(NULL, LOG_ERROR, "Failed to attach masquerade detector\n");
		return -1;
	}

	res = send_start_msg(control_app(control), chan, argc, argv);
	if (res != 0) {
		ast_log_chan(NULL, LOG_ERROR,
			"Error sending start message to '%s'\n", app_name);
		remove_masquerade_store(chan);
		return -1;
	}

	/* Pull queued prestart commands and execute */
	control_prestart_dispatch_all(control, chan);

	while (!control_is_done(control)) {
		RAII_VAR(struct ast_frame *, f, NULL, ast_frame_dtor);
		int r;
		int command_count;
		RAII_VAR(struct ast_bridge *, last_bridge, NULL, ao2_cleanup);

		/* Check to see if a bridge absorbed our hangup frame */
		if (ast_check_hangup_locked(chan)) {
			control_mark_done(control);
			break;
		}

		/* control->next_app is only modified within the control thread, so this is safe */
		if (control_next_app(control)) {
			struct stasis_app *next_app = ao2_find(apps_registry, control_next_app(control), OBJ_SEARCH_KEY);

			if (next_app && app_is_active(next_app)) {
				int idx;
				int next_argc;
				char **next_argv;

				/* If something goes wrong in this conditional, res will need to be non-zero
				 * so that the code below the exec loop knows something went wrong during a move.
				 */
				if (!stasis_app_channel_is_stasis_end_published(chan)) {
					res = has_masquerade_store(chan) && app_send_end_msg(control_app(control), chan);
					if (res != 0) {
						ast_log_chan(NULL, LOG_ERROR,
							"Error sending end message to %s\n", stasis_app_name(control_app(control)));
						control_mark_done(control);
						ao2_ref(next_app, -1);
						break;
					}
				} else {
					remove_stasis_end_published(chan);
				}

				/* This will ao2_bump next_app, and unref the previous app by 1 */
				control_set_app(control, next_app);

				/* There's a chance that the previous application is ready for clean up, so go ahead
				 * and do that now.
				 */
				cleanup();

				/* We need to add another masquerade store, otherwise the leave message will
				 * not show up for the correct application.
				 */
				if (add_masquerade_store(chan)) {
					ast_log_chan(NULL, LOG_ERROR, "Failed to attach masquerade detector\n");
					res = -1;
					control_mark_done(control);
					ao2_ref(next_app, -1);
					break;
				}

				/* We MUST get the size before the list, as control_next_app_args steals the elements
				 * from the string vector.
				 */
				next_argc = control_next_app_args_size(control);
				next_argv = control_next_app_args(control);

				res = send_start_msg(control_app(control), chan, next_argc, next_argv);

				/* Even if res != 0, we still need to free the memory we got from control_argv */
				if (next_argv) {
					for (idx = 0; idx < next_argc; idx++) {
						ast_free(next_argv[idx]);
					}
					ast_free(next_argv);
				}

				if (res != 0) {
					ast_log_chan(NULL, LOG_ERROR,
						"Error sending start message to '%s'\n", stasis_app_name(control_app(control)));
					remove_masquerade_store(chan);
					control_mark_done(control);
					ao2_ref(next_app, -1);
					break;
				}

				/* Done switching applications, free memory and clean up */
				control_move_cleanup(control);
			} else {
				/* If we can't switch applications, do nothing */
				struct ast_json *msg;
				RAII_VAR(struct ast_channel_snapshot *, snapshot, NULL, ao2_cleanup);

				if (!next_app) {
					ast_log_chan(NULL, LOG_ERROR, "Could not move to Stasis app '%s' - not registered\n",
						control_next_app(control));
				} else {
					ast_log_chan(NULL, LOG_ERROR, "Could not move to Stasis app '%s' - not active\n",
						control_next_app(control));
				}

				snapshot = ast_channel_snapshot_get_latest(ast_channel_uniqueid(chan));
				if (!snapshot) {
					ast_log_chan(NULL, LOG_ERROR, "Could not get channel shapshot for '%s'\n",
						ast_channel_name(chan));
				} else {
					struct ast_json *json_args;
					int next_argc = control_next_app_args_size(control);
					char **next_argv = control_next_app_args(control);

					msg = ast_json_pack("{s: s, s: o, s: o, s: s, s: []}",
						"type", "ApplicationMoveFailed",
						"timestamp", ast_json_timeval(ast_tvnow(), NULL),
						"channel", ast_channel_snapshot_to_json(snapshot, NULL),
						"destination", control_next_app(control),
						"args");
					if (!msg) {
						ast_log_chan(NULL, LOG_ERROR, "Failed to pack JSON for ApplicationMoveFailed message\n");
					} else {
						json_args = ast_json_object_get(msg, "args");
						if (!json_args) {
							ast_log_chan(NULL, LOG_ERROR, "Could not get args json array");
						} else {
							int r = 0;
							int idx;
							for (idx = 0; idx < next_argc; ++idx) {
								r = ast_json_array_append(json_args,
									ast_json_string_create(next_argv[idx]));
								if (r != 0) {
									ast_log_chan(NULL, LOG_ERROR, "Error appending to ApplicationMoveFailed message\n");
									break;
								}
							}
							if (r == 0) {
								app_send(control_app(control), msg);
							}
						}
						ast_json_unref(msg);
					}
				}
			}
			control_move_cleanup(control);
			ao2_cleanup(next_app);
		}

		last_bridge = bridge;
		bridge = ao2_bump(stasis_app_get_bridge(control));

		if (bridge != last_bridge) {
			if (last_bridge) {
				app_unsubscribe_bridge(control_app(control), last_bridge);
			}
			if (bridge) {
				app_subscribe_bridge(control_app(control), bridge);
			}
		}

		if (bridge) {
			/* Bridge/dial is handling channel frames */
			control_wait(control);
			control_dispatch_all(control, chan);
			continue;
		}

		r = ast_waitfor(chan, MAX_WAIT_MS);

		if (r < 0) {
			ast_debug(3, "%s: Poll error\n",
				  ast_channel_uniqueid(chan));
			control_mark_done(control);
			break;
		}

		command_count = control_dispatch_all(control, chan);

		if (command_count > 0 && ast_channel_fdno(chan) == -1) {
			/* Command drained the channel; wait for next frame */
			continue;
		}

		if (r == 0) {
			/* Timeout */
			continue;
		}

		f = ast_read(chan);
		if (!f) {
			/* Continue on in the dialplan */
			ast_debug(3, "%s: Hangup (no more frames)\n",
				ast_channel_uniqueid(chan));
			control_mark_done(control);
			break;
		}

		if (f->frametype == AST_FRAME_CONTROL) {
			if (f->subclass.integer == AST_CONTROL_HANGUP) {
				/* Continue on in the dialplan */
				ast_debug(3, "%s: Hangup\n",
					ast_channel_uniqueid(chan));
				control_mark_done(control);
				break;
			}
		}
	}

	ast_channel_lock(chan);
	needs_depart = (ast_channel_internal_bridge_channel(chan) != NULL);
	ast_channel_unlock(chan);
	if (needs_depart) {
		ast_bridge_depart(chan);
	}

	if (stasis_app_get_bridge(control)) {
		app_unsubscribe_bridge(control_app(control), stasis_app_get_bridge(control));
	}
	ao2_cleanup(bridge);

	/* Only publish a stasis_end event if it hasn't already been published */
	if (!res && !stasis_app_channel_is_stasis_end_published(chan)) {
		/* A masquerade has occurred and this message will be wrong so it
		 * has already been sent elsewhere. */
		res = has_masquerade_store(chan) && app_send_end_msg(control_app(control), chan);
		if (res != 0) {
			ast_log_chan(NULL, LOG_ERROR,
				"Error sending end message to %s\n", stasis_app_name(control_app(control)));
			return res;
		}
	} else {
		remove_stasis_end_published(chan);
	}

	control_flush_queue(control);

	/* Stop any lingering silence generator */
	control_silence_stop_now(control);

	/* There's an off chance that app is ready for cleanup. Go ahead
	 * and clean up, just in case
	 */
	cleanup();

	/* The control needs to be removed from the controls container in
	 * case a new PBX is started and ends up coming back into Stasis.
	 */
	control_unlink(control);
	control = NULL;

	if (!res && !ast_channel_pbx(chan)) {
		int chan_hungup;

		/* The ASYNCGOTO softhangup flag may have broken the channel out of
		 * its bridge to run dialplan, so if there's no pbx on the channel
		 * let it run dialplan here. Otherwise, it will run when this
		 * application exits. */
		ast_channel_lock(chan);
		ast_channel_clear_softhangup(chan, AST_SOFTHANGUP_ASYNCGOTO);
		chan_hungup = ast_check_hangup(chan);
		ast_channel_unlock(chan);

		if (!chan_hungup) {
			struct ast_pbx_args pbx_args;

			memset(&pbx_args, 0, sizeof(pbx_args));
			pbx_args.no_hangup_chan = 1;

			res = ast_pbx_run_args(chan, &pbx_args);
		}
	}

	return res;
}

int stasis_app_send(const char *app_name, struct ast_json *message)
{
	struct stasis_app *app;

	if (!apps_registry) {
		return -1;
	}

	app = ao2_find(apps_registry, app_name, OBJ_SEARCH_KEY);
	if (!app) {
		/* XXX We can do a better job handling late binding, queueing up
		 * the call for a few seconds to wait for the app to register.
		 */
		ast_log_chan(NULL, LOG_WARNING,
			"Stasis app '%s' not registered\n", app_name);
		return -1;
	}
	app_send(app, message);
	ao2_ref(app, -1);

	return 0;
}

static struct stasis_app *find_app_by_name(const char *app_name)
{
	struct stasis_app *res = NULL;

	if (!apps_registry) {
		return NULL;
	}

	if (!ast_strlen_zero(app_name)) {
		res = ao2_find(apps_registry, app_name, OBJ_SEARCH_KEY);
	}

	return res;
}

struct stasis_app *stasis_app_get_by_name(const char *name)
{
	return find_app_by_name(name);
}

static int append_name(void *obj, void *arg, int flags)
{
	struct stasis_app *app = obj;
	struct ao2_container *apps = arg;

	ast_str_container_add(apps, stasis_app_name(app));
	return 0;
}

struct ao2_container *stasis_app_get_all(void)
{
	struct ao2_container *apps;

	if (!apps_registry) {
		return NULL;
	}

	apps = ast_str_container_alloc(1);
	if (!apps) {
		return NULL;
	}

	ao2_callback(apps_registry, OBJ_NODATA, append_name, apps);

	return apps;
}

static int __stasis_app_register(const char *app_name, stasis_app_cb handler, void *data, int all_events)
{
	RAII_VAR(struct stasis_app *, app, NULL, ao2_cleanup);

	if (!apps_registry) {
		return -1;
	}

	ao2_lock(apps_registry);
	app = ao2_find(apps_registry, app_name, OBJ_SEARCH_KEY | OBJ_NOLOCK);
	if (app) {
		/*
		 * We need to unlock the apps_registry before calling app_update to
		 * prevent the possibility of a deadlock with the session.
		 */
		ao2_unlock(apps_registry);
		app_update(app, handler, data);
		cleanup();
		return 0;
	}

	app = app_create(app_name, handler, data, all_events ? STASIS_APP_SUBSCRIBE_ALL : STASIS_APP_SUBSCRIBE_MANUAL);
	if (!app) {
		ao2_unlock(apps_registry);
		return -1;
	}

	if (all_events) {
		struct stasis_app_event_source *source;

		AST_RWLIST_RDLOCK(&event_sources);
		AST_LIST_TRAVERSE(&event_sources, source, next) {
			if (!source->subscribe) {
				continue;
			}

			source->subscribe(app, NULL);
		}
		AST_RWLIST_UNLOCK(&event_sources);
	}
	ao2_link_flags(apps_registry, app, OBJ_NOLOCK);

	ao2_unlock(apps_registry);

	/* We lazily clean up the apps_registry, because it's good enough to
	 * prevent memory leaks, and we're lazy.
	 */
	cleanup();
	return 0;
}

int stasis_app_register(const char *app_name, stasis_app_cb handler, void *data)
{
	return __stasis_app_register(app_name, handler, data, 0);
}

int stasis_app_register_all(const char *app_name, stasis_app_cb handler, void *data)
{
	return __stasis_app_register(app_name, handler, data, 1);
}

void stasis_app_unregister(const char *app_name)
{
	struct stasis_app *app;

	if (!app_name) {
		return;
	}

	if (!apps_registry) {
		return;
	}

	app = ao2_find(apps_registry, app_name, OBJ_SEARCH_KEY);
	if (!app) {
		ast_log_chan(NULL, LOG_ERROR,
			"Stasis app '%s' not registered\n", app_name);
		return;
	}

	app_deactivate(app);

	/* There's a decent chance that app is ready for cleanup. Go ahead
	 * and clean up, just in case
	 */
	cleanup();

	ao2_ref(app, -1);
}

void stasis_app_register_event_source(struct stasis_app_event_source *obj)
{
	AST_RWLIST_WRLOCK(&event_sources);
	AST_LIST_INSERT_TAIL(&event_sources, obj, next);
	AST_RWLIST_UNLOCK(&event_sources);
}

void stasis_app_unregister_event_source(struct stasis_app_event_source *obj)
{
	struct stasis_app_event_source *source;

	AST_RWLIST_WRLOCK(&event_sources);
	AST_RWLIST_TRAVERSE_SAFE_BEGIN(&event_sources, source, next) {
		if (source == obj) {
			AST_RWLIST_REMOVE_CURRENT(next);
			break;
		}
	}
	AST_RWLIST_TRAVERSE_SAFE_END;
	AST_RWLIST_UNLOCK(&event_sources);
}

/*!
 * \internal
 * \brief Convert event source data to JSON.
 *
 * Calls each event source that has a "to_json" handler allowing each
 * source to add data to the given JSON object.
 *
 * \param app application associated with the event source
 * \param json a json object to "fill"
 *
 * \retval The given json object.
 */
static struct ast_json *app_event_sources_to_json(
	const struct stasis_app *app, struct ast_json *json)
{
	struct stasis_app_event_source *source;

	AST_RWLIST_RDLOCK(&event_sources);
	AST_LIST_TRAVERSE(&event_sources, source, next) {
		if (source->to_json) {
			source->to_json(app, json);
		}
	}
	AST_RWLIST_UNLOCK(&event_sources);

	return json;
}

struct ast_json *stasis_app_object_to_json(struct stasis_app *app)
{
	if (!app) {
		return NULL;
	}

	return stasis_app_event_filter_to_json(
		app, app_event_sources_to_json(app, app_to_json(app)));
}

struct ast_json *stasis_app_to_json(const char *app_name)
{
	struct stasis_app *app = find_app_by_name(app_name);
	struct ast_json *json = stasis_app_object_to_json(app);

	ao2_cleanup(app);

	return json;
}

/*!
 * \internal
 * \brief Finds an event source that matches a uri scheme.
 *
 * Uri(s) should begin with a particular scheme that can be matched
 * against an event source.
 *
 * \param uri uri containing a scheme to match
 *
 * \retval an event source if found, NULL otherwise.
 */
static struct stasis_app_event_source *app_event_source_find(const char *uri)
{
	struct stasis_app_event_source *source;

	AST_RWLIST_RDLOCK(&event_sources);
	AST_LIST_TRAVERSE(&event_sources, source, next) {
		if (ast_begins_with(uri, source->scheme)) {
			break;
		}
	}
	AST_RWLIST_UNLOCK(&event_sources);

	return source;
}

/*!
 * \internal
 * \brief Callback for subscription handling
 *
 * \param app [un]subscribing application
 * \param uri scheme:id of an event source
 * \param event_source being [un]subscribed [from]to
 *
 * \retval stasis_app_subscribe_res return code.
 */
typedef enum stasis_app_subscribe_res (*app_subscription_handler)(
	struct stasis_app *app, const char *uri,
	struct stasis_app_event_source *event_source);

/*!
 * \internal
 * \brief Subscriptions handler for application [un]subscribing.
 *
 * \param app_name Name of the application to subscribe.
 * \param event_source_uris URIs for the event sources to subscribe to.
 * \param event_sources_count Array size of event_source_uris.
 * \param json Optional output pointer for JSON representation of the app
 *             after adding the subscription.
 * \param handler [un]subscribe handler
 *
 * \retval stasis_app_subscribe_res return code.
 */
static enum stasis_app_subscribe_res app_handle_subscriptions(
	const char *app_name, const char **event_source_uris,
	int event_sources_count, struct ast_json **json,
	app_subscription_handler handler)
{
	struct stasis_app *app = find_app_by_name(app_name);
	int i;

	ast_assert(handler != NULL);

	if (!app) {
		return STASIS_ASR_APP_NOT_FOUND;
	}

	for (i = 0; i < event_sources_count; ++i) {
		const char *uri = event_source_uris[i];
		struct stasis_app_event_source *event_source;
		enum stasis_app_subscribe_res res;

		event_source = app_event_source_find(uri);
		if (!event_source) {
			ast_log_chan(NULL, LOG_WARNING, "Invalid scheme: %s\n", uri);
			ao2_ref(app, -1);

			return STASIS_ASR_EVENT_SOURCE_BAD_SCHEME;
		}

		res = handler(app, uri, event_source);
		if (res != STASIS_ASR_OK) {
			ao2_ref(app, -1);

			return res;
		}
	}

	if (json) {
		ast_debug(3, "%s: Successful; setting results\n", app_name);
		*json = stasis_app_object_to_json(app);
	}

	ao2_ref(app, -1);

	return STASIS_ASR_OK;
}

enum stasis_app_subscribe_res stasis_app_subscribe_channel(const char *app_name,
	struct ast_channel *chan)
{
	struct stasis_app *app = find_app_by_name(app_name);
	int res;

	if (!app) {
		return STASIS_ASR_APP_NOT_FOUND;
	}

	ast_debug(3, "%s: Subscribing to %s\n", app_name, ast_channel_uniqueid(chan));

	res = app_subscribe_channel(app, chan);
	ao2_ref(app, -1);

	if (res != 0) {
		ast_log_chan(NULL, LOG_ERROR, "Error subscribing app '%s' to channel '%s'\n",
			app_name, ast_channel_uniqueid(chan));
		return STASIS_ASR_INTERNAL_ERROR;
	}

	return STASIS_ASR_OK;
}


/*!
 * \internal
 * \brief Subscribe an app to an event source.
 *
 * \param app subscribing application
 * \param uri scheme:id of an event source
 * \param event_source being subscribed to
 *
 * \retval stasis_app_subscribe_res return code.
 */
static enum stasis_app_subscribe_res app_subscribe(
	struct stasis_app *app, const char *uri,
	struct stasis_app_event_source *event_source)
{
	const char *app_name = stasis_app_name(app);
	RAII_VAR(void *, obj, NULL, ao2_cleanup);

	ast_debug(3, "%s: Checking %s\n", app_name, uri);

	if (!ast_strlen_zero(uri + strlen(event_source->scheme)) &&
	    (!event_source->find || (!(obj = event_source->find(app, uri + strlen(event_source->scheme)))))) {
		ast_log_chan(NULL, LOG_WARNING, "Event source not found: %s\n", uri);
		return STASIS_ASR_EVENT_SOURCE_NOT_FOUND;
	}

	ast_debug(3, "%s: Subscribing to %s\n", app_name, uri);

	if (!event_source->subscribe || (event_source->subscribe(app, obj))) {
		ast_log_chan(NULL, LOG_WARNING, "Error subscribing app '%s' to '%s'\n",
			app_name, uri);
		return STASIS_ASR_INTERNAL_ERROR;
	}

	return STASIS_ASR_OK;
}

enum stasis_app_subscribe_res stasis_app_subscribe(const char *app_name,
	const char **event_source_uris, int event_sources_count,
	struct ast_json **json)
{
	return app_handle_subscriptions(
		app_name, event_source_uris, event_sources_count,
		json, app_subscribe);
}

/*!
 * \internal
 * \brief Unsubscribe an app from an event source.
 *
 * \param app application to unsubscribe
 * \param uri scheme:id of an event source
 * \param event_source being unsubscribed from
 *
 * \retval stasis_app_subscribe_res return code.
 */
static enum stasis_app_subscribe_res app_unsubscribe(
	struct stasis_app *app, const char *uri,
	struct stasis_app_event_source *event_source)
{
	const char *app_name = stasis_app_name(app);
	const char *id = uri + strlen(event_source->scheme);

	if (!event_source->is_subscribed ||
	    (!event_source->is_subscribed(app, id))) {
		return STASIS_ASR_EVENT_SOURCE_NOT_FOUND;
	}

	ast_debug(3, "%s: Unsubscribing from %s\n", app_name, uri);

	if (!event_source->unsubscribe || (event_source->unsubscribe(app, id))) {
		ast_log_chan(NULL, LOG_WARNING, "Error unsubscribing app '%s' to '%s'\n",
			app_name, uri);
		return -1;
	}
	return 0;
}

enum stasis_app_subscribe_res stasis_app_unsubscribe(const char *app_name,
	const char **event_source_uris, int event_sources_count,
	struct ast_json **json)
{
	return app_handle_subscriptions(
		app_name, event_source_uris, event_sources_count,
		json, app_unsubscribe);
}

enum stasis_app_user_event_res stasis_app_user_event(const char *app_name,
	const char *event_name,
	const char **source_uris, int sources_count,
	struct ast_json *json_variables)
{
	RAII_VAR(struct stasis_app *, app, find_app_by_name(app_name), ao2_cleanup);
	struct ast_json *blob = NULL;
	struct ast_multi_object_blob *multi;
	struct stasis_message *message;
	enum stasis_app_user_event_res res = STASIS_APP_USER_INTERNAL_ERROR;
	int have_channel = 0;
	int i;

	if (!app) {
		ast_log_chan(NULL, LOG_WARNING, "App %s not found\n", app_name);
		return STASIS_APP_USER_APP_NOT_FOUND;
	}

	if (!ast_multi_user_event_type()) {
		return res;
	}

	if (json_variables) {
		struct ast_json *json_value = ast_json_string_create(event_name);

		if (json_value && !ast_json_object_set(json_variables, "eventname", json_value)) {
			blob = ast_json_ref(json_variables);
		}
	} else {
		blob = ast_json_pack("{s: s}", "eventname", event_name);
	}

	if (!blob) {
		ast_log_chan(NULL, LOG_ERROR, "Failed to initialize blob\n");

		return res;
	}

	multi = ast_multi_object_blob_create(blob);
	ast_json_unref(blob);
	if (!multi) {
		ast_log_chan(NULL, LOG_ERROR, "Failed to initialize multi\n");

		return res;
	}

	for (i = 0; i < sources_count; ++i) {
		const char *uri = source_uris[i];
		void *snapshot=NULL;
		enum stasis_user_multi_object_snapshot_type type;

		if (ast_begins_with(uri, "channel:")) {
			type = STASIS_UMOS_CHANNEL;
			snapshot = ast_channel_snapshot_get_latest(uri + 8);
			have_channel = 1;
		} else if (ast_begins_with(uri, "bridge:")) {
			type = STASIS_UMOS_BRIDGE;
			snapshot = ast_bridge_get_snapshot_by_uniqueid(uri + 7);
		} else if (ast_begins_with(uri, "endpoint:")) {
			type = STASIS_UMOS_ENDPOINT;
			snapshot = ast_endpoint_latest_snapshot(uri + 9, NULL);
		} else {
			ast_log_chan(NULL, LOG_WARNING, "Invalid scheme: %s\n", uri);
			ao2_ref(multi, -1);

			return STASIS_APP_USER_EVENT_SOURCE_BAD_SCHEME;
		}
		if (!snapshot) {
			ast_log_chan(NULL, LOG_ERROR, "Unable to get snapshot for %s\n", uri);
			ao2_ref(multi, -1);

			return STASIS_APP_USER_EVENT_SOURCE_NOT_FOUND;
		}
		ast_multi_object_blob_add(multi, type, snapshot);
	}

	message = stasis_message_create(ast_multi_user_event_type(), multi);
	ao2_ref(multi, -1);

	if (!message) {
		ast_log_chan(NULL, LOG_ERROR, "Unable to create stasis user event message\n");
		return res;
	}

	/*
	 * Publishing to two different topics is normally to be avoided -- except
	 * in this case both are final destinations with no forwards (only listeners).
	 * The message has to be delivered to the application topic for ARI, but a
	 * copy is also delivered directly to the manager for AMI if there is a channel.
	 */
	stasis_publish(ast_app_get_topic(app), message);

	if (have_channel) {
		stasis_publish(ast_manager_get_topic(), message);
	}
	ao2_ref(message, -1);

	return STASIS_APP_USER_OK;
}

static int unload_module(void)
{
	stasis_app_unregister_event_sources();

	messaging_cleanup();

	cleanup();

	stasis_app_control_shutdown();

	ao2_cleanup(apps_registry);
	apps_registry = NULL;

	ao2_cleanup(app_controls);
	app_controls = NULL;

	ao2_cleanup(app_bridges);
	app_bridges = NULL;

	ao2_cleanup(app_bridges_moh);
	app_bridges_moh = NULL;

	ao2_cleanup(app_bridges_playback);
	app_bridges_playback = NULL;

	STASIS_MESSAGE_TYPE_CLEANUP(end_message_type);
	STASIS_MESSAGE_TYPE_CLEANUP(start_message_type);

	return 0;
}

/*! \brief Sanitization callback for channel snapshots */
static int channel_snapshot_sanitizer(const struct ast_channel_snapshot *snapshot)
{
	if (!snapshot || !(snapshot->base->tech_properties & AST_CHAN_TP_INTERNAL)) {
		return 0;
	}
	return 1;
}

/*! \brief Sanitization callback for channels */
static int channel_sanitizer(const struct ast_channel *chan)
{
	if (!chan || !(ast_channel_tech(chan)->properties & AST_CHAN_TP_INTERNAL)) {
		return 0;
	}
	return 1;
}

/*! \brief Sanitization callback for channel unique IDs */
static int channel_id_sanitizer(const char *id)
{
	struct ast_channel_snapshot *snapshot;
	int ret;

	snapshot = ast_channel_snapshot_get_latest(id);
	ret = channel_snapshot_sanitizer(snapshot);
	ao2_cleanup(snapshot);

	return ret;
}

/*! \brief Sanitization callbacks for communication to Stasis applications */
struct stasis_message_sanitizer app_sanitizer = {
	.channel_id = channel_id_sanitizer,
	.channel_snapshot = channel_snapshot_sanitizer,
	.channel = channel_sanitizer,
};

struct stasis_message_sanitizer *stasis_app_get_sanitizer(void)
{
	return &app_sanitizer;
}

static const struct ast_datastore_info stasis_internal_channel_info = {
	.type = "stasis-internal-channel",
};

static int set_internal_datastore(struct ast_channel *chan)
{
	struct ast_datastore *datastore;

	datastore = ast_channel_datastore_find(chan, &stasis_internal_channel_info, NULL);
	if (!datastore) {
		datastore = ast_datastore_alloc(&stasis_internal_channel_info, NULL);
		if (!datastore) {
			return -1;
		}
		ast_channel_datastore_add(chan, datastore);
	}
	return 0;
}

int stasis_app_channel_unreal_set_internal(struct ast_channel *chan)
{
	struct ast_channel *outchan = NULL, *outowner = NULL;
	int res = 0;
	struct ast_unreal_pvt *unreal_pvt = ast_channel_tech_pvt(chan);

	ao2_ref(unreal_pvt, +1);
	ast_unreal_lock_all(unreal_pvt, &outowner, &outchan);
	if (outowner) {
		res |= set_internal_datastore(outowner);
		ast_channel_unlock(outowner);
		ast_channel_unref(outowner);
	}
	if (outchan) {
		res |= set_internal_datastore(outchan);
		ast_channel_unlock(outchan);
		ast_channel_unref(outchan);
	}
	ao2_unlock(unreal_pvt);
	ao2_ref(unreal_pvt, -1);
	return res;
}

int stasis_app_channel_set_internal(struct ast_channel *chan)
{
	int res;

	ast_channel_lock(chan);
	res = set_internal_datastore(chan);
	ast_channel_unlock(chan);

	return res;
}

int stasis_app_channel_is_internal(struct ast_channel *chan)
{
	struct ast_datastore *datastore;
	int res = 0;

	ast_channel_lock(chan);
	datastore = ast_channel_datastore_find(chan, &stasis_internal_channel_info, NULL);
	if (datastore) {
		res = 1;
	}
	ast_channel_unlock(chan);

	return res;
}

static int load_module(void)
{
	if (STASIS_MESSAGE_TYPE_INIT(start_message_type) != 0) {
		return AST_MODULE_LOAD_DECLINE;
	}
	if (STASIS_MESSAGE_TYPE_INIT(end_message_type) != 0) {
		return AST_MODULE_LOAD_DECLINE;
	}
	apps_registry = ao2_container_alloc_hash(AO2_ALLOC_OPT_LOCK_MUTEX, 0,
		APPS_NUM_BUCKETS, app_hash, NULL, app_compare);
	app_controls = ao2_container_alloc_hash(AO2_ALLOC_OPT_LOCK_MUTEX, 0,
		CONTROLS_NUM_BUCKETS, control_hash, NULL, control_compare);
	app_bridges = ao2_container_alloc_hash(AO2_ALLOC_OPT_LOCK_MUTEX,
		AO2_CONTAINER_ALLOC_OPT_DUPS_REJECT,
		BRIDGES_NUM_BUCKETS, bridges_hash, bridges_sort, bridges_compare);
	app_bridges_moh = ao2_container_alloc_hash(
		AO2_ALLOC_OPT_LOCK_MUTEX, 0,
		37, bridges_channel_hash_fn, NULL, bridges_channel_compare);
	app_bridges_playback = ao2_container_alloc_hash(
		AO2_ALLOC_OPT_LOCK_MUTEX, AO2_CONTAINER_ALLOC_OPT_DUPS_REJECT,
		37, bridges_channel_hash_fn, bridges_channel_sort_fn, NULL);
	if (!apps_registry || !app_controls || !app_bridges || !app_bridges_moh || !app_bridges_playback) {
		unload_module();
		return AST_MODULE_LOAD_DECLINE;
	}

	if (messaging_init()) {
		unload_module();
		return AST_MODULE_LOAD_DECLINE;
	}

	bridge_stasis_init();

	stasis_app_register_event_sources();

	return AST_MODULE_LOAD_SUCCESS;
}

AST_MODULE_INFO(GABPBX_GPL_KEY, AST_MODFLAG_GLOBAL_SYMBOLS | AST_MODFLAG_LOAD_ORDER, "Stasis application support",
	.load_pri = AST_MODPRI_APP_DEPEND - 1,
	.support_level = AST_MODULE_SUPPORT_CORE,
	.load = load_module,
	.unload = unload_module,
);
