/*
 * GABpbx -- An open source telephony toolkit.
 *
 * Copyright (C) 1999 - 2005, Digium, Inc.
 *
 * Mark Spencer <markster@digium.com>
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
 * \brief Convenient Application Routines
 *
 * \author Mark Spencer <markster@digium.com>
 */

/*!
 * Application Skeleton is an example of creating an application for GABpbx.
 * \example app_skel.c
 */

/*** MODULEINFO
	<support_level>core</support_level>
 ***/

#include "gabpbx.h"

#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif
#include <regex.h>          /* for regcomp(3) */
#include <sys/file.h>       /* for flock(2) */
#include <signal.h>         /* for pthread_sigmask(3) */
#include <stdlib.h>         /* for closefrom(3) */
#include <sys/types.h>
#include <sys/wait.h>       /* for waitpid(2) */
#ifndef HAVE_CLOSEFROM
#include <dirent.h>         /* for opendir(3)   */
#endif
#ifdef HAVE_CAP
#include <sys/capability.h>
#endif /* HAVE_CAP */

#include "gabpbx/paths.h"	/* use ast_config_AST_DATA_DIR */
#include "gabpbx/channel.h"
#include "gabpbx/pbx.h"
#include "gabpbx/file.h"
#include "gabpbx/app.h"
#include "gabpbx/dsp.h"
#include "gabpbx/utils.h"
#include "gabpbx/lock.h"
#include "gabpbx/indications.h"
#include "gabpbx/linkedlists.h"
#include "gabpbx/threadstorage.h"
#include "gabpbx/test.h"
#include "gabpbx/module.h"
#include "gabpbx/astobj2.h"
#include "gabpbx/stasis.h"
#include "gabpbx/stasis_channels.h"
#include "gabpbx/json.h"
#include "gabpbx/format_cache.h"

AST_THREADSTORAGE_PUBLIC(ast_str_thread_global_buf);

static pthread_t shaun_of_the_dead_thread = AST_PTHREADT_NULL;

struct zombie {
	pid_t pid;
	AST_LIST_ENTRY(zombie) list;
};

static AST_LIST_HEAD_STATIC(zombies, zombie);

#ifdef HAVE_CAP
static cap_t child_cap;
#endif
/*!
 * \brief Define \ref stasis topic objects
 * @{
 */
static struct stasis_topic *queue_topic_all;
static struct stasis_topic_pool *queue_topic_pool;

/*! @} */

static void *shaun_of_the_dead(void *data)
{
	struct zombie *cur;
	int status;
	for (;;) {
		if (!AST_LIST_EMPTY(&zombies)) {
			/* Don't allow cancellation while we have a lock. */
			pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
			AST_LIST_LOCK(&zombies);
			AST_LIST_TRAVERSE_SAFE_BEGIN(&zombies, cur, list) {
				if (waitpid(cur->pid, &status, WNOHANG) != 0) {
					AST_LIST_REMOVE_CURRENT(list);
					ast_free(cur);
				}
			}
			AST_LIST_TRAVERSE_SAFE_END
			AST_LIST_UNLOCK(&zombies);
			pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
		}
		pthread_testcancel();
		/* Wait for 60 seconds, without engaging in a busy loop. */
		ast_poll(NULL, 0, AST_LIST_FIRST(&zombies) ? 5000 : 60000);
	}
	return NULL;
}


#define AST_MAX_FORMATS 10

static AST_RWLIST_HEAD_STATIC(groups, ast_group_info);

/*!
 * \brief This function presents a dialtone and reads an extension into 'collect'
 * which must be a pointer to a **pre-initialized** array of char having a
 * size of 'size' suitable for writing to.  It will collect no more than the smaller
 * of 'maxlen' or 'size' minus the original strlen() of collect digits.
 * \param chan struct.
 * \param context
 * \param collect
 * \param size
 * \param maxlen
 * \param timeout timeout in milliseconds
*/
int ast_app_dtget(struct ast_channel *chan, const char *context, char *collect, size_t size, int maxlen, int timeout)
{
	struct ast_tone_zone_sound *ts;
	int res = 0, x = 0;

	if (maxlen > size) {
		maxlen = size;
	}

	if (!timeout) {
		if (ast_channel_pbx(chan) && ast_channel_pbx(chan)->dtimeoutms) {
			timeout = ast_channel_pbx(chan)->dtimeoutms;
		} else {
			timeout = 5000;
		}
	}

	if ((ts = ast_get_indication_tone(ast_channel_zone(chan), "dial"))) {
		res = ast_playtones_start(chan, 0, ts->data, 0);
		ts = ast_tone_zone_sound_unref(ts);
	} else {
		ast_log(LOG_NOTICE, "Huh....? no dial for indications?\n");
	}

	for (x = strlen(collect); x < maxlen; ) {
		res = ast_waitfordigit(chan, timeout);
		if (!ast_ignore_pattern(context, collect)) {
			ast_playtones_stop(chan);
		}
		if (res < 1) {
			break;
		}
		if (res == '#') {
			break;
		}
		collect[x++] = res;
		if (!ast_matchmore_extension(chan, context, collect, 1,
			S_COR(ast_channel_caller(chan)->id.number.valid, ast_channel_caller(chan)->id.number.str, NULL))) {
			break;
		}
	}

	if (res >= 0) {
		res = ast_exists_extension(chan, context, collect, 1,
			S_COR(ast_channel_caller(chan)->id.number.valid, ast_channel_caller(chan)->id.number.str, NULL)) ? 1 : 0;
	}

	return res;
}

enum ast_getdata_result ast_app_getdata(struct ast_channel *c, const char *prompt, char *s, int maxlen, int timeout)
{
	return ast_app_getdata_terminator(c, prompt, s, maxlen, timeout, NULL);
}

enum ast_getdata_result ast_app_getdata_terminator(struct ast_channel *c, const char *prompt, char *s,
	int maxlen, int timeout, char *terminator)
{
	int res = 0, to, fto;
	char *front, *filename;

	/* XXX Merge with full version? XXX */

	if (maxlen)
		s[0] = '\0';

	if (!prompt)
		prompt = "";

	filename = ast_strdupa(prompt);
	while ((front = ast_strsep(&filename, '&', AST_STRSEP_STRIP | AST_STRSEP_TRIM))) {
		if (!ast_strlen_zero(front)) {
			res = ast_streamfile(c, front, ast_channel_language(c));
			if (res)
				continue;
		}
		if (ast_strlen_zero(filename)) {
			/* set timeouts for the last prompt */
			fto = ast_channel_pbx(c) ? ast_channel_pbx(c)->rtimeoutms : 6000;
			to = ast_channel_pbx(c) ? ast_channel_pbx(c)->dtimeoutms : 2000;

			if (timeout > 0) {
				fto = to = timeout;
			}
			if (timeout < 0) {
				fto = to = 1000000000;
			}
		} else {
			/* there is more than one prompt, so
			 * get rid of the long timeout between
			 * prompts, and make it 50ms */
			fto = 50;
			to = ast_channel_pbx(c) ? ast_channel_pbx(c)->dtimeoutms : 2000;
		}
		res = ast_readstring(c, s, maxlen, to, fto, (terminator ? terminator : "#"));
		if (res == AST_GETDATA_EMPTY_END_TERMINATED) {
			return res;
		}
		if (!ast_strlen_zero(s)) {
			return res;
		}
	}

	return res;
}

/* The lock type used by ast_lock_path() / ast_unlock_path() */
static enum AST_LOCK_TYPE ast_lock_type = AST_LOCK_TYPE_LOCKFILE;

int ast_app_getdata_full(struct ast_channel *c, const char *prompt, char *s, int maxlen, int timeout, int audiofd, int ctrlfd)
{
	int res, to = 2000, fto = 6000;

	if (!ast_strlen_zero(prompt)) {
		res = ast_streamfile(c, prompt, ast_channel_language(c));
		if (res < 0) {
			return res;
		}
	}

	if (timeout > 0) {
		fto = to = timeout;
	}
	if (timeout < 0) {
		fto = to = 1000000000;
	}

	res = ast_readstring_full(c, s, maxlen, to, fto, "#", audiofd, ctrlfd);

	return res;
}

/* BUGBUG this is not thread safe. */
static const struct ast_app_stack_funcs *app_stack_callbacks;

void ast_install_stack_functions(const struct ast_app_stack_funcs *funcs)
{
	app_stack_callbacks = funcs;
}

const char *ast_app_expand_sub_args(struct ast_channel *chan, const char *args)
{
	const struct ast_app_stack_funcs *funcs;
	const char *new_args;

	funcs = app_stack_callbacks;
	if (!funcs || !funcs->expand_sub_args || !ast_module_running_ref(funcs->module)) {
		ast_log(LOG_WARNING,
			"Cannot expand 'Gosub(%s)' arguments.  The app_stack module is not available.\n",
			args);
		return NULL;
	}

	new_args = funcs->expand_sub_args(chan, args);
	ast_module_unref(funcs->module);

	return new_args;
}

int ast_app_exec_sub(struct ast_channel *autoservice_chan, struct ast_channel *sub_chan, const char *sub_args, int ignore_hangup)
{
	const struct ast_app_stack_funcs *funcs;
	int res;

	funcs = app_stack_callbacks;
	if (!funcs || !funcs->run_sub || !ast_module_running_ref(funcs->module)) {
		ast_log(LOG_WARNING,
			"Cannot run 'Gosub(%s)'.  The app_stack module is not available.\n",
			sub_args);
		return -1;
	}

	if (autoservice_chan) {
		ast_autoservice_start(autoservice_chan);
	}

	res = funcs->run_sub(sub_chan, sub_args, ignore_hangup);
	ast_module_unref(funcs->module);

	if (autoservice_chan) {
		ast_autoservice_stop(autoservice_chan);
	}

	if (!ignore_hangup && ast_check_hangup_locked(sub_chan)) {
		ast_queue_hangup(sub_chan);
	}

	return res;
}

int ast_app_run_sub(struct ast_channel *autoservice_chan, struct ast_channel *sub_chan, const char *sub_location, const char *sub_args, int ignore_hangup)
{
	int res;
	char *args_str;
	size_t args_len;

	if (ast_strlen_zero(sub_args)) {
		return ast_app_exec_sub(autoservice_chan, sub_chan, sub_location, ignore_hangup);
	}

	/* Create the Gosub application argument string. */
	args_len = strlen(sub_location) + strlen(sub_args) + 3;
	args_str = ast_malloc(args_len);
	if (!args_str) {
		return -1;
	}
	snprintf(args_str, args_len, "%s(%s)", sub_location, sub_args);

	res = ast_app_exec_sub(autoservice_chan, sub_chan, args_str, ignore_hangup);
	ast_free(args_str);
	return res;
}

/*! \brief The container for the voicemail provider */
static AO2_GLOBAL_OBJ_STATIC(vm_provider);

/*! Voicemail not registered warning */
static int vm_warnings;

int ast_vm_is_registered(void)
{
	struct ast_vm_functions *table;
	int is_registered;

	table = ao2_global_obj_ref(vm_provider);
	is_registered = table ? 1 : 0;
	ao2_cleanup(table);
	return is_registered;
}

int __ast_vm_register(const struct ast_vm_functions *vm_table, struct ast_module *module)
{
	RAII_VAR(struct ast_vm_functions *, table, NULL, ao2_cleanup);

	if (!vm_table->module_name) {
		ast_log(LOG_ERROR, "Voicemail provider missing required information.\n");
		return -1;
	}
	if (vm_table->module_version != VM_MODULE_VERSION) {
		ast_log(LOG_ERROR, "Voicemail provider '%s' has incorrect version\n",
			vm_table->module_name);
		return -1;
	}

	table = ao2_global_obj_ref(vm_provider);
	if (table) {
		ast_log(LOG_WARNING, "Voicemail provider already registered by %s.\n",
			table->module_name);
		return AST_MODULE_LOAD_DECLINE;
	}

	table = ao2_alloc_options(sizeof(*table), NULL, AO2_ALLOC_OPT_LOCK_NOLOCK);
	if (!table) {
		return -1;
	}
	*table = *vm_table;
	table->module = module;

	ao2_global_obj_replace_unref(vm_provider, table);
	return 0;
}

void ast_vm_unregister(const char *module_name)
{
	struct ast_vm_functions *table;

	table = ao2_global_obj_ref(vm_provider);
	if (table && !strcmp(table->module_name, module_name)) {
		ao2_global_obj_release(vm_provider);
	}
	ao2_cleanup(table);
}

#ifdef TEST_FRAMEWORK
/*! \brief Holding container for the voicemail provider used while testing */
static AO2_GLOBAL_OBJ_STATIC(vm_provider_holder);
static int provider_is_swapped = 0;

void ast_vm_test_swap_table_in(const struct ast_vm_functions *vm_table)
{
	RAII_VAR(struct ast_vm_functions *, holding_table, NULL, ao2_cleanup);
	RAII_VAR(struct ast_vm_functions *, new_table, NULL, ao2_cleanup);

	if (provider_is_swapped) {
		ast_log(LOG_ERROR, "Attempted to swap in test function table without swapping out old test table.\n");
		return;
	}

	holding_table = ao2_global_obj_ref(vm_provider);

	if (holding_table) {
		ao2_global_obj_replace_unref(vm_provider_holder, holding_table);
	}

	new_table = ao2_alloc_options(sizeof(*new_table), NULL, AO2_ALLOC_OPT_LOCK_NOLOCK);
	if (!new_table) {
		return;
	}
	*new_table = *vm_table;

	ao2_global_obj_replace_unref(vm_provider, new_table);
	provider_is_swapped = 1;
}

void ast_vm_test_swap_table_out(void)
{
	RAII_VAR(struct ast_vm_functions *, held_table, NULL, ao2_cleanup);

	if (!provider_is_swapped) {
		ast_log(LOG_ERROR, "Attempted to swap out test function table, but none is currently installed.\n");
		return;
	}

	held_table = ao2_global_obj_ref(vm_provider_holder);
	if (!held_table) {
		return;
	}

	ao2_global_obj_replace_unref(vm_provider, held_table);
	ao2_global_obj_release(vm_provider_holder);
	provider_is_swapped = 0;
}
#endif

/*! \brief The container for the voicemail greeter provider */
static AO2_GLOBAL_OBJ_STATIC(vm_greeter_provider);

/*! Voicemail greeter not registered warning */
static int vm_greeter_warnings;

int ast_vm_greeter_is_registered(void)
{
	struct ast_vm_greeter_functions *table;
	int is_registered;

	table = ao2_global_obj_ref(vm_greeter_provider);
	is_registered = table ? 1 : 0;
	ao2_cleanup(table);
	return is_registered;
}

int __ast_vm_greeter_register(const struct ast_vm_greeter_functions *vm_table, struct ast_module *module)
{
	RAII_VAR(struct ast_vm_greeter_functions *, table, NULL, ao2_cleanup);

	if (!vm_table->module_name) {
		ast_log(LOG_ERROR, "Voicemail greeter provider missing required information.\n");
		return -1;
	}
	if (vm_table->module_version != VM_GREETER_MODULE_VERSION) {
		ast_log(LOG_ERROR, "Voicemail greeter provider '%s' has incorrect version\n",
			vm_table->module_name);
		return -1;
	}

	table = ao2_global_obj_ref(vm_greeter_provider);
	if (table) {
		ast_log(LOG_WARNING, "Voicemail greeter provider already registered by %s.\n",
			table->module_name);
		return AST_MODULE_LOAD_DECLINE;
	}

	table = ao2_alloc_options(sizeof(*table), NULL, AO2_ALLOC_OPT_LOCK_NOLOCK);
	if (!table) {
		return -1;
	}
	*table = *vm_table;
	table->module = module;

	ao2_global_obj_replace_unref(vm_greeter_provider, table);
	return 0;
}

void ast_vm_greeter_unregister(const char *module_name)
{
	struct ast_vm_greeter_functions *table;

	table = ao2_global_obj_ref(vm_greeter_provider);
	if (table && !strcmp(table->module_name, module_name)) {
		ao2_global_obj_release(vm_greeter_provider);
	}
	ao2_cleanup(table);
}

#ifdef TEST_FRAMEWORK
static ast_vm_test_create_user_fn *ast_vm_test_create_user_func = NULL;
static ast_vm_test_destroy_user_fn *ast_vm_test_destroy_user_func = NULL;

void ast_install_vm_test_functions(ast_vm_test_create_user_fn *vm_test_create_user_func,
	ast_vm_test_destroy_user_fn *vm_test_destroy_user_func)
{
	ast_vm_test_create_user_func = vm_test_create_user_func;
	ast_vm_test_destroy_user_func = vm_test_destroy_user_func;
}

void ast_uninstall_vm_test_functions(void)
{
	ast_vm_test_create_user_func = NULL;
	ast_vm_test_destroy_user_func = NULL;
}
#endif

static void vm_warn_no_provider(void)
{
	if (vm_warnings++ % 10 == 0) {
		ast_verb(3, "No voicemail provider registered.\n");
	}
}

#define VM_API_CALL(res, api_call, api_parms)								\
	do {																	\
		struct ast_vm_functions *table;										\
		table = ao2_global_obj_ref(vm_provider);							\
		if (!table) {														\
			vm_warn_no_provider();											\
		} else if (table->api_call) {										\
			ast_module_ref(table->module);									\
			(res) = table->api_call api_parms;								\
			ast_module_unref(table->module);								\
		}																	\
		ao2_cleanup(table);													\
	} while (0)

static void vm_greeter_warn_no_provider(void)
{
	if (vm_greeter_warnings++ % 10 == 0) {
		ast_verb(3, "No voicemail greeter provider registered.\n");
	}
}

#define VM_GREETER_API_CALL(res, api_call, api_parms)						\
	do {																	\
		struct ast_vm_greeter_functions *table;								\
		table = ao2_global_obj_ref(vm_greeter_provider);					\
		if (!table) {														\
			vm_greeter_warn_no_provider();									\
		} else if (table->api_call) {										\
			ast_module_ref(table->module);									\
			(res) = table->api_call api_parms;								\
			ast_module_unref(table->module);								\
		}																	\
		ao2_cleanup(table);													\
	} while (0)

int ast_app_has_voicemail(const char *mailboxes, const char *folder)
{
	int res = 0;

	VM_API_CALL(res, has_voicemail, (mailboxes, folder));
	return res;
}

/*!
 * \internal
 * \brief Function used as a callback for ast_copy_recording_to_vm when a real one isn't installed.
 * \param vm_rec_data Stores crucial information about the voicemail that will basically just be used
 * to figure out what the name of the recipient was supposed to be
 */
int ast_app_copy_recording_to_vm(struct ast_vm_recording_data *vm_rec_data)
{
	int res = -1;

	VM_API_CALL(res, copy_recording_to_vm, (vm_rec_data));
	return res;
}

int ast_app_inboxcount(const char *mailboxes, int *newmsgs, int *oldmsgs)
{
	int res = 0;

	if (newmsgs) {
		*newmsgs = 0;
	}
	if (oldmsgs) {
		*oldmsgs = 0;
	}

	VM_API_CALL(res, inboxcount, (mailboxes, newmsgs, oldmsgs));
	return res;
}

int ast_app_inboxcount2(const char *mailboxes, int *urgentmsgs, int *newmsgs, int *oldmsgs)
{
	int res = 0;

	if (newmsgs) {
		*newmsgs = 0;
	}
	if (oldmsgs) {
		*oldmsgs = 0;
	}
	if (urgentmsgs) {
		*urgentmsgs = 0;
	}

	VM_API_CALL(res, inboxcount2, (mailboxes, urgentmsgs, newmsgs, oldmsgs));
	return res;
}

int ast_app_sayname(struct ast_channel *chan, const char *mailbox_id)
{
	int res = -1;

	VM_GREETER_API_CALL(res, sayname, (chan, mailbox_id));
	return res;
}

int ast_app_messagecount(const char *mailbox_id, const char *folder)
{
	int res = 0;

	VM_API_CALL(res, messagecount, (mailbox_id, folder));
	return res;
}

const char *ast_vm_index_to_foldername(int id)
{
	const char *res = NULL;

	VM_API_CALL(res, index_to_foldername, (id));
	return res;
}

struct ast_vm_mailbox_snapshot *ast_vm_mailbox_snapshot_create(const char *mailbox,
	const char *context,
	const char *folder,
	int descending,
	enum ast_vm_snapshot_sort_val sort_val,
	int combine_INBOX_and_OLD)
{
	struct ast_vm_mailbox_snapshot *res = NULL;

	VM_API_CALL(res, mailbox_snapshot_create, (mailbox, context, folder, descending,
		sort_val, combine_INBOX_and_OLD));
	return res;
}

struct ast_vm_mailbox_snapshot *ast_vm_mailbox_snapshot_destroy(struct ast_vm_mailbox_snapshot *mailbox_snapshot)
{
	struct ast_vm_mailbox_snapshot *res = NULL;

	VM_API_CALL(res, mailbox_snapshot_destroy, (mailbox_snapshot));
	return res;
}

int ast_vm_msg_move(const char *mailbox,
	const char *context,
	size_t num_msgs,
	const char *oldfolder,
	const char *old_msg_ids[],
	const char *newfolder)
{
	int res = 0;

	VM_API_CALL(res, msg_move, (mailbox, context, num_msgs, oldfolder, old_msg_ids,
		newfolder));
	return res;
}

int ast_vm_msg_remove(const char *mailbox,
	const char *context,
	size_t num_msgs,
	const char *folder,
	const char *msgs[])
{
	int res = 0;

	VM_API_CALL(res, msg_remove, (mailbox, context, num_msgs, folder, msgs));
	return res;
}

int ast_vm_msg_forward(const char *from_mailbox,
	const char *from_context,
	const char *from_folder,
	const char *to_mailbox,
	const char *to_context,
	const char *to_folder,
	size_t num_msgs,
	const char *msg_ids[],
	int delete_old)
{
	int res = 0;

	VM_API_CALL(res, msg_forward, (from_mailbox, from_context, from_folder, to_mailbox,
		to_context, to_folder, num_msgs, msg_ids, delete_old));
	return res;
}

int ast_vm_msg_play(struct ast_channel *chan,
	const char *mailbox,
	const char *context,
	const char *folder,
	const char *msg_num,
	ast_vm_msg_play_cb *cb)
{
	int res = 0;

	VM_API_CALL(res, msg_play, (chan, mailbox, context, folder, msg_num, cb));
	return res;
}

#ifdef TEST_FRAMEWORK
int ast_vm_test_create_user(const char *context, const char *mailbox)
{
	if (ast_vm_test_create_user_func) {
		return ast_vm_test_create_user_func(context, mailbox);
	}
	return 0;
}

int ast_vm_test_destroy_user(const char *context, const char *mailbox)
{
	if (ast_vm_test_destroy_user_func) {
		return ast_vm_test_destroy_user_func(context, mailbox);
	}
	return 0;
}
#endif

static int external_sleep(struct ast_channel *chan, int ms)
{
	usleep(ms * 1000);
	return 0;
}

static int sf_stream(struct ast_channel *chan, struct ast_channel *chan2, const char *digits, int frequency, int is_external)
{
	/* Bell System Technical Journal 39 (Nov. 1960) */
	#define SF_ON 67
	#define SF_OFF 33
	#define SF_BETWEEN 600

	const char *ptr;
	int res;
	struct ast_silence_generator *silgen = NULL, *silgen2 = NULL;
	char *freq;
	int (*my_sleep)(struct ast_channel *chan, int ms);

	if (frequency >= 100000) {
		ast_log(LOG_WARNING, "Frequency too large: %d\n", frequency);
		return -1;
	}

	if (is_external) {
		my_sleep = external_sleep;
	} else {
		my_sleep = ast_safe_sleep;
	}

	/* Need a quiet time before sending digits. */
	if (ast_opt_transmit_silence) {
		silgen = ast_channel_start_silence_generator(chan);
		if (chan2) {
			silgen2 = ast_channel_start_silence_generator(chan2);
		}
	}
	if (chan2) {
		ast_autoservice_start(chan2);
	}
	res = my_sleep(chan, 100);
	if (chan2) {
		ast_autoservice_stop(chan2);
	}
	if (res) {
		goto sf_stream_cleanup;
	}

/* len(SF_ON) + len(SF_OFF) + len(0) + maxlen(frequency) + /,/ + null terminator = 2 + 2 + 1 + 5 at most + 3 + 1 = 14 */
#define SF_BUF_LEN  20
	freq = ast_alloca(SF_BUF_LEN); /* min 20 to avoid compiler warning about insufficient buffer */
	/* pauses need to send audio, so send 0 Hz */
	snprintf(freq, SF_BUF_LEN, "%d/%d,%d/%d", frequency, SF_ON, 0, SF_OFF);

	for (ptr = digits; *ptr; ptr++) {
		if (*ptr == 'w') {
			/* 'w' -- wait half a second */
			if (chan2) {
				ast_autoservice_start(chan2);
			}
			res = my_sleep(chan, 500);
			if (chan2) {
				ast_autoservice_stop(chan2);
			}
			if (res) {
				break;
			}
		} else if (*ptr == 'h' || *ptr == 'H') {
			/* 'h' -- 2600 Hz for half a second, but
				only to far end of trunk, not near end */
			ast_playtones_start(chan, 0, "2600", 0);
			if (chan2) {
				ast_playtones_start(chan2, 0, "0", 0);
				ast_autoservice_start(chan2);
			}
			res = my_sleep(chan, 250);
			ast_senddigit_mf_end(chan);
			if (chan2) {
				ast_autoservice_stop(chan2);
				ast_senddigit_mf_end(chan2);
			}
			if (res) {
				break;
			}
		} else if (strchr("0123456789*#ABCDabcdwWfF", *ptr)) {
			if (*ptr == 'f' || *ptr == 'F') {
				/* ignore return values if not supported by channel */
				ast_indicate(chan, AST_CONTROL_FLASH);
			} else if (*ptr == 'W') {
				/* ignore return values if not supported by channel */
				ast_indicate(chan, AST_CONTROL_WINK);
			} else {
				/* Character represents valid SF */
				int beeps;
				if (*ptr == '*') {
					beeps = 11;
				} else if (*ptr == '#') {
					beeps = 12;
				} else if (*ptr == 'D') {
					beeps = 13;
				} else if (*ptr == 'C') {
					beeps = 14;
				} else if (*ptr == 'B') {
					beeps = 15;
				} else if (*ptr == 'A') {
					beeps = 16;
				} else {
					beeps = (*ptr == '0') ? 10 : *ptr - '0';
				}
				while (beeps-- > 0) {
					ast_playtones_start(chan, 0, freq, 0);
					if (chan2) {
						ast_playtones_start(chan2, 0, freq, 0);
						ast_autoservice_start(chan2);
					}
					res = my_sleep(chan, SF_ON + SF_OFF);
					ast_senddigit_mf_end(chan);
					if (chan2) {
						ast_autoservice_stop(chan2);
						ast_senddigit_mf_end(chan2);
					}
					if (res) {
						break;
					}
				}
			}
			/* pause between digits */
			ast_playtones_start(chan, 0, "0", 0);
			if (chan2) {
				ast_playtones_start(chan2, 0, "0", 0);
				ast_autoservice_start(chan2);
			}
			res = my_sleep(chan, SF_BETWEEN);
			if (chan2) {
				ast_autoservice_stop(chan2);
				ast_senddigit_mf_end(chan2);
			}
			ast_senddigit_mf_end(chan);
			if (res) {
				break;
			}
		} else {
			ast_log(LOG_WARNING, "Illegal SF character '%c' in string. (0-9A-DwWfFhH allowed)\n", *ptr);
		}
	}

sf_stream_cleanup:
	if (silgen) {
		ast_channel_stop_silence_generator(chan, silgen);
	}
	if (silgen2) {
		ast_channel_stop_silence_generator(chan2, silgen2);
	}

	return res;
}

static int mf_stream(struct ast_channel *chan, struct ast_channel *chan2, const char *digits, int between, unsigned int duration,
	unsigned int durationkp, unsigned int durationst, int is_external)
{
	const char *ptr;
	int res;
	struct ast_silence_generator *silgen = NULL, *silgen2 = NULL;
	int (*my_sleep)(struct ast_channel *chan, int ms);

	if (is_external) {
		my_sleep = external_sleep;
	} else {
		my_sleep = ast_safe_sleep;
	}

	if (!between) {
		between = 100;
	}

	/* Need a quiet time before sending digits. */
	if (ast_opt_transmit_silence) {
		silgen = ast_channel_start_silence_generator(chan);
		if (chan2) {
			silgen2 = ast_channel_start_silence_generator(chan2);
		}
	}
	if (chan2) {
		ast_autoservice_start(chan2);
	}
	res = my_sleep(chan, 100);
	if (chan2) {
		ast_autoservice_stop(chan2);
	}
	if (res) {
		goto mf_stream_cleanup;
	}

	for (ptr = digits; *ptr; ptr++) {
		if (*ptr == 'w') {
			/* 'w' -- wait half a second */
			if (chan2) {
				ast_autoservice_start(chan2);
			}
			res = my_sleep(chan, 500);
			if (chan2) {
				ast_autoservice_stop(chan2);
			}
			if (res) {
				break;
			}
		} else if (*ptr == 'h' || *ptr == 'H') {
			/* 'h' -- 2600 Hz for half a second, but
				only to far end of trunk, not near end */
			ast_playtones_start(chan, 0, "2600", 0);
			if (chan2) {
				ast_playtones_start(chan2, 0, "0", 0);
				ast_autoservice_start(chan2);
			}
			res = my_sleep(chan, 250);
			ast_senddigit_mf_end(chan);
			if (chan2) {
				ast_autoservice_stop(chan2);
				ast_senddigit_mf_end(chan2);
			}
			if (res) {
				break;
			}
		} else if (strchr("0123456789*#ABCwWfF", *ptr)) {
			if (*ptr == 'f' || *ptr == 'F') {
				/* ignore return values if not supported by channel */
				ast_indicate(chan, AST_CONTROL_FLASH);
			} else if (*ptr == 'W') {
				/* ignore return values if not supported by channel */
				ast_indicate(chan, AST_CONTROL_WINK);
			} else {
				/* Character represents valid MF */
				ast_senddigit_mf(chan, *ptr, duration, durationkp, durationst, is_external);
				if (chan2) {
					ast_senddigit_mf(chan2, *ptr, duration, durationkp, durationst, is_external);
				}
			}
			/* pause between digits */
			/* The DSP code in GABpbx does not currently properly receive repeated tones
				if no audio is sent in the middle. Simply sending audio (even 0 Hz)
				works around this limitation and guarantees the correct behavior.
				*/
			ast_playtones_start(chan, 0, "0", 0);
			if (chan2) {
				ast_playtones_start(chan2, 0, "0", 0);
				ast_autoservice_start(chan2);
			}
			res = my_sleep(chan, between);
			ast_senddigit_mf_end(chan);
			if (chan2) {
				ast_autoservice_stop(chan2);
				ast_senddigit_mf_end(chan2);
			}
			if (res) {
				break;
			}
		} else {
			ast_log(LOG_WARNING, "Illegal MF character '%c' in string. (0-9*#ABCwWfFhH allowed)\n", *ptr);
		}
	}

mf_stream_cleanup:
	if (silgen) {
		ast_channel_stop_silence_generator(chan, silgen);
	}
	if (silgen2) {
		ast_channel_stop_silence_generator(chan2, silgen2);
	}

	return res;
}

static int dtmf_stream(struct ast_channel *chan, const char *digits, int between, unsigned int duration, int is_external)
{
	const char *ptr;
	int res;
	struct ast_silence_generator *silgen = NULL;
	int (*my_sleep)(struct ast_channel *chan, int ms);
	int (*my_senddigit)(struct ast_channel *chan, char digit, unsigned int duration);

	if (is_external) {
		my_sleep = external_sleep;
		my_senddigit = ast_senddigit_external;
	} else {
		my_sleep = ast_safe_sleep;
		my_senddigit = ast_senddigit;
	}

	if (!between) {
		between = 100;
	}

	/* Need a quiet time before sending digits. */
	if (ast_opt_transmit_silence) {
		silgen = ast_channel_start_silence_generator(chan);
	}
	res = my_sleep(chan, 100);
	if (res) {
		goto dtmf_stream_cleanup;
	}

	for (ptr = digits; *ptr; ptr++) {
		if (*ptr == 'w') {
			/* 'w' -- wait half a second */
			res = my_sleep(chan, 500);
			if (res) {
				break;
			}
		} else if (*ptr == 'W') {
			/* 'W' -- wait a second */
			res = my_sleep(chan, 1000);
			if (res) {
				break;
			}
		} else if (strchr("0123456789*#abcdfABCDF", *ptr)) {
			if (*ptr == 'f' || *ptr == 'F') {
				/* ignore return values if not supported by channel */
				ast_indicate(chan, AST_CONTROL_FLASH);
			} else {
				/* Character represents valid DTMF */
				my_senddigit(chan, *ptr, duration);
			}
			/* pause between digits */
			res = my_sleep(chan, between);
			if (res) {
				break;
			}
		} else {
			ast_log(LOG_WARNING, "Illegal DTMF character '%c' in string. (0-9*#aAbBcCdD allowed)\n", *ptr);
		}
	}

dtmf_stream_cleanup:
	if (silgen) {
		ast_channel_stop_silence_generator(chan, silgen);
	}

	return res;
}

int ast_sf_stream(struct ast_channel *chan, struct ast_channel *peer, struct ast_channel *chan2, const char *digits, int frequency, int is_external)
{
	int res;
	if (frequency <= 0) {
		frequency = 2600;
	}
	if (!is_external && !chan2 && peer && ast_autoservice_start(peer)) {
		return -1;
	}
	res = sf_stream(chan, chan2, digits, frequency, is_external);
	if (!is_external && !chan2 && peer && ast_autoservice_stop(peer)) {
		res = -1;
	}
	return res;
}

int ast_mf_stream(struct ast_channel *chan, struct ast_channel *peer, struct ast_channel *chan2, const char *digits,
	int between, unsigned int duration, unsigned int durationkp, unsigned int durationst, int is_external)
{
	int res;
	if (!is_external && !chan2 && peer && ast_autoservice_start(peer)) {
		return -1;
	}
	res = mf_stream(chan, chan2, digits, between, duration, durationkp, durationst, is_external);
	if (!is_external && !chan2 && peer && ast_autoservice_stop(peer)) {
		res = -1;
	}
	return res;
}

int ast_dtmf_stream(struct ast_channel *chan, struct ast_channel *peer, const char *digits, int between, unsigned int duration)
{
	int res;

	if (peer && ast_autoservice_start(peer)) {
		return -1;
	}
	res = dtmf_stream(chan, digits, between, duration, 0);
	if (peer && ast_autoservice_stop(peer)) {
		res = -1;
	}

	return res;
}

void ast_dtmf_stream_external(struct ast_channel *chan, const char *digits, int between, unsigned int duration)
{
	dtmf_stream(chan, digits, between, duration, 1);
}

struct linear_state {
	int fd;
	int autoclose;
	int allowoverride;
	struct ast_format *origwfmt;
};

static void linear_release(struct ast_channel *chan, void *params)
{
	struct linear_state *ls = params;

	if (ls->origwfmt && ast_set_write_format(chan, ls->origwfmt)) {
		ast_log(LOG_WARNING, "Unable to restore channel '%s' to format '%s'\n",
			ast_channel_name(chan), ast_format_get_name(ls->origwfmt));
	}
	ao2_cleanup(ls->origwfmt);

	if (ls->autoclose) {
		close(ls->fd);
	}

	ast_free(params);
}

static int linear_generator(struct ast_channel *chan, void *data, int len, int samples)
{
	short buf[2048 + AST_FRIENDLY_OFFSET / 2];
	struct linear_state *ls = data;
	struct ast_frame f = {
		.frametype = AST_FRAME_VOICE,
		.data.ptr = buf + AST_FRIENDLY_OFFSET / 2,
		.offset = AST_FRIENDLY_OFFSET,
	};
	int res;

	f.subclass.format = ast_format_slin;

	len = samples * 2;
	if (len > sizeof(buf) - AST_FRIENDLY_OFFSET) {
		ast_log(LOG_WARNING, "Can't generate %d bytes of data!\n" , len);
		len = sizeof(buf) - AST_FRIENDLY_OFFSET;
	}
	res = read(ls->fd, buf + AST_FRIENDLY_OFFSET/2, len);
	if (res > 0) {
		f.datalen = res;
		f.samples = res / 2;
		ast_write(chan, &f);
		if (res == len) {
			return 0;
		}
	}
	return -1;
}

static void *linear_alloc(struct ast_channel *chan, void *params)
{
	struct linear_state *ls = params;

	if (!params) {
		return NULL;
	}

	/* In this case, params is already malloc'd */
	if (ls->allowoverride) {
		ast_set_flag(ast_channel_flags(chan), AST_FLAG_WRITE_INT);
	} else {
		ast_clear_flag(ast_channel_flags(chan), AST_FLAG_WRITE_INT);
	}

	ls->origwfmt = ao2_bump(ast_channel_writeformat(chan));

	if (ast_set_write_format(chan, ast_format_slin)) {
		ast_log(LOG_WARNING, "Unable to set '%s' to linear format (write)\n", ast_channel_name(chan));
		ao2_cleanup(ls->origwfmt);
		ast_free(ls);
		ls = params = NULL;
	}

	return params;
}

static struct ast_generator linearstream =
{
	.alloc = linear_alloc,
	.release = linear_release,
	.generate = linear_generator,
};

int ast_linear_stream(struct ast_channel *chan, const char *filename, int fd, int allowoverride)
{
	struct linear_state *lin;
	char tmpf[256];
	int autoclose = 0;

	if (fd < 0) {
		if (ast_strlen_zero(filename)) {
			return -1;
		}

		autoclose = 1;

		if (filename[0] == '/') {
			ast_copy_string(tmpf, filename, sizeof(tmpf));
		} else {
			snprintf(tmpf, sizeof(tmpf), "%s/%s/%s", ast_config_AST_DATA_DIR, "sounds", filename);
		}

		fd = open(tmpf, O_RDONLY);
		if (fd < 0) {
			ast_log(LOG_WARNING, "Unable to open file '%s': %s\n", tmpf, strerror(errno));
			return -1;
		}
	}

	lin = ast_calloc(1, sizeof(*lin));
	if (!lin) {
		if (autoclose) {
			close(fd);
		}

		return -1;
	}

	lin->fd = fd;
	lin->allowoverride = allowoverride;
	lin->autoclose = autoclose;

	return ast_activate_generator(chan, &linearstream, lin);
}

static int control_streamfile(struct ast_channel *chan,
	const char *file,
	const char *fwd,
	const char *rev,
	const char *stop,
	const char *suspend,
	const char *restart,
	int skipms,
	long *offsetms,
	const char *lang,
	ast_waitstream_fr_cb cb)
{
	char *breaks = NULL;
	char *end = NULL;
	int blen = 2;
	int res;
	long pause_restart_point = 0;
	long offset = 0;
	struct ast_silence_generator *silgen = NULL;

	if (!file) {
		return -1;
	}
	if (offsetms) {
		offset = *offsetms * 8; /* XXX Assumes 8kHz */
	}
	if (lang == NULL) {
		lang = ast_channel_language(chan);
	}

	if (stop) {
		blen += strlen(stop);
	}
	if (suspend) {
		blen += strlen(suspend);
	}
	if (restart) {
		blen += strlen(restart);
	}

	if (blen > 2) {
		breaks = ast_alloca(blen + 1);
		breaks[0] = '\0';
		if (stop) {
			strcat(breaks, stop);
		}
		if (suspend) {
			strcat(breaks, suspend);
		}
		if (restart) {
			strcat(breaks, restart);
		}
	}

	if ((end = strchr(file, ':'))) {
		if (!strcasecmp(end, ":end")) {
			*end = '\0';
			end++;
		} else {
			end = NULL;
		}
	}

	for (;;) {
		ast_stopstream(chan);
		res = ast_streamfile(chan, file, lang);
		if (!res) {
			if (pause_restart_point) {
				ast_seekstream(ast_channel_stream(chan), pause_restart_point, SEEK_SET);
				pause_restart_point = 0;
			}
			else if (end || offset < 0) {
				if (offset == -8) {
					offset = 0;
				}
				ast_verb(3, "ControlPlayback seek to offset %ld from end\n", offset);

				ast_seekstream(ast_channel_stream(chan), offset, SEEK_END);
				end = NULL;
				offset = 0;
			} else if (offset) {
				ast_verb(3, "ControlPlayback seek to offset %ld\n", offset);
				ast_seekstream(ast_channel_stream(chan), offset, SEEK_SET);
				offset = 0;
			}
			if (cb) {
				res = ast_waitstream_fr_w_cb(chan, breaks, fwd, rev, skipms, cb);
			} else {
				res = ast_waitstream_fr(chan, breaks, fwd, rev, skipms);
			}
		}

		if (res < 1) {
			break;
		}

		/* We go at next loop if we got the restart char */
		if ((restart && strchr(restart, res)) || res == AST_CONTROL_STREAM_RESTART) {
			ast_debug(1, "we'll restart the stream here at next loop\n");
			pause_restart_point = 0;
			ast_test_suite_event_notify("PLAYBACK","Channel: %s\r\n"
				"Control: %s\r\n",
				ast_channel_name(chan),
				"Restart");
			continue;
		}

		if ((suspend && strchr(suspend, res)) || res == AST_CONTROL_STREAM_SUSPEND) {
			pause_restart_point = ast_tellstream(ast_channel_stream(chan));

			if (ast_opt_transmit_silence) {
				silgen = ast_channel_start_silence_generator(chan);
			}
			ast_test_suite_event_notify("PLAYBACK","Channel: %s\r\n"
				"Control: %s\r\n",
				ast_channel_name(chan),
				"Pause");
			for (;;) {
				ast_stopstream(chan);
				if (!(res = ast_waitfordigit(chan, 1000))) {
					continue;
				} else if (res == -1 || (suspend && strchr(suspend, res)) || (stop && strchr(stop, res))
						|| res == AST_CONTROL_STREAM_SUSPEND || res == AST_CONTROL_STREAM_STOP) {
					break;
				}
			}
			if (silgen) {
				ast_channel_stop_silence_generator(chan, silgen);
				silgen = NULL;
			}

			if ((suspend && (res == *suspend)) || res == AST_CONTROL_STREAM_SUSPEND) {
				res = 0;
				ast_test_suite_event_notify("PLAYBACK","Channel: %s\r\n"
					"Control: %s\r\n",
					ast_channel_name(chan),
					"Unpause");
				continue;
			}
		}

		if (res == -1) {
			break;
		}

		/* if we get one of our stop chars, return it to the calling function */
		if ((stop && strchr(stop, res)) || res == AST_CONTROL_STREAM_STOP) {
			ast_test_suite_event_notify("PLAYBACK","Channel: %s\r\n"
				"Control: %s\r\n",
				ast_channel_name(chan),
				"Stop");
			break;
		}
	}

	if (pause_restart_point) {
		offset = pause_restart_point;
	} else {
		if (ast_channel_stream(chan)) {
			offset = ast_tellstream(ast_channel_stream(chan));
		} else {
			offset = -8;  /* indicate end of file */
		}
	}

	if (offsetms) {
		*offsetms = offset / 8; /* samples --> ms ... XXX Assumes 8 kHz */
	}

	ast_stopstream(chan);

	return res;
}

int ast_control_streamfile_w_cb(struct ast_channel *chan,
	const char *file,
	const char *fwd,
	const char *rev,
	const char *stop,
	const char *suspend,
	const char *restart,
	int skipms,
	long *offsetms,
	ast_waitstream_fr_cb cb)
{
	return control_streamfile(chan, file, fwd, rev, stop, suspend, restart, skipms, offsetms, NULL, cb);
}

int ast_control_streamfile(struct ast_channel *chan, const char *file,
			   const char *fwd, const char *rev,
			   const char *stop, const char *suspend,
			   const char *restart, int skipms, long *offsetms)
{
	return control_streamfile(chan, file, fwd, rev, stop, suspend, restart, skipms, offsetms, NULL, NULL);
}

int ast_control_streamfile_lang(struct ast_channel *chan, const char *file,
	const char *fwd, const char *rev, const char *stop, const char *suspend,
	const char *restart, int skipms, const char *lang, long *offsetms)
{
	return control_streamfile(chan, file, fwd, rev, stop, suspend, restart, skipms, offsetms, lang, NULL);
}

enum control_tone_frame_response_result {
	CONTROL_TONE_RESPONSE_FAILED = -1,
	CONTROL_TONE_RESPONSE_NORMAL = 0,
	CONTROL_TONE_RESPONSE_FINISHED = 1,
};

static enum control_tone_frame_response_result control_tone_frame_response(struct ast_channel *chan, struct ast_frame *fr, struct ast_tone_zone_sound *ts, const char *tone, int *paused)
{
	switch (fr->subclass.integer) {
	case AST_CONTROL_STREAM_STOP:
		ast_playtones_stop(chan);
		return CONTROL_TONE_RESPONSE_FINISHED;
	case AST_CONTROL_STREAM_SUSPEND:
		if (*paused) {
			*paused = 0;
			if (ast_playtones_start(chan, 0, ts ? ts->data : tone, 0)) {
				return CONTROL_TONE_RESPONSE_FAILED;
			}
		} else {
			*paused = 1;
			ast_playtones_stop(chan);
		}
		return CONTROL_TONE_RESPONSE_NORMAL;
	case AST_CONTROL_STREAM_RESTART:
		ast_playtones_stop(chan);
		if (ast_playtones_start(chan, 0, ts ? ts->data : tone, 0)) {
			return CONTROL_TONE_RESPONSE_FAILED;
		}
		return CONTROL_TONE_RESPONSE_NORMAL;
	case AST_CONTROL_STREAM_REVERSE:
		ast_log(LOG_NOTICE, "Media control operation 'reverse' not supported for media type 'tone'\n");
		return CONTROL_TONE_RESPONSE_NORMAL;
	case AST_CONTROL_STREAM_FORWARD:
		ast_log(LOG_NOTICE, "Media control operation 'forward' not supported for media type 'tone'\n");
		return CONTROL_TONE_RESPONSE_NORMAL;
	case AST_CONTROL_HANGUP:
	case AST_CONTROL_BUSY:
	case AST_CONTROL_CONGESTION:
		return CONTROL_TONE_RESPONSE_FINISHED;
	}

	return CONTROL_TONE_RESPONSE_NORMAL;
}

static int parse_tone_uri(char *tone_parser,
	const char **tone_indication,
	const char **tone_zone)
{
	*tone_indication = strsep(&tone_parser, ";");

	if (ast_strlen_zero(tone_parser)) {
		/* Only the indication is included */
		return 0;
	}

	if (!(strncmp(tone_parser, "tonezone=", 9))) {
		*tone_zone = tone_parser + 9;
	} else {
		ast_log(LOG_ERROR, "Unexpected Tone URI component: %s\n", tone_parser);
		return -1;
	}

	return 0;
}

int ast_control_tone(struct ast_channel *chan, const char *tone)
{
	struct ast_tone_zone *zone = NULL;
	struct ast_tone_zone_sound *ts;
	int paused = 0;
	int res = 0;

	const char *tone_indication = NULL;
	const char *tone_zone = NULL;
	char *tone_uri_parser;

	if (ast_strlen_zero(tone)) {
		return -1;
	}

	tone_uri_parser = ast_strdupa(tone);

	if (parse_tone_uri(tone_uri_parser, &tone_indication, &tone_zone)) {
		return -1;
	}

	if (tone_zone) {
		zone = ast_get_indication_zone(tone_zone);
	}

	ts = ast_get_indication_tone(zone ? zone : ast_channel_zone(chan), tone_indication);

	if (ast_playtones_start(chan, 0, ts ? ts->data : tone_indication, 0)) {
		res = -1;
	}

	while (!res) {
		struct ast_frame *fr;

		if (ast_waitfor(chan, -1) < 0) {
			res = -1;
			break;
		}

		fr = ast_read_noaudio(chan);

		if (!fr) {
			res = -1;
			break;
		}

		if (fr->frametype != AST_FRAME_CONTROL) {
			continue;
		}

		res = control_tone_frame_response(chan, fr, ts, tone_indication, &paused);
		if (res == CONTROL_TONE_RESPONSE_FINISHED) {
			res = 0;
			break;
		} else if (res == CONTROL_TONE_RESPONSE_FAILED) {
			res = -1;
			break;
		}
	}

	if (ts) {
		ast_tone_zone_sound_unref(ts);
	}

	if (zone) {
		ast_tone_zone_unref(zone);
	}

	return res;
}

int ast_play_and_wait(struct ast_channel *chan, const char *fn)
{
	int d = 0;

	if ((d = ast_streamfile(chan, fn, ast_channel_language(chan)))) {
		return d;
	}

	d = ast_waitstream(chan, AST_DIGIT_ANY);

	ast_stopstream(chan);

	return d;
}

/*!
 * \brief Construct a silence frame of the same duration as \a orig.
 *
 * The \a orig frame must be \ref ast_format_slin.
 *
 * \param orig Frame as basis for silence to generate.
 * \return New frame of silence; free with ast_frfree().
 * \retval NULL on error.
 */
static struct ast_frame *make_silence(const struct ast_frame *orig)
{
	struct ast_frame *silence;
	size_t size;
	size_t datalen;
	size_t samples = 0;

	if (!orig) {
		return NULL;
	}
	do {
		if (ast_format_cmp(orig->subclass.format, ast_format_slin) == AST_FORMAT_CMP_NOT_EQUAL) {
			ast_log(LOG_WARNING, "Attempting to silence non-slin frame\n");
			return NULL;
		}

		samples += orig->samples;

		orig = AST_LIST_NEXT(orig, frame_list);
	} while (orig);

	ast_verb(4, "Silencing %zu samples\n", samples);


	datalen = sizeof(short) * samples;
	size = sizeof(*silence) + datalen;
	silence = ast_calloc(1, size);
	if (!silence) {
		return NULL;
	}

	silence->mallocd = AST_MALLOCD_HDR;
	silence->frametype = AST_FRAME_VOICE;
	silence->data.ptr = (void *)(silence + 1);
	silence->samples = samples;
	silence->datalen = datalen;

	silence->subclass.format = ao2_bump(ast_format_slin);

	return silence;
}

/*!
 * \brief Sets a channel's read format to \ref ast_format_slin, recording
 * its original format.
 *
 * \param chan Channel to modify.
 * \param[out] orig_format Output variable to store channel's original read
 *                         format.
 * \return 0 on success.
 * \return -1 on error.
 */
static int set_read_to_slin(struct ast_channel *chan, struct ast_format **orig_format)
{
	if (!chan || !orig_format) {
		return -1;
	}
	*orig_format = ao2_bump(ast_channel_readformat(chan));
	return ast_set_read_format(chan, ast_format_slin);
}

static int global_silence_threshold = 128;
static int global_maxsilence = 0;

/*! Optionally play a sound file or a beep, then record audio and video from the channel.
 * \param chan Channel to playback to/record from.
 * \param playfile Filename of sound to play before recording begins.
 * \param recordfile Filename to record to.
 * \param maxtime Maximum length of recording (in seconds).
 * \param fmt Format(s) to record message in. Multiple formats may be specified by separating them with a '|'.
 * \param duration Where to store actual length of the recorded message (in milliseconds).
 * \param sound_duration Where to store the length of the recorded message (in milliseconds), minus any silence
 * \param beep Whether to play a beep before starting to record.
 * \param silencethreshold
 * \param maxsilence Length of silence that will end a recording (in milliseconds).
 * \param path Optional filesystem path to unlock.
 * \param prepend If true, prepend the recorded audio to an existing file and follow prepend mode recording rules
 * \param acceptdtmf DTMF digits that will end the recording.
 * \param canceldtmf DTMF digits that will cancel the recording.
 * \param skip_confirmation_sound If true, don't play auth-thankyou at end. Nice for custom recording prompts in apps.
 * \param if_exists
 *
 * \retval -1 failure or hangup
 * \retval 'S' Recording ended from silence timeout
 * \retval 't' Recording ended from the message exceeding the maximum duration, or via DTMF in prepend mode
 * \retval dtmfchar Recording ended via the return value's DTMF character for either cancel or accept.
 */
static int __ast_play_and_record(struct ast_channel *chan, const char *playfile,
	const char *recordfile, int maxtime, const char *fmt, int *duration,
	int *sound_duration, int beep, int silencethreshold, int maxsilence,
	const char *path, int prepend, const char *acceptdtmf, const char *canceldtmf,
	int skip_confirmation_sound, enum ast_record_if_exists if_exists)
{
	int d = 0;
	char *fmts;
	char comment[256];
	int x, fmtcnt = 1, res = -1, outmsg = 0;
	struct ast_filestream *others[AST_MAX_FORMATS];
	const char *sfmt[AST_MAX_FORMATS];
	char *stringp = NULL;
	time_t start, end;
	struct ast_dsp *sildet = NULL;   /* silence detector dsp */
	int totalsilence = 0;
	int dspsilence = 0;
	int olddspsilence = 0;
	struct ast_format *rfmt = NULL;
	struct ast_silence_generator *silgen = NULL;
	char prependfile[PATH_MAX];
	int ioflags;	/* IO flags for writing output file */
	SCOPE_ENTER(3, "%s: play: '%s'  record: '%s'  path: '%s'  prepend: %d\n",
		ast_channel_name(chan), playfile, recordfile, path, prepend);

	ioflags = O_CREAT|O_WRONLY;

	switch (if_exists) {
	case AST_RECORD_IF_EXISTS_FAIL:
		ioflags |= O_EXCL;
		break;
	case AST_RECORD_IF_EXISTS_OVERWRITE:
		ioflags |= O_TRUNC;
		break;
	case AST_RECORD_IF_EXISTS_APPEND:
		ioflags |= O_APPEND;
		break;
	case AST_RECORD_IF_EXISTS_ERROR:
		ast_assert(0);
		break;
	}

	if (silencethreshold < 0) {
		silencethreshold = global_silence_threshold;
	}

	if (maxsilence < 0) {
		maxsilence = global_maxsilence;
	}

	/* barf if no pointer passed to store duration in */
	if (!duration) {
		ast_log(LOG_WARNING, "Error play_and_record called without duration pointer\n");
		return -1;
	}

	ast_debug(1, "play_and_record: %s, %s, '%s'\n", playfile ? playfile : "<None>", recordfile, fmt);
	snprintf(comment, sizeof(comment), "Playing %s, Recording to: %s on %s\n", playfile ? playfile : "<None>", recordfile, ast_channel_name(chan));

	if (playfile || beep) {
		if (!beep) {
			ast_trace(-1, "Playing '%s' to '%s'\n", playfile, ast_channel_name(chan));
			d = ast_play_and_wait(chan, playfile);
		}
		if (d > -1) {
			ast_trace(-1, "Playing 'beep' to '%s'\n", ast_channel_name(chan));
			d = ast_stream_and_wait(chan, "beep", "");
		}
		if (d < 0) {
			SCOPE_EXIT_RTN_VALUE(-1, "Failed to play. RC: %d\n", d);
		}
	}

	if (prepend) {
		ast_copy_string(prependfile, recordfile, sizeof(prependfile));
		strncat(prependfile, "-prepend", sizeof(prependfile) - strlen(prependfile) - 1);
		ast_trace(-1, "Prepending to '%s'\n", prependfile);
	}

	fmts = ast_strdupa(fmt);

	stringp = fmts;
	strsep(&stringp, "|");
	ast_debug(1, "Recording Formats: sfmts=%s\n", fmts);
	sfmt[0] = ast_strdupa(fmts);

	while ((fmt = strsep(&stringp, "|"))) {
		if (fmtcnt > AST_MAX_FORMATS - 1) {
			ast_log(LOG_WARNING, "Please increase AST_MAX_FORMATS in file.h\n");
			break;
		}
		/*
		 * Storage for 'fmt' is on the stack and held by 'fmts', which is maintained for
		 * the rest of this function. So okay to not duplicate 'fmt' here, but only keep
		 * a pointer to it.
		 */
		sfmt[fmtcnt++] = fmt;
	}

	end = start = time(NULL);  /* pre-initialize end to be same as start in case we never get into loop */
	for (x = 0; x < fmtcnt; x++) {
		others[x] = ast_writefile(prepend ? prependfile : recordfile, sfmt[x], comment, ioflags, 0, AST_FILE_MODE);
		ast_trace(-1, "x=%d, open writing:  %s format: %s, %p\n", x, prepend ? prependfile : recordfile, sfmt[x], others[x]);

		if (!others[x]) {
			break;
		}
	}

	if (path) {
		ast_unlock_path(path);
	}

	if (maxsilence > 0) {
		sildet = ast_dsp_new(); /* Create the silence detector */
		if (!sildet) {
			ast_log(LOG_WARNING, "Unable to create silence detector :(\n");
			return -1;
		}
		ast_dsp_set_threshold(sildet, silencethreshold);
		res = set_read_to_slin(chan, &rfmt);
		if (res < 0) {
			ast_log(LOG_WARNING, "Unable to set to linear mode, giving up\n");
			ast_dsp_free(sildet);
			ao2_cleanup(rfmt);
			return -1;
		}
	}

	if (!prepend) {
		/* Request a video update */
		ast_indicate(chan, AST_CONTROL_VIDUPDATE);

		if (ast_opt_transmit_silence) {
			silgen = ast_channel_start_silence_generator(chan);
		}
	}

	if (x == fmtcnt) {
		/* Loop, writing the packets we read to the writer(s), until
		 * we have reason to stop. */
		struct ast_frame *f;
		int paused = 0;
		int muted = 0;
		time_t pause_start = 0;
		int paused_secs = 0;
		int pausedsilence = 0;

		for (;;) {
			if (!(res = ast_waitfor(chan, 2000))) {
				ast_debug(1, "One waitfor failed, trying another\n");
				/* Try one more time in case of masq */
				if (!(res = ast_waitfor(chan, 2000))) {
					ast_log(LOG_WARNING, "No audio available on %s??\n", ast_channel_name(chan));
					res = -1;
				}
			}

			if (res < 0) {
				f = NULL;
				break;
			}
			if (!(f = ast_read(chan))) {
				break;
			}
			if (f->frametype == AST_FRAME_VOICE) {
				/* write each format */
				if (paused) {
					/* It's all good */
					res = 0;
				} else {
					struct ast_frame *silence = NULL;
					struct ast_frame *orig = f;

					if (muted) {
						silence = make_silence(orig);
						if (!silence) {
							ast_log(LOG_WARNING, "Error creating silence\n");
							break;
						}
						f = silence;
					}
					for (x = 0; x < fmtcnt; x++) {
						if (prepend && !others[x]) {
							break;
						}
						res = ast_writestream(others[x], f);
					}
					ast_frame_dtor(silence);
					f = orig;
				}

				/* Silence Detection */
				if (maxsilence > 0) {
					dspsilence = 0;
					ast_dsp_silence(sildet, f, &dspsilence);
					if (olddspsilence > dspsilence) {
						totalsilence += olddspsilence;
					}
					olddspsilence = dspsilence;

					if (paused) {
						/* record how much silence there was while we are paused */
						pausedsilence = dspsilence;
					} else if (dspsilence > pausedsilence) {
						/* ignore the paused silence */
						dspsilence -= pausedsilence;
					} else {
						/* dspsilence has reset, reset pausedsilence */
						pausedsilence = 0;
					}

					if (dspsilence > maxsilence) {
						/* Ended happily with silence */
						ast_verb(3, "Recording automatically stopped after a silence of %d seconds\n", dspsilence/1000);
						res = 'S';
						outmsg = 2;
						break;
					}
				}
				/* Exit on any error */
				if (res) {
					ast_log(LOG_WARNING, "Error writing frame\n");
					break;
				}
			} else if (f->frametype == AST_FRAME_VIDEO) {
				/* Write only once */
				ast_writestream(others[0], f);
			} else if (f->frametype == AST_FRAME_DTMF) {
				if (prepend) {
				/* stop recording with any digit */
					ast_verb(3, "User ended message by pressing %c\n", f->subclass.integer);
					res = 't';
					outmsg = 2;
					break;
				}
				if (strchr(acceptdtmf, f->subclass.integer)) {
					ast_verb(3, "User ended message by pressing %c\n", f->subclass.integer);
					res = f->subclass.integer;
					outmsg = 2;
					break;
				}
				if (strchr(canceldtmf, f->subclass.integer)) {
					ast_verb(3, "User canceled message by pressing %c\n", f->subclass.integer);
					res = f->subclass.integer;
					outmsg = 0;
					break;
				}
			} else if (f->frametype == AST_FRAME_CONTROL) {
				if (f->subclass.integer == AST_CONTROL_RECORD_CANCEL) {
					ast_verb(3, "Message canceled by control\n");
					outmsg = 0; /* cancels the recording */
					res = 0;
					break;
				} else if (f->subclass.integer == AST_CONTROL_RECORD_STOP) {
					ast_verb(3, "Message ended by control\n");
					res = 0;
					break;
				} else if (f->subclass.integer == AST_CONTROL_RECORD_SUSPEND) {
					paused = !paused;
					ast_verb(3, "Message %spaused by control\n",
						paused ? "" : "un");
					if (paused) {
						pause_start = time(NULL);
					} else {
						paused_secs += time(NULL) - pause_start;
					}
				} else if (f->subclass.integer == AST_CONTROL_RECORD_MUTE) {
					muted = !muted;
					ast_verb(3, "Message %smuted by control\n",
						muted ? "" : "un");
					/* We can only silence slin frames, so
					 * set the mode, if we haven't already
					 * for sildet
					 */
					if (muted && !rfmt) {
						ast_verb(3, "Setting read format to linear mode\n");
						res = set_read_to_slin(chan, &rfmt);
						if (res < 0) {
							ast_log(LOG_WARNING, "Unable to set to linear mode, giving up\n");
							break;
						}
					}
				}
			}
			if (maxtime && !paused) {
				end = time(NULL);
				if (maxtime < (end - start - paused_secs)) {
					ast_verb(3, "Took too long, cutting it short...\n");
					res = 't';
					outmsg = 2;
					break;
				}
			}
			ast_frfree(f);
		}
		if (!f) {
			ast_verb(3, "User hung up\n");
			res = -1;
			outmsg = 1;
		} else {
			ast_frfree(f);
		}
	} else {
		ast_log(LOG_WARNING, "Error creating writestream '%s', format '%s'\n", recordfile, sfmt[x]);
	}

	if (!prepend) {
		if (silgen) {
			ast_channel_stop_silence_generator(chan, silgen);
		}
	}

	/*!\note
	 * Instead of asking how much time passed (end - start), calculate the number
	 * of seconds of audio which actually went into the file.  This fixes a
	 * problem where audio is stopped up on the network and never gets to us.
	 *
	 * Note that we still want to use the number of seconds passed for the max
	 * message, otherwise we could get a situation where this stream is never
	 * closed (which would create a resource leak).
	 */
	*duration = others[0] ? ast_tellstream(others[0]) / 8000 : 0;
	if (sound_duration) {
		*sound_duration = *duration;
	}

	if (!prepend) {
		/* Reduce duration by a total silence amount */
		if (olddspsilence <= dspsilence) {
			totalsilence += dspsilence;
		}

		if (sound_duration) {
			if (totalsilence > 0) {
				*sound_duration -= (totalsilence - 200) / 1000;
			}
			if (*sound_duration < 0) {
				*sound_duration = 0;
			}
		}

		if (dspsilence > 0) {
			*duration -= (dspsilence - 200) / 1000;
		}

		if (*duration < 0) {
			*duration = 0;
		}

		for (x = 0; x < fmtcnt; x++) {
			if (!others[x]) {
				break;
			}
			/*!\note
			 * If we ended with silence, trim all but the first 200ms of silence
			 * off the recording.  However, if we ended with '#', we don't want
			 * to trim ANY part of the recording.
			 */
			if (res > 0 && dspsilence) {
				/* rewind only the trailing silence */
				ast_stream_rewind(others[x], dspsilence - 200);
			}
			ast_truncstream(others[x]);
			ast_closestream(others[x]);
		}
	} else if (prepend && outmsg) {
		struct ast_filestream *realfiles[AST_MAX_FORMATS];
		struct ast_frame *fr;

		for (x = 0; x < fmtcnt; x++) {
			snprintf(comment, sizeof(comment), "Opening the real file %s.%s\n", recordfile, sfmt[x]);
			realfiles[x] = ast_readfile(recordfile, sfmt[x], comment, O_RDONLY, 0, 0);
			if (!others[x]) {
				break;
			}
			if (!realfiles[x]) {
				ast_closestream(others[x]);
				continue;
			}
			/*!\note Same logic as above. */
			if (dspsilence) {
				ast_stream_rewind(others[x], dspsilence - 200);
			}
			ast_truncstream(others[x]);
			/* add the original file too */
			while ((fr = ast_readframe(realfiles[x]))) {
				ast_writestream(others[x], fr);
				ast_frfree(fr);
			}
			ast_closestream(others[x]);
			ast_closestream(realfiles[x]);
			ast_filerename(prependfile, recordfile, sfmt[x]);
			ast_trace(-1, "Recording Format: sfmts=%s, prependfile %s, recordfile %s\n", sfmt[x], prependfile, recordfile);
			ast_trace(-1, "Deleting the prepend file %s.%s\n", recordfile, sfmt[x]);
			ast_filedelete(prependfile, sfmt[x]);
		}
	} else {
		for (x = 0; x < fmtcnt; x++) {
			if (!others[x]) {
				break;
			}
			ast_closestream(others[x]);
		}
	}

	if (rfmt && ast_set_read_format(chan, rfmt)) {
		ast_log(LOG_WARNING, "Unable to restore format %s to channel '%s'\n", ast_format_get_name(rfmt), ast_channel_name(chan));
	}
	ao2_cleanup(rfmt);
	if ((outmsg == 2) && (!skip_confirmation_sound)) {
		ast_stream_and_wait(chan, "auth-thankyou", "");
	}
	if (sildet) {
		ast_dsp_free(sildet);
	}
	SCOPE_EXIT_RTN_VALUE(res, "Done.  RC: %d\n", res);
}

static const char default_acceptdtmf[] = "#";
static const char default_canceldtmf[] = "";

int ast_play_and_record_full(struct ast_channel *chan, const char *playfile, const char *recordfile, int maxtime, const char *fmt, int *duration, int *sound_duration, int beep, int silencethreshold, int maxsilence, const char *path, const char *acceptdtmf, const char *canceldtmf, int skip_confirmation_sound, enum ast_record_if_exists if_exists)
{
	return __ast_play_and_record(chan, playfile, recordfile, maxtime, fmt, duration, sound_duration, beep, silencethreshold, maxsilence, path, 0, S_OR(acceptdtmf, ""), S_OR(canceldtmf, default_canceldtmf), skip_confirmation_sound, if_exists);
}

int ast_play_and_record(struct ast_channel *chan, const char *playfile, const char *recordfile, int maxtime, const char *fmt, int *duration, int *sound_duration, int silencethreshold, int maxsilence, const char *path)
{
	return __ast_play_and_record(chan, playfile, recordfile, maxtime, fmt, duration, sound_duration, 0, silencethreshold, maxsilence, path, 0, default_acceptdtmf, default_canceldtmf, 0, AST_RECORD_IF_EXISTS_OVERWRITE);
}

int ast_play_and_prepend(struct ast_channel *chan, char *playfile, char *recordfile, int maxtime, char *fmt, int *duration, int *sound_duration, int beep, int silencethreshold, int maxsilence)
{
	return __ast_play_and_record(chan, playfile, recordfile, maxtime, fmt, duration, sound_duration, beep, silencethreshold, maxsilence, NULL, 1, default_acceptdtmf, default_canceldtmf, 1, AST_RECORD_IF_EXISTS_OVERWRITE);
}

/* Channel group core functions */

int ast_app_group_split_group(const char *data, char *group, int group_max, char *category, int category_max)
{
	int res = 0;
	char tmp[256];
	char *grp = NULL, *cat = NULL;

	if (!ast_strlen_zero(data)) {
		ast_copy_string(tmp, data, sizeof(tmp));
		grp = tmp;
		if ((cat = strchr(tmp, '@'))) {
			*cat++ = '\0';
		}
	}

	if (!ast_strlen_zero(grp)) {
		ast_copy_string(group, grp, group_max);
	} else {
		*group = '\0';
	}

	if (!ast_strlen_zero(cat)) {
		ast_copy_string(category, cat, category_max);
	}

	return res;
}

int ast_app_group_set_channel(struct ast_channel *chan, const char *data)
{
	int res = 0;
	char group[80] = "", category[80] = "";
	struct ast_group_info *gi = NULL;
	size_t len = 0;

	if (ast_app_group_split_group(data, group, sizeof(group), category, sizeof(category))) {
		return -1;
	}

	/* Calculate memory we will need if this is new */
	len = sizeof(*gi) + strlen(group) + 1;
	if (!ast_strlen_zero(category)) {
		len += strlen(category) + 1;
	}

	AST_RWLIST_WRLOCK(&groups);
	AST_RWLIST_TRAVERSE_SAFE_BEGIN(&groups, gi, group_list) {
		if ((gi->chan == chan) && ((ast_strlen_zero(category) && ast_strlen_zero(gi->category)) || (!ast_strlen_zero(gi->category) && !strcasecmp(gi->category, category)))) {
			AST_RWLIST_REMOVE_CURRENT(group_list);
			ast_free(gi);
			break;
		}
	}
	AST_RWLIST_TRAVERSE_SAFE_END;

	if (ast_strlen_zero(group)) {
		/* Enable unsetting the group */
	} else if ((gi = ast_calloc(1, len))) {
		gi->chan = chan;
		gi->group = (char *) gi + sizeof(*gi);
		strcpy(gi->group, group);
		if (!ast_strlen_zero(category)) {
			gi->category = (char *) gi + sizeof(*gi) + strlen(group) + 1;
			strcpy(gi->category, category);
		}
		AST_RWLIST_INSERT_TAIL(&groups, gi, group_list);
	} else {
		res = -1;
	}

	AST_RWLIST_UNLOCK(&groups);

	return res;
}

int ast_app_group_get_count(const char *group, const char *category)
{
	struct ast_group_info *gi = NULL;
	int count = 0;

	if (ast_strlen_zero(group)) {
		return 0;
	}

	AST_RWLIST_RDLOCK(&groups);
	AST_RWLIST_TRAVERSE(&groups, gi, group_list) {
		if (!strcasecmp(gi->group, group) && (ast_strlen_zero(category) || (!ast_strlen_zero(gi->category) && !strcasecmp(gi->category, category)))) {
			count++;
		}
	}
	AST_RWLIST_UNLOCK(&groups);

	return count;
}

int ast_app_group_match_get_count(const char *groupmatch, const char *category)
{
	struct ast_group_info *gi = NULL;
	regex_t regexbuf_group;
	regex_t regexbuf_category;
	int count = 0;

	if (ast_strlen_zero(groupmatch)) {
		ast_log(LOG_NOTICE, "groupmatch empty\n");
		return 0;
	}

	/* if regex compilation fails, return zero matches */
	if (regcomp(&regexbuf_group, groupmatch, REG_EXTENDED | REG_NOSUB)) {
		ast_log(LOG_ERROR, "Regex compile failed on: %s\n", groupmatch);
		return 0;
	}

	if (!ast_strlen_zero(category) && regcomp(&regexbuf_category, category, REG_EXTENDED | REG_NOSUB)) {
		ast_log(LOG_ERROR, "Regex compile failed on: %s\n", category);
		regfree(&regexbuf_group);
		return 0;
	}

	AST_RWLIST_RDLOCK(&groups);
	AST_RWLIST_TRAVERSE(&groups, gi, group_list) {
		if (!regexec(&regexbuf_group, gi->group, 0, NULL, 0) && (ast_strlen_zero(category) || (!ast_strlen_zero(gi->category) && !regexec(&regexbuf_category, gi->category, 0, NULL, 0)))) {
			count++;
		}
	}
	AST_RWLIST_UNLOCK(&groups);

	regfree(&regexbuf_group);
	if (!ast_strlen_zero(category)) {
		regfree(&regexbuf_category);
	}

	return count;
}

int ast_app_group_update(struct ast_channel *old, struct ast_channel *new)
{
	struct ast_group_info *gi = NULL;

	AST_RWLIST_WRLOCK(&groups);
	AST_RWLIST_TRAVERSE_SAFE_BEGIN(&groups, gi, group_list) {
		if (gi->chan == old) {
			gi->chan = new;
		} else if (gi->chan == new) {
			AST_RWLIST_REMOVE_CURRENT(group_list);
			ast_free(gi);
		}
	}
	AST_RWLIST_TRAVERSE_SAFE_END;
	AST_RWLIST_UNLOCK(&groups);

	return 0;
}

int ast_app_group_discard(struct ast_channel *chan)
{
	struct ast_group_info *gi = NULL;

	AST_RWLIST_WRLOCK(&groups);
	AST_RWLIST_TRAVERSE_SAFE_BEGIN(&groups, gi, group_list) {
		if (gi->chan == chan) {
			AST_RWLIST_REMOVE_CURRENT(group_list);
			ast_free(gi);
		}
	}
	AST_RWLIST_TRAVERSE_SAFE_END;
	AST_RWLIST_UNLOCK(&groups);

	return 0;
}

int ast_app_group_list_wrlock(void)
{
	return AST_RWLIST_WRLOCK(&groups);
}

int ast_app_group_list_rdlock(void)
{
	return AST_RWLIST_RDLOCK(&groups);
}

struct ast_group_info *ast_app_group_list_head(void)
{
	return AST_RWLIST_FIRST(&groups);
}

int ast_app_group_list_unlock(void)
{
	return AST_RWLIST_UNLOCK(&groups);
}

unsigned int __ast_app_separate_args(char *buf, char delim, int remove_chars, char **array, int arraylen)
{
	int argc;
	char *scan, *wasdelim = NULL;
	int paren = 0, quote = 0, bracket = 0;

	if (!array || !arraylen) {
		return 0;
	}

	memset(array, 0, arraylen * sizeof(*array));

	if (!buf) {
		return 0;
	}

	scan = buf;

	for (argc = 0; *scan && (argc < arraylen - 1); argc++) {
		array[argc] = scan;
		for (; *scan; scan++) {
			if (*scan == '(') {
				paren++;
			} else if (*scan == ')') {
				if (paren) {
					paren--;
				}
			} else if (*scan == '[') {
				bracket++;
			} else if (*scan == ']') {
				if (bracket) {
					bracket--;
				}
			} else if (*scan == '"' && delim != '"') {
				quote = quote ? 0 : 1;
				if (remove_chars) {
					/* Remove quote character from argument */
					memmove(scan, scan + 1, strlen(scan));
					scan--;
				}
			} else if (*scan == '\\') {
				if (remove_chars) {
					/* Literal character, don't parse */
					memmove(scan, scan + 1, strlen(scan));
				} else {
					scan++;
				}
			} else if ((*scan == delim) && !paren && !quote && !bracket) {
				wasdelim = scan;
				*scan++ = '\0';
				break;
			}
		}
	}

	/* If the last character in the original string was the delimiter, then
	 * there is one additional argument. */
	if (*scan || (scan > buf && (scan - 1) == wasdelim)) {
		array[argc++] = scan;
	}

	return argc;
}

static enum AST_LOCK_RESULT ast_lock_path_lockfile(const char *path)
{
	char *s;
	char *fs;
	int res;
	int fd;
	int lp = strlen(path);
	time_t start;

	s = ast_alloca(lp + 10);
	fs = ast_alloca(lp + 20);

	snprintf(fs, strlen(path) + 19, "%s/.lock-%08lx", path, (unsigned long)ast_random());
	fd = open(fs, O_WRONLY | O_CREAT | O_EXCL, AST_FILE_MODE);
	if (fd < 0) {
		ast_log(LOG_ERROR, "Unable to create lock file '%s': %s\n", path, strerror(errno));
		return AST_LOCK_PATH_NOT_FOUND;
	}
	close(fd);

	snprintf(s, strlen(path) + 9, "%s/.lock", path);
	start = time(NULL);
	while (((res = link(fs, s)) < 0) && (errno == EEXIST) && (time(NULL) - start < 5)) {
		sched_yield();
	}

	unlink(fs);

	if (res) {
		ast_log(LOG_WARNING, "Failed to lock path '%s': %s\n", path, strerror(errno));
		return AST_LOCK_TIMEOUT;
	} else {
		ast_debug(1, "Locked path '%s'\n", path);
		return AST_LOCK_SUCCESS;
	}
}

static int ast_unlock_path_lockfile(const char *path)
{
	char *s;
	int res;

	s = ast_alloca(strlen(path) + 10);

	snprintf(s, strlen(path) + 9, "%s/%s", path, ".lock");

	if ((res = unlink(s))) {
		ast_log(LOG_ERROR, "Could not unlock path '%s': %s\n", path, strerror(errno));
	} else {
		ast_debug(1, "Unlocked path '%s'\n", path);
	}

	return res;
}

struct path_lock {
	AST_LIST_ENTRY(path_lock) le;
	int fd;
	char *path;
};

static AST_LIST_HEAD_STATIC(path_lock_list, path_lock);

static void path_lock_destroy(struct path_lock *obj)
{
	if (obj->fd >= 0) {
		close(obj->fd);
	}
	if (obj->path) {
		ast_free(obj->path);
	}
	ast_free(obj);
}

static enum AST_LOCK_RESULT ast_lock_path_flock(const char *path)
{
	char *fs;
	int res;
	int fd;
	time_t start;
	struct path_lock *pl;
	struct stat st, ost;

	fs = ast_alloca(strlen(path) + 20);

	snprintf(fs, strlen(path) + 19, "%s/lock", path);
	if (lstat(fs, &st) == 0) {
		if ((st.st_mode & S_IFMT) == S_IFLNK) {
			ast_log(LOG_WARNING, "Unable to create lock file "
					"'%s': it's already a symbolic link\n",
					fs);
			return AST_LOCK_FAILURE;
		}
		if (st.st_nlink > 1) {
			ast_log(LOG_WARNING, "Unable to create lock file "
					"'%s': %u hard links exist\n",
					fs, (unsigned int) st.st_nlink);
			return AST_LOCK_FAILURE;
		}
	}
	if ((fd = open(fs, O_WRONLY | O_CREAT, 0600)) < 0) {
		ast_log(LOG_WARNING, "Unable to create lock file '%s': %s\n",
				fs, strerror(errno));
		return AST_LOCK_PATH_NOT_FOUND;
	}
	if (!(pl = ast_calloc(1, sizeof(*pl)))) {
		/* We don't unlink the lock file here, on the possibility that
		 * someone else created it - better to leave a little mess
		 * than create a big one by destroying someone else's lock
		 * and causing something to be corrupted.
		 */
		close(fd);
		return AST_LOCK_FAILURE;
	}
	pl->fd = fd;
	pl->path = ast_strdup(path);

	time(&start);
	while (
		#ifdef SOLARIS
		((res = fcntl(pl->fd, F_SETLK, fcntl(pl->fd, F_GETFL) | O_NONBLOCK)) < 0) &&
		#else
		((res = flock(pl->fd, LOCK_EX | LOCK_NB)) < 0) &&
		#endif
			(errno == EWOULDBLOCK) &&
			(time(NULL) - start < 5))
		usleep(1000);
	if (res) {
		ast_log(LOG_WARNING, "Failed to lock path '%s': %s\n",
				path, strerror(errno));
		/* No unlinking of lock done, since we tried and failed to
		 * flock() it.
		 */
		path_lock_destroy(pl);
		return AST_LOCK_TIMEOUT;
	}

	/* Check for the race where the file is recreated or deleted out from
	 * underneath us.
	 */
	if (lstat(fs, &st) != 0 && fstat(pl->fd, &ost) != 0 &&
			st.st_dev != ost.st_dev &&
			st.st_ino != ost.st_ino) {
		ast_log(LOG_WARNING, "Unable to create lock file '%s': "
				"file changed underneath us\n", fs);
		path_lock_destroy(pl);
		return AST_LOCK_FAILURE;
	}

	/* Success: file created, flocked, and is the one we started with */
	AST_LIST_LOCK(&path_lock_list);
	AST_LIST_INSERT_TAIL(&path_lock_list, pl, le);
	AST_LIST_UNLOCK(&path_lock_list);

	ast_debug(1, "Locked path '%s'\n", path);

	return AST_LOCK_SUCCESS;
}

static int ast_unlock_path_flock(const char *path)
{
	char *s;
	struct path_lock *p;

	s = ast_alloca(strlen(path) + 20);

	AST_LIST_LOCK(&path_lock_list);
	AST_LIST_TRAVERSE_SAFE_BEGIN(&path_lock_list, p, le) {
		if (!strcmp(p->path, path)) {
			AST_LIST_REMOVE_CURRENT(le);
			break;
		}
	}
	AST_LIST_TRAVERSE_SAFE_END;
	AST_LIST_UNLOCK(&path_lock_list);

	if (p) {
		snprintf(s, strlen(path) + 19, "%s/lock", path);
		unlink(s);
		path_lock_destroy(p);
		ast_debug(1, "Unlocked path '%s'\n", path);
	} else {
		ast_debug(1, "Failed to unlock path '%s': "
				"lock not found\n", path);
	}

	return 0;
}

void ast_set_lock_type(enum AST_LOCK_TYPE type)
{
	ast_lock_type = type;
}

enum AST_LOCK_RESULT ast_lock_path(const char *path)
{
	enum AST_LOCK_RESULT r = AST_LOCK_FAILURE;

	switch (ast_lock_type) {
	case AST_LOCK_TYPE_LOCKFILE:
		r = ast_lock_path_lockfile(path);
		break;
	case AST_LOCK_TYPE_FLOCK:
		r = ast_lock_path_flock(path);
		break;
	}

	return r;
}

int ast_unlock_path(const char *path)
{
	int r = 0;

	switch (ast_lock_type) {
	case AST_LOCK_TYPE_LOCKFILE:
		r = ast_unlock_path_lockfile(path);
		break;
	case AST_LOCK_TYPE_FLOCK:
		r = ast_unlock_path_flock(path);
		break;
	}

	return r;
}

int ast_record_review(struct ast_channel *chan, const char *playfile, const char *recordfile, int maxtime, const char *fmt, int *duration, const char *path)
{
	int silencethreshold;
	int maxsilence = 0;
	int res = 0;
	int cmd = 0;
	int max_attempts = 3;
	int attempts = 0;
	int recorded = 0;
	int message_exists = 0;
	/* Note that urgent and private are for flagging messages as such in the future */

	/* barf if no pointer passed to store duration in */
	if (!duration) {
		ast_log(LOG_WARNING, "Error ast_record_review called without duration pointer\n");
		return -1;
	}

	cmd = '3';	 /* Want to start by recording */

	silencethreshold = ast_dsp_get_threshold_from_settings(THRESHOLD_SILENCE);

	while ((cmd >= 0) && (cmd != 't')) {
		switch (cmd) {
		case '1':
			if (!message_exists) {
				/* In this case, 1 is to record a message */
				cmd = '3';
				break;
			} else {
				ast_stream_and_wait(chan, "vm-msgsaved", "");
				cmd = 't';
				return res;
			}
		case '2':
			/* Review */
			ast_verb(3, "Reviewing the recording\n");
			cmd = ast_stream_and_wait(chan, recordfile, AST_DIGIT_ANY);
			break;
		case '3':
			message_exists = 0;
			/* Record */
			ast_verb(3, "R%secording\n", recorded == 1 ? "e-r" : "");
			recorded = 1;
			if ((cmd = ast_play_and_record(chan, playfile, recordfile, maxtime, fmt, duration, NULL, silencethreshold, maxsilence, path)) == -1) {
				/* User has hung up, no options to give */
				return cmd;
			}
			if (cmd == '0') {
				break;
			} else if (cmd == '*') {
				break;
			} else {
				/* If all is well, a message exists */
				message_exists = 1;
				cmd = 0;
			}
			break;
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9':
		case '*':
		case '#':
			cmd = ast_play_and_wait(chan, "vm-sorry");
			break;
		default:
			if (message_exists) {
				cmd = ast_play_and_wait(chan, "vm-review");
			} else {
				if (!(cmd = ast_play_and_wait(chan, "vm-torerecord"))) {
					cmd = ast_waitfordigit(chan, 600);
				}
			}

			if (!cmd) {
				cmd = ast_waitfordigit(chan, 6000);
			}
			if (!cmd) {
				attempts++;
			}
			if (attempts > max_attempts) {
				cmd = 't';
			}
		}
	}
	if (cmd == 't') {
		cmd = 0;
	}
	return cmd;
}

#define RES_UPONE (1 << 16)
#define RES_EXIT  (1 << 17)
#define RES_REPEAT (1 << 18)
#define RES_RESTART ((1 << 19) | RES_REPEAT)

static int ast_ivr_menu_run_internal(struct ast_channel *chan, struct ast_ivr_menu *menu, void *cbdata);

static int ivr_dispatch(struct ast_channel *chan, struct ast_ivr_option *option, char *exten, void *cbdata)
{
	int res;
	int (*ivr_func)(struct ast_channel *, void *);
	char *c;
	char *n;

	switch (option->action) {
	case AST_ACTION_UPONE:
		return RES_UPONE;
	case AST_ACTION_EXIT:
		return RES_EXIT | (((unsigned long)(option->adata)) & 0xffff);
	case AST_ACTION_REPEAT:
		return RES_REPEAT | (((unsigned long)(option->adata)) & 0xffff);
	case AST_ACTION_RESTART:
		return RES_RESTART ;
	case AST_ACTION_NOOP:
		return 0;
	case AST_ACTION_BACKGROUND:
		res = ast_stream_and_wait(chan, (char *)option->adata, AST_DIGIT_ANY);
		if (res < 0) {
			ast_log(LOG_NOTICE, "Unable to find file '%s'!\n", (char *)option->adata);
			res = 0;
		}
		return res;
	case AST_ACTION_PLAYBACK:
		res = ast_stream_and_wait(chan, (char *)option->adata, "");
		if (res < 0) {
			ast_log(LOG_NOTICE, "Unable to find file '%s'!\n", (char *)option->adata);
			res = 0;
		}
		return res;
	case AST_ACTION_MENU:
		if ((res = ast_ivr_menu_run_internal(chan, (struct ast_ivr_menu *)option->adata, cbdata)) == -2) {
			/* Do not pass entry errors back up, treat as though it was an "UPONE" */
			res = 0;
		}
		return res;
	case AST_ACTION_WAITOPTION:
		if (!(res = ast_waitfordigit(chan, ast_channel_pbx(chan) ? ast_channel_pbx(chan)->rtimeoutms : 10000))) {
			return 't';
		}
		return res;
	case AST_ACTION_CALLBACK:
		ivr_func = option->adata;
		res = ivr_func(chan, cbdata);
		return res;
	case AST_ACTION_TRANSFER:
		res = ast_parseable_goto(chan, option->adata);
		return 0;
	case AST_ACTION_PLAYLIST:
	case AST_ACTION_BACKLIST:
		res = 0;
		c = ast_strdupa(option->adata);
		while ((n = strsep(&c, ";"))) {
			if ((res = ast_stream_and_wait(chan, n,
					(option->action == AST_ACTION_BACKLIST) ? AST_DIGIT_ANY : ""))) {
				break;
			}
		}
		ast_stopstream(chan);
		return res;
	default:
		ast_log(LOG_NOTICE, "Unknown dispatch function %u, ignoring!\n", option->action);
		return 0;
	}
	return -1;
}

static int option_exists(struct ast_ivr_menu *menu, char *option)
{
	int x;
	for (x = 0; menu->options[x].option; x++) {
		if (!strcasecmp(menu->options[x].option, option)) {
			return x;
		}
	}
	return -1;
}

static int option_matchmore(struct ast_ivr_menu *menu, char *option)
{
	int x;
	for (x = 0; menu->options[x].option; x++) {
		if ((!strncasecmp(menu->options[x].option, option, strlen(option))) &&
				(menu->options[x].option[strlen(option)])) {
			return x;
		}
	}
	return -1;
}

static int read_newoption(struct ast_channel *chan, struct ast_ivr_menu *menu, char *exten, int maxexten)
{
	int res = 0;
	int ms;
	while (option_matchmore(menu, exten)) {
		ms = ast_channel_pbx(chan) ? ast_channel_pbx(chan)->dtimeoutms : 5000;
		if (strlen(exten) >= maxexten - 1) {
			break;
		}
		if ((res = ast_waitfordigit(chan, ms)) < 1) {
			break;
		}
		exten[strlen(exten) + 1] = '\0';
		exten[strlen(exten)] = res;
	}
	return res > 0 ? 0 : res;
}

static int ast_ivr_menu_run_internal(struct ast_channel *chan, struct ast_ivr_menu *menu, void *cbdata)
{
	/* Execute an IVR menu structure */
	int res = 0;
	int pos = 0;
	int retries = 0;
	char exten[AST_MAX_EXTENSION] = "s";
	if (option_exists(menu, "s") < 0) {
		strcpy(exten, "g");
		if (option_exists(menu, "g") < 0) {
			ast_log(LOG_WARNING, "No 's' nor 'g' extension in menu '%s'!\n", menu->title);
			return -1;
		}
	}
	while (!res) {
		while (menu->options[pos].option) {
			if (!strcasecmp(menu->options[pos].option, exten)) {
				res = ivr_dispatch(chan, menu->options + pos, exten, cbdata);
				ast_debug(1, "IVR Dispatch of '%s' (pos %d) yields %d\n", exten, pos, res);
				if (res < 0) {
					break;
				} else if (res & RES_UPONE) {
					return 0;
				} else if (res & RES_EXIT) {
					return res;
				} else if (res & RES_REPEAT) {
					int maxretries = res & 0xffff;
					if ((res & RES_RESTART) == RES_RESTART) {
						retries = 0;
					} else {
						retries++;
					}
					if (!maxretries) {
						maxretries = 3;
					}
					if ((maxretries > 0) && (retries >= maxretries)) {
						ast_debug(1, "Max retries %d exceeded\n", maxretries);
						return -2;
					} else {
						if (option_exists(menu, "g") > -1) {
							strcpy(exten, "g");
						} else if (option_exists(menu, "s") > -1) {
							strcpy(exten, "s");
						}
					}
					pos = 0;
					continue;
				} else if (res && strchr(AST_DIGIT_ANY, res)) {
					ast_debug(1, "Got start of extension, %c\n", res);
					exten[1] = '\0';
					exten[0] = res;
					if ((res = read_newoption(chan, menu, exten, sizeof(exten)))) {
						break;
					}
					if (option_exists(menu, exten) < 0) {
						if (option_exists(menu, "i")) {
							ast_debug(1, "Invalid extension entered, going to 'i'!\n");
							strcpy(exten, "i");
							pos = 0;
							continue;
						} else {
							ast_debug(1, "Aborting on invalid entry, with no 'i' option!\n");
							res = -2;
							break;
						}
					} else {
						ast_debug(1, "New existing extension: %s\n", exten);
						pos = 0;
						continue;
					}
				}
			}
			pos++;
		}
		ast_debug(1, "Stopping option '%s', res is %d\n", exten, res);
		pos = 0;
		if (!strcasecmp(exten, "s")) {
			strcpy(exten, "g");
		} else {
			break;
		}
	}
	return res;
}

int ast_ivr_menu_run(struct ast_channel *chan, struct ast_ivr_menu *menu, void *cbdata)
{
	int res = ast_ivr_menu_run_internal(chan, menu, cbdata);
	/* Hide internal coding */
	return res > 0 ? 0 : res;
}

char *ast_read_textfile(const char *filename)
{
	int fd, count = 0, res;
	char *output = NULL;
	struct stat filesize;

	if (stat(filename, &filesize) == -1) {
		ast_log(LOG_WARNING, "Error can't stat %s\n", filename);
		return NULL;
	}

	count = filesize.st_size + 1;

	if ((fd = open(filename, O_RDONLY)) < 0) {
		ast_log(LOG_WARNING, "Cannot open file '%s' for reading: %s\n", filename, strerror(errno));
		return NULL;
	}

	if ((output = ast_malloc(count))) {
		res = read(fd, output, count - 1);
		if (res == count - 1) {
			output[res] = '\0';
		} else {
			ast_log(LOG_WARNING, "Short read of %s (%d of %d): %s\n", filename, res, count - 1, strerror(errno));
			ast_free(output);
			output = NULL;
		}
	}

	close(fd);

	return output;
}

static int parse_options(const struct ast_app_option *options, void *_flags, char **args, char *optstr, int flaglen)
{
	char *s, *arg;
	int curarg, res = 0;
	unsigned int argloc;
	struct ast_flags *flags = _flags;
	struct ast_flags64 *flags64 = _flags;

	if (flaglen == 32) {
		ast_clear_flag(flags, AST_FLAGS_ALL);
	} else {
		flags64->flags = 0;
	}

	if (!optstr) {
		return 0;
	}

	s = optstr;
	while (*s) {
		curarg = *s++ & 0x7f;	/* the array (in app.h) has 128 entries */
		argloc = options[curarg].arg_index;
		if (*s == '(') {
			int paren = 1, quote = 0;
			int parsequotes = (s[1] == '"') ? 1 : 0;

			/* Has argument */
			arg = ++s;
			for (; *s; s++) {
				if (*s == '(' && !quote) {
					paren++;
				} else if (*s == ')' && !quote) {
					/* Count parentheses, unless they're within quotes (or backslashed, below) */
					paren--;
				} else if (*s == '"' && parsequotes) {
					/* Leave embedded quotes alone, unless they are the first character */
					quote = quote ? 0 : 1;
					ast_copy_string(s, s + 1, INT_MAX);
					s--;
				} else if (*s == '\\') {
					if (!quote) {
						/* If a backslash is found outside of quotes, remove it */
						ast_copy_string(s, s + 1, INT_MAX);
					} else if (quote && s[1] == '"') {
						/* Backslash for a quote character within quotes, remove the backslash */
						ast_copy_string(s, s + 1, INT_MAX);
					} else {
						/* Backslash within quotes, keep both characters */
						s++;
					}
				}

				if (paren == 0) {
					break;
				}
			}
			/* This will find the closing paren we found above, or none, if the string ended before we found one. */
			if ((s = strchr(s, ')'))) {
				if (argloc) {
					args[argloc - 1] = arg;
				}
				*s++ = '\0';
			} else {
				ast_log(LOG_WARNING, "Missing closing parenthesis for argument '%c' in string '%s'\n", curarg, arg);
				res = -1;
				break;
			}
		} else if (argloc) {
			args[argloc - 1] = "";
		}
		if (!options[curarg].flag) {
			ast_log(LOG_WARNING, "Unrecognized option: '%c'\n", curarg);
		}
		if (flaglen == 32) {
			ast_set_flag(flags, options[curarg].flag);
		} else {
			ast_set_flag64(flags64, options[curarg].flag);
		}
	}

	return res;
}

int ast_app_parse_options(const struct ast_app_option *options, struct ast_flags *flags, char **args, char *optstr)
{
	return parse_options(options, flags, args, optstr, 32);
}

int ast_app_parse_options64(const struct ast_app_option *options, struct ast_flags64 *flags, char **args, char *optstr)
{
	return parse_options(options, flags, args, optstr, 64);
}

void ast_app_options2str64(const struct ast_app_option *options, struct ast_flags64 *flags, char *buf, size_t len)
{
	unsigned int i, found = 0;
	for (i = 32; i < 128 && found < len; i++) {
		if (ast_test_flag64(flags, options[i].flag)) {
			buf[found++] = i;
		}
	}
	buf[found] = '\0';
}

int ast_get_encoded_char(const char *stream, char *result, size_t *consumed)
{
	int i;
	*consumed = 1;
	*result = 0;
	if (ast_strlen_zero(stream)) {
		*consumed = 0;
		return -1;
	}

	if (*stream == '\\') {
		*consumed = 2;
		switch (*(stream + 1)) {
		case 'n':
			*result = '\n';
			break;
		case 'r':
			*result = '\r';
			break;
		case 't':
			*result = '\t';
			break;
		case 'x':
			/* Hexadecimal */
			if (strchr("0123456789ABCDEFabcdef", *(stream + 2)) && *(stream + 2) != '\0') {
				*consumed = 3;
				if (*(stream + 2) <= '9') {
					*result = *(stream + 2) - '0';
				} else if (*(stream + 2) <= 'F') {
					*result = *(stream + 2) - 'A' + 10;
				} else {
					*result = *(stream + 2) - 'a' + 10;
				}
			} else {
				ast_log(LOG_ERROR, "Illegal character '%c' in hexadecimal string\n", *(stream + 2));
				return -1;
			}

			if (strchr("0123456789ABCDEFabcdef", *(stream + 3)) && *(stream + 3) != '\0') {
				*consumed = 4;
				*result <<= 4;
				if (*(stream + 3) <= '9') {
					*result += *(stream + 3) - '0';
				} else if (*(stream + 3) <= 'F') {
					*result += *(stream + 3) - 'A' + 10;
				} else {
					*result += *(stream + 3) - 'a' + 10;
				}
			}
			break;
		case '0':
			/* Octal */
			*consumed = 2;
			for (i = 2; ; i++) {
				if (strchr("01234567", *(stream + i)) && *(stream + i) != '\0') {
					(*consumed)++;
					ast_debug(5, "result was %d, ", *result);
					*result <<= 3;
					*result += *(stream + i) - '0';
					ast_debug(5, "is now %d\n", *result);
				} else {
					break;
				}
			}
			break;
		default:
			*result = *(stream + 1);
		}
	} else {
		*result = *stream;
		*consumed = 1;
	}
	return 0;
}

char *ast_get_encoded_str(const char *stream, char *result, size_t result_size)
{
	char *cur = result;
	size_t consumed;

	while (cur < result + result_size - 1 && !ast_get_encoded_char(stream, cur, &consumed)) {
		cur++;
		stream += consumed;
	}
	*cur = '\0';
	return result;
}

int ast_str_get_encoded_str(struct ast_str **str, int maxlen, const char *stream)
{
	char next, *buf;
	size_t offset = 0;
	size_t consumed;

	if (strchr(stream, '\\')) {
		while (!ast_get_encoded_char(stream, &next, &consumed)) {
			if (offset + 2 > ast_str_size(*str) && maxlen > -1) {
				ast_str_make_space(str, maxlen > 0 ? maxlen : (ast_str_size(*str) + 48) * 2 - 48);
			}
			if (offset + 2 > ast_str_size(*str)) {
				break;
			}
			buf = ast_str_buffer(*str);
			buf[offset++] = next;
			stream += consumed;
		}
		buf = ast_str_buffer(*str);
		buf[offset++] = '\0';
		ast_str_update(*str);
	} else {
		ast_str_set(str, maxlen, "%s", stream);
	}
	return 0;
}

void ast_close_fds_above_n(int n)
{
	closefrom(n + 1);
}

int ast_safe_fork(int stop_reaper)
{
	sigset_t signal_set, old_set;
	int pid;

	/* Don't let the default signal handler for children reap our status */
	if (stop_reaper) {
		ast_replace_sigchld();
	}

	/* GCC 4.9 gives a bogus "right-hand operand of comma expression has
	 * no effect" warning */
	(void) sigfillset(&signal_set);
	pthread_sigmask(SIG_BLOCK, &signal_set, &old_set);

	pid = fork();

	if (pid != 0) {
		/* Fork failed or parent */
		pthread_sigmask(SIG_SETMASK, &old_set, NULL);
		if (!stop_reaper && pid > 0) {
			struct zombie *cur = ast_calloc(1, sizeof(*cur));
			if (cur) {
				cur->pid = pid;
				AST_LIST_LOCK(&zombies);
				AST_LIST_INSERT_TAIL(&zombies, cur, list);
				AST_LIST_UNLOCK(&zombies);
				if (shaun_of_the_dead_thread == AST_PTHREADT_NULL) {
					if (ast_pthread_create_background(&shaun_of_the_dead_thread, NULL, shaun_of_the_dead, NULL)) {
						ast_log(LOG_ERROR, "Shaun of the Dead wants to kill zombies, but can't?!!\n");
						shaun_of_the_dead_thread = AST_PTHREADT_NULL;
					}
				}
			}
		}
		return pid;
	} else {
		/* Child */
#ifdef HAVE_CAP
		cap_set_proc(child_cap);
#endif

		/* Before we unblock our signals, return our trapped signals back to the defaults */
		signal(SIGHUP, SIG_DFL);
		signal(SIGCHLD, SIG_DFL);
		signal(SIGINT, SIG_DFL);
		signal(SIGURG, SIG_DFL);
		signal(SIGTERM, SIG_DFL);
		signal(SIGPIPE, SIG_DFL);
		signal(SIGXFSZ, SIG_DFL);

		/* unblock important signal handlers */
		if (pthread_sigmask(SIG_UNBLOCK, &signal_set, NULL)) {
			ast_log(LOG_WARNING, "unable to unblock signals: %s\n", strerror(errno));
			_exit(1);
		}

		return pid;
	}
}

void ast_safe_fork_cleanup(void)
{
	ast_unreplace_sigchld();
}

int ast_app_parse_timelen(const char *timestr, int *result, enum ast_timelen unit)
{
	int res;
	char u[10];
#ifdef HAVE_LONG_DOUBLE_WIDER
	long double amount;
	#define FMT "%30Lf%9s"
#else
	double amount;
	#define FMT "%30lf%9s"
#endif
	if (!timestr) {
		return -1;
	}

	res = sscanf(timestr, FMT, &amount, u);

	if (res == 0 || res == EOF) {
#undef FMT
		return -1;
	} else if (res == 2) {
		switch (u[0]) {
		case 'h':
		case 'H':
			unit = TIMELEN_HOURS;
			if (u[1] != '\0') {
				return -1;
			}
			break;
		case 's':
		case 'S':
			unit = TIMELEN_SECONDS;
			if (u[1] != '\0') {
				return -1;
			}
			break;
		case 'm':
		case 'M':
			if (toupper(u[1]) == 'S') {
				unit = TIMELEN_MILLISECONDS;
				if (u[2] != '\0') {
					return -1;
				}
			} else if (u[1] == '\0') {
				unit = TIMELEN_MINUTES;
			} else {
				return -1;
			}
			break;
		default:
			return -1;
		}
	}

	switch (unit) {
	case TIMELEN_HOURS:
		amount *= 60;
		/* fall-through */
	case TIMELEN_MINUTES:
		amount *= 60;
		/* fall-through */
	case TIMELEN_SECONDS:
		amount *= 1000;
		/* fall-through */
	case TIMELEN_MILLISECONDS:
		;
	}
	*result = amount > INT_MAX ? INT_MAX : (int) amount;
	return 0;
}

struct stasis_topic *ast_queue_topic_all(void)
{
	return queue_topic_all;
}

struct stasis_topic *ast_queue_topic(const char *queuename)
{
	return stasis_topic_pool_get_topic(queue_topic_pool, queuename);
}

static void app_cleanup(void)
{
#ifdef HAS_CAP
	cap_free(child_cap);
#endif
	ao2_cleanup(queue_topic_pool);
	queue_topic_pool = NULL;
	ao2_cleanup(queue_topic_all);
	queue_topic_all = NULL;
}

int app_init(void)
{
	ast_register_cleanup(app_cleanup);
#ifdef HAVE_CAP
	child_cap = cap_from_text("cap_net_admin-eip");
#endif
	queue_topic_all = stasis_topic_create("queue:all");
	if (!queue_topic_all) {
		return -1;
	}
	queue_topic_pool = stasis_topic_pool_create(queue_topic_all);
	if (!queue_topic_pool) {
		return -1;
	}
	return 0;
}
