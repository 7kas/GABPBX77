/*
 * GABpbx -- An open source telephony toolkit.
 *
 * Copyright (C) 2009 - 2014, Digium, Inc.
 *
 * Joshua Colp <jcolp@digium.com>
 * Andreas 'MacBrody' Brodmann <andreas.brodmann@gmail.com>
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
 * \author Joshua Colp <jcolp@digium.com>
 * \author Andreas 'MacBrody' Brodmann <andreas.brodmann@gmail.com>
 *
 * \brief RTP (Multicast and Unicast) Media Channel
 *
 * \ingroup channel_drivers
 */

/*** MODULEINFO
	<depend>res_rtp_multicast</depend>
	<support_level>core</support_level>
 ***/

#include "gabpbx.h"

#include "gabpbx/channel.h"
#include "gabpbx/module.h"
#include "gabpbx/pbx.h"
#include "gabpbx/acl.h"
#include "gabpbx/app.h"
#include "gabpbx/rtp_engine.h"
#include "gabpbx/causes.h"
#include "gabpbx/format_cache.h"
#include "gabpbx/multicast_rtp.h"
#include "gabpbx/dns_core.h"

/* Forward declarations */
static struct ast_channel *multicast_rtp_request(const char *type, struct ast_format_cap *cap, const struct ast_assigned_ids *assignedids, const struct ast_channel *requestor, const char *data, int *cause);
static struct ast_channel *unicast_rtp_request(const char *type, struct ast_format_cap *cap, const struct ast_assigned_ids *assignedids, const struct ast_channel *requestor, const char *data, int *cause);
static int rtp_call(struct ast_channel *ast, const char *dest, int timeout);
static int rtp_hangup(struct ast_channel *ast);
static struct ast_frame *rtp_read(struct ast_channel *ast);
static int rtp_write(struct ast_channel *ast, struct ast_frame *f);

/* Multicast channel driver declaration */
static struct ast_channel_tech multicast_rtp_tech = {
	.type = "MulticastRTP",
	.description = "Multicast RTP Paging Channel Driver",
	.requester = multicast_rtp_request,
	.call = rtp_call,
	.hangup = rtp_hangup,
	.read = rtp_read,
	.write = rtp_write,
};

/* Unicast channel driver declaration */
static struct ast_channel_tech unicast_rtp_tech = {
	.type = "UnicastRTP",
	.description = "Unicast RTP Media Channel Driver",
	.requester = unicast_rtp_request,
	.call = rtp_call,
	.hangup = rtp_hangup,
	.read = rtp_read,
	.write = rtp_write,
};

/*! \brief Function called when we should read a frame from the channel */
static struct ast_frame  *rtp_read(struct ast_channel *ast)
{
	struct ast_rtp_instance *instance = ast_channel_tech_pvt(ast);
	int fdno = ast_channel_fdno(ast);

	switch (fdno) {
	case 0:
		return ast_rtp_instance_read(instance, 0);
	default:
		return &ast_null_frame;
	}
}

/*! \brief Function called when we should write a frame to the channel */
static int rtp_write(struct ast_channel *ast, struct ast_frame *f)
{
	struct ast_rtp_instance *instance = ast_channel_tech_pvt(ast);

	return ast_rtp_instance_write(instance, f);
}

/*! \brief Function called when we should actually call the destination */
static int rtp_call(struct ast_channel *ast, const char *dest, int timeout)
{
	struct ast_rtp_instance *instance = ast_channel_tech_pvt(ast);

	ast_queue_control(ast, AST_CONTROL_ANSWER);

	return ast_rtp_instance_activate(instance);
}

/*! \brief Function called when we should hang the channel up */
static int rtp_hangup(struct ast_channel *ast)
{
	struct ast_rtp_instance *instance = ast_channel_tech_pvt(ast);

	ast_rtp_instance_destroy(instance);

	ast_channel_tech_pvt_set(ast, NULL);

	return 0;
}

static struct ast_format *derive_format_from_cap(struct ast_format_cap *cap)
{
	struct ast_format *fmt = ast_format_cap_get_format(cap, 0);

	if (ast_format_cap_count(cap) == 1 && fmt == ast_format_slin) {
		/*
		 * Because we have no SDP, we must use one of the static RTP payload
		 * assignments. Signed linear @ 8kHz does not map, so if that is our
		 * only capability, we force μ-law instead.
		 */
		ao2_ref(fmt, -1);
		fmt = ao2_bump(ast_format_ulaw);
	}

	return fmt;
}

/*! \brief Function called when we should prepare to call the multicast destination */
static struct ast_channel *multicast_rtp_request(const char *type, struct ast_format_cap *cap, const struct ast_assigned_ids *assignedids, const struct ast_channel *requestor, const char *data, int *cause)
{
	char *parse;
	struct ast_rtp_instance *instance;
	struct ast_sockaddr control_address;
	struct ast_sockaddr destination_address;
	struct ast_channel *chan;
	struct ast_format_cap *caps = NULL;
	struct ast_format *fmt = NULL;
	AST_DECLARE_APP_ARGS(args,
		AST_APP_ARG(type);
		AST_APP_ARG(destination);
		AST_APP_ARG(control);
		AST_APP_ARG(options);
	);
	struct ast_multicast_rtp_options *mcast_options = NULL;

	if (ast_strlen_zero(data)) {
		ast_log_chan(NULL, LOG_ERROR, "A multicast type and destination must be given to the 'MulticastRTP' channel\n");
		goto failure;
	}
	parse = ast_strdupa(data);
	AST_NONSTANDARD_APP_ARGS(args, parse, '/');

	if (ast_strlen_zero(args.type)) {
		ast_log_chan(NULL, LOG_ERROR, "Type is required for the 'MulticastRTP' channel\n");
		goto failure;
	}

	if (ast_strlen_zero(args.destination)) {
		ast_log_chan(NULL, LOG_ERROR, "Destination is required for the 'MulticastRTP' channel\n");
		goto failure;
	}
	if (!ast_sockaddr_parse(&destination_address, args.destination, PARSE_PORT_REQUIRE)) {
		ast_log_chan(NULL, LOG_ERROR, "Destination address '%s' could not be parsed\n",
			args.destination);
		goto failure;
	}

	ast_sockaddr_setnull(&control_address);
	if (!ast_strlen_zero(args.control)
		&& !ast_sockaddr_parse(&control_address, args.control, PARSE_PORT_REQUIRE)) {
		ast_log_chan(NULL, LOG_ERROR, "Control address '%s' could not be parsed\n", args.control);
		goto failure;
	}

	mcast_options = ast_multicast_rtp_create_options(args.type, args.options);
	if (!mcast_options) {
		goto failure;
	}

	fmt = ast_multicast_rtp_options_get_format(mcast_options);
	if (!fmt) {
		fmt = derive_format_from_cap(cap);
	}
	if (!fmt) {
		ast_log_chan(NULL, LOG_ERROR, "No codec available for sending RTP to '%s'\n",
			args.destination);
		goto failure;
	}

	caps = ast_format_cap_alloc(AST_FORMAT_CAP_FLAG_DEFAULT);
	if (!caps) {
		goto failure;
	}

	instance = ast_rtp_instance_new("multicast", NULL, &control_address, mcast_options);
	if (!instance) {
		ast_log_chan(NULL, LOG_ERROR,
			"Could not create '%s' multicast RTP instance for sending media to '%s'\n",
			args.type, args.destination);
		goto failure;
	}

	chan = ast_channel_alloc(1, AST_STATE_DOWN, "", "", "", "", "", assignedids,
		requestor, 0, "MulticastRTP/%s-%p", args.destination, instance);
	if (!chan) {
		ast_rtp_instance_destroy(instance);
		goto failure;
	}
	ast_rtp_instance_set_channel_id(instance, ast_channel_uniqueid(chan));
	ast_rtp_instance_set_remote_address(instance, &destination_address);

	ast_channel_tech_set(chan, &multicast_rtp_tech);

	ast_format_cap_append(caps, fmt, 0);
	ast_channel_nativeformats_set(chan, caps);
	ast_channel_set_writeformat(chan, fmt);
	ast_channel_set_rawwriteformat(chan, fmt);
	ast_channel_set_readformat(chan, fmt);
	ast_channel_set_rawreadformat(chan, fmt);

	ast_channel_tech_pvt_set(chan, instance);

	ast_channel_unlock(chan);

	ao2_ref(fmt, -1);
	ao2_ref(caps, -1);
	ast_multicast_rtp_free_options(mcast_options);

	return chan;

failure:
	ao2_cleanup(fmt);
	ao2_cleanup(caps);
	ast_multicast_rtp_free_options(mcast_options);
	*cause = AST_CAUSE_FAILURE;
	return NULL;
}

enum {
	OPT_RTP_CODEC =  (1 << 0),
	OPT_RTP_ENGINE = (1 << 1),
	OPT_RTP_GLUE = (1 << 2),
};

enum {
	OPT_ARG_RTP_CODEC,
	OPT_ARG_RTP_ENGINE,
	/* note: this entry _MUST_ be the last one in the enum */
	OPT_ARG_ARRAY_SIZE
};

AST_APP_OPTIONS(unicast_rtp_options, BEGIN_OPTIONS
	/*! Set the codec to be used for unicast RTP */
	AST_APP_OPTION_ARG('c', OPT_RTP_CODEC, OPT_ARG_RTP_CODEC),
	/*! Set the RTP engine to use for unicast RTP */
	AST_APP_OPTION_ARG('e', OPT_RTP_ENGINE, OPT_ARG_RTP_ENGINE),
	/*! Provide RTP glue for the channel */
	AST_APP_OPTION('g', OPT_RTP_GLUE),
END_OPTIONS );

static const struct ast_datastore_info chan_rtp_datastore_info = {
	.type = "CHAN_RTP_GLUE",
};

/*! \brief Function called when we should prepare to call the unicast destination */
static struct ast_channel *unicast_rtp_request(const char *type, struct ast_format_cap *cap, const struct ast_assigned_ids *assignedids, const struct ast_channel *requestor, const char *data, int *cause)
{
	char *parse;
	struct ast_rtp_instance *instance;
	struct ast_sockaddr address;
	struct ast_sockaddr local_address;
	struct ast_channel *chan;
	struct ast_format_cap *caps = NULL;
	struct ast_format *fmt = NULL;
	const char *engine_name;
	AST_DECLARE_APP_ARGS(args,
		AST_APP_ARG(destination);
		AST_APP_ARG(options);
	);
	struct ast_flags opts = { 0, };
	char *opt_args[OPT_ARG_ARRAY_SIZE];

	if (ast_strlen_zero(data)) {
		ast_log_chan(NULL, LOG_ERROR, "Destination is required for the 'UnicastRTP' channel\n");
		goto failure;
	}
	parse = ast_strdupa(data);
	AST_NONSTANDARD_APP_ARGS(args, parse, '/');

	if (ast_strlen_zero(args.destination)) {
		ast_log_chan(NULL, LOG_ERROR, "Destination is required for the 'UnicastRTP' channel\n");
		goto failure;
	}

	if (!ast_sockaddr_parse(&address, args.destination, PARSE_PORT_REQUIRE)) {
	    int rc;
	    char *host;
	    char *port;

	    rc = ast_sockaddr_split_hostport(args.destination, &host, &port, PARSE_PORT_REQUIRE);
	    if (!rc) {
	        ast_log_chan(NULL, LOG_ERROR, "Unable to parse destination '%s' into host and port\n", args.destination);
	        goto failure;
	    }

	    rc = ast_dns_resolve_ipv6_and_ipv4(&address, host, port);
	    if (rc != 0) {
	        ast_log_chan(NULL, LOG_ERROR, "Unable to resolve host '%s'\n", host);
	        goto failure;
	    }
	}

	if (!ast_strlen_zero(args.options)
		&& ast_app_parse_options(unicast_rtp_options, &opts, opt_args,
			ast_strdupa(args.options))) {
		ast_log_chan(NULL, LOG_ERROR, "'UnicastRTP' channel options '%s' parse error\n",
			args.options);
		goto failure;
	}

	if (ast_test_flag(&opts, OPT_RTP_CODEC)
		&& !ast_strlen_zero(opt_args[OPT_ARG_RTP_CODEC])) {
		fmt = ast_format_cache_get(opt_args[OPT_ARG_RTP_CODEC]);
		if (!fmt) {
			ast_log_chan(NULL, LOG_ERROR, "Codec '%s' not found for sending RTP to '%s'\n",
				opt_args[OPT_ARG_RTP_CODEC], args.destination);
			goto failure;
		}
	} else {
		fmt = derive_format_from_cap(cap);
		if (!fmt) {
			ast_log_chan(NULL, LOG_ERROR, "No codec available for sending RTP to '%s'\n",
				args.destination);
			goto failure;
		}
	}

	caps = ast_format_cap_alloc(AST_FORMAT_CAP_FLAG_DEFAULT);
	if (!caps) {
		goto failure;
	}

	engine_name = S_COR(ast_test_flag(&opts, OPT_RTP_ENGINE),
		opt_args[OPT_ARG_RTP_ENGINE], "gabpbx");

	ast_sockaddr_copy(&local_address, &address);
	if (ast_ouraddrfor(&address, &local_address)) {
		ast_log_chan(NULL, LOG_ERROR, "Could not get our address for sending media to '%s'\n",
			args.destination);
		goto failure;
	}
	instance = ast_rtp_instance_new(engine_name, NULL, &local_address, NULL);
	if (!instance) {
		ast_log_chan(NULL, LOG_ERROR,
			"Could not create %s RTP instance for sending media to '%s'\n",
			S_OR(engine_name, "default"), args.destination);
		goto failure;
	}

	chan = ast_channel_alloc(1, AST_STATE_DOWN, "", "", "", "", "", assignedids,
		requestor, 0, "UnicastRTP/%s-%p", args.destination, instance);
	if (!chan) {
		ast_rtp_instance_destroy(instance);
		goto failure;
	}
	ast_rtp_instance_set_channel_id(instance, ast_channel_uniqueid(chan));
	ast_rtp_instance_set_remote_address(instance, &address);
	ast_channel_set_fd(chan, 0, ast_rtp_instance_fd(instance, 0));

	ast_channel_tech_set(chan, &unicast_rtp_tech);

	if (ast_test_flag(&opts, OPT_RTP_GLUE)) {
		struct ast_datastore *datastore;
		if ((datastore = ast_datastore_alloc(&chan_rtp_datastore_info, NULL))) {
			ast_channel_datastore_add(chan, datastore);
		}
	}

	ast_format_cap_append(caps, fmt, 0);
	ast_channel_nativeformats_set(chan, caps);
	ast_channel_set_writeformat(chan, fmt);
	ast_channel_set_rawwriteformat(chan, fmt);
	ast_channel_set_readformat(chan, fmt);
	ast_channel_set_rawreadformat(chan, fmt);

	ast_channel_tech_pvt_set(chan, instance);

	ast_rtp_instance_get_local_address(instance, &local_address);
	pbx_builtin_setvar_helper(chan, "UNICASTRTP_LOCAL_ADDRESS",
		ast_sockaddr_stringify_addr(&local_address));
	pbx_builtin_setvar_helper(chan, "UNICASTRTP_LOCAL_PORT",
		ast_sockaddr_stringify_port(&local_address));

	ast_channel_unlock(chan);

	ao2_ref(fmt, -1);
	ao2_ref(caps, -1);

	return chan;

failure:
	ao2_cleanup(fmt);
	ao2_cleanup(caps);
	*cause = AST_CAUSE_FAILURE;
	return NULL;
}

/*! \brief Function called by RTP engine to get peer capabilities */
static void chan_rtp_get_codec(struct ast_channel *chan, struct ast_format_cap *result)
{
	SCOPE_ENTER(1, "%s Native formats %s\n", ast_channel_name(chan),
		ast_str_tmp(AST_FORMAT_CAP_NAMES_LEN, ast_format_cap_get_names(ast_channel_nativeformats(chan), &STR_TMP)));
	ast_format_cap_append_from_cap(result, ast_channel_nativeformats(chan), AST_MEDIA_TYPE_UNKNOWN);
	SCOPE_EXIT_RTN();
}

/*! \brief Function called by RTP engine to change where the remote party should send media.
 *
 * chan_rtp is not able to actually update the peer, so this function has no effect.
 * */
static int chan_rtp_set_rtp_peer(struct ast_channel *chan, struct ast_rtp_instance *rtp, struct ast_rtp_instance *vrtp, struct ast_rtp_instance *tpeer, const struct ast_format_cap *cap, int nat_active)
{
	return -1;
}

/*! \brief Function called by RTP engine to get local audio RTP peer */
static enum ast_rtp_glue_result chan_rtp_get_vrtp_peer(struct ast_channel *chan, struct ast_rtp_instance **instance)
{
	return AST_RTP_GLUE_RESULT_FORBID;
}

/*! \brief Function called by RTP engine to get local audio RTP peer */
static enum ast_rtp_glue_result chan_rtp_get_rtp_peer(struct ast_channel *chan, struct ast_rtp_instance **instance)
{
	struct ast_rtp_instance *rtp_instance = ast_channel_tech_pvt(chan);
	struct ast_datastore *datastore;

	if (!rtp_instance) {
		return AST_RTP_GLUE_RESULT_FORBID;
	}

	if ((datastore = ast_channel_datastore_find(chan, &chan_rtp_datastore_info, NULL))) {
		ao2_ref(datastore, -1);

		*instance = rtp_instance;
		ao2_ref(*instance, +1);

		return AST_RTP_GLUE_RESULT_LOCAL;
	}

	return AST_RTP_GLUE_RESULT_FORBID;
}

/*! \brief Local glue for interacting with the RTP engine core */
static struct ast_rtp_glue unicast_rtp_glue = {
	.type = "UnicastRTP",
	.get_rtp_info = chan_rtp_get_rtp_peer,
	.get_vrtp_info = chan_rtp_get_vrtp_peer,
	.get_codec = chan_rtp_get_codec,
	.update_peer = chan_rtp_set_rtp_peer,
};

/*! \brief Function called when our module is unloaded */
static int unload_module(void)
{
	ast_channel_unregister(&multicast_rtp_tech);
	ao2_cleanup(multicast_rtp_tech.capabilities);
	multicast_rtp_tech.capabilities = NULL;

	ast_channel_unregister(&unicast_rtp_tech);
	ao2_cleanup(unicast_rtp_tech.capabilities);
	unicast_rtp_tech.capabilities = NULL;

	ast_rtp_glue_unregister(&unicast_rtp_glue);

	return 0;
}

/*! \brief Function called when our module is loaded */
static int load_module(void)
{
	if (!(multicast_rtp_tech.capabilities = ast_format_cap_alloc(AST_FORMAT_CAP_FLAG_DEFAULT))) {
		return AST_MODULE_LOAD_DECLINE;
	}

	ast_rtp_glue_register(&unicast_rtp_glue);

	ast_format_cap_append_by_type(multicast_rtp_tech.capabilities, AST_MEDIA_TYPE_UNKNOWN);
	if (ast_channel_register(&multicast_rtp_tech)) {
		ast_log_chan(NULL, LOG_ERROR, "Unable to register channel class 'MulticastRTP'\n");
		unload_module();
		return AST_MODULE_LOAD_DECLINE;
	}

	if (!(unicast_rtp_tech.capabilities = ast_format_cap_alloc(AST_FORMAT_CAP_FLAG_DEFAULT))) {
		unload_module();
		return AST_MODULE_LOAD_DECLINE;
	}
	ast_format_cap_append_by_type(unicast_rtp_tech.capabilities, AST_MEDIA_TYPE_UNKNOWN);
	if (ast_channel_register(&unicast_rtp_tech)) {
		ast_log_chan(NULL, LOG_ERROR, "Unable to register channel class 'UnicastRTP'\n");
		unload_module();
		return AST_MODULE_LOAD_DECLINE;
	}

	return AST_MODULE_LOAD_SUCCESS;
}

AST_MODULE_INFO(GABPBX_GPL_KEY, AST_MODFLAG_LOAD_ORDER, "RTP Media Channel",
	.support_level = AST_MODULE_SUPPORT_CORE,
	.load = load_module,
	.unload = unload_module,
	.load_pri = AST_MODPRI_CHANNEL_DRIVER,
	.requires = "res_rtp_multicast",
);
