/*
 * GABpbx -- An open source telephony toolkit.
 *
 * Copyright (C) 2015, Digium, Inc.
 *
 * Alec Davis <sivad.a@paradise.net.nz>
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
 * \brief Application to place the channel into an existing Bridge
 *
 * \author Alec Davis
 *
 * \ingroup applications
 */

/*** MODULEINFO
	<support_level>core</support_level>
 ***/

#include "gabpbx.h"

#include "gabpbx/file.h"
#include "gabpbx/module.h"
#include "gabpbx/channel.h"
#include "gabpbx/bridge.h"
#include "gabpbx/features.h"

/*** DOCUMENTATION
	<application name="BridgeAdd" language="en_US">
		<since>
			<version>14.0.0</version>
		</since>
		<synopsis>
			Join a bridge that contains the specified channel.
		</synopsis>
		<syntax>
			<parameter name="channel" required="true">
				<para>The current channel joins the bridge containing the channel
				identified by the channel name, channel name prefix, or channel
				uniqueid.</para>
			</parameter>
		</syntax>
		<description>
			<para>This application places the incoming channel into
			the bridge containing the specified channel. The specified
			channel only needs to be the prefix of a full channel name
			IE. 'PJSIP/cisco0001'.
			</para>
			<para>This application sets the following channel variable upon completion:</para>
			<variablelist>
				<variable name="BRIDGERESULT">
					<para>The result of the bridge attempt as a text string.</para>
					<value name="SUCCESS" />
					<value name="FAILURE" />
					<value name="LOOP" />
					<value name="NONEXISTENT" />
				</variable>
			</variablelist>
		</description>
	</application>
 ***/

static const char app[] = "BridgeAdd";

static int bridgeadd_exec(struct ast_channel *chan, const char *data)
{
	struct ast_channel *c_ref;
	struct ast_bridge_features chan_features;
	struct ast_bridge *bridge;
	char *c_name;
	int failed;

	/* Answer the channel if needed */
	if (ast_channel_state(chan) != AST_STATE_UP) {
		ast_answer(chan);
	}

	if (ast_strlen_zero(data)) {
		data = "";
		c_ref = NULL;
	} else {
		c_ref = ast_channel_get_by_name_prefix(data, strlen(data));
	}
	if (!c_ref) {
		ast_verb_chan(NULL, 4, "Channel '%s' not found\n", data);
		pbx_builtin_setvar_helper(chan, "BRIDGERESULT", "NONEXISTENT");
		return 0;
	}
	if (chan == c_ref) {
		ast_channel_unref(c_ref);
		pbx_builtin_setvar_helper(chan, "BRIDGERESULT", "LOOP");
		return 0;
	}

	c_name = ast_strdupa(ast_channel_name(c_ref));

	ast_channel_lock(c_ref);
	bridge = ast_channel_get_bridge(c_ref);
	ast_channel_unlock(c_ref);

	ast_channel_unref(c_ref);

	if (!bridge) {
		ast_verb_chan(NULL, 4, "Channel '%s' is not in a bridge\n", c_name);
		pbx_builtin_setvar_helper(chan, "BRIDGERESULT", "FAILURE");
		return 0;
	}

	ast_verb_chan(NULL, 4, "%s is joining %s in bridge %s\n",
		ast_channel_name(chan), c_name, bridge->uniqueid);

	failed = ast_bridge_features_init(&chan_features)
		|| ast_bridge_join(bridge, chan, NULL, &chan_features, NULL, 0);
	if (failed) {
		ast_verb_chan(NULL, 4, "%s failed to join %s in bridge %s\n",
			ast_channel_name(chan), c_name, bridge->uniqueid);
	}

	ast_bridge_features_cleanup(&chan_features);
	ao2_cleanup(bridge);
	pbx_builtin_setvar_helper(chan, "BRIDGERESULT", failed ? "FAILURE" : "SUCCESS");
	return 0;
}

static int unload_module(void)
{
	return ast_unregister_application(app);
}

static int load_module(void)
{
	return ast_register_application_xml(app, bridgeadd_exec);
}

AST_MODULE_INFO_STANDARD(GABPBX_GPL_KEY, "Bridge Add Channel Application");
