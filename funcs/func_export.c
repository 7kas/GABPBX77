/*
 * GABpbx -- An open source telephony toolkit.
 *
 * Copyright (C) 2021-2022, Naveen Albert
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
 * \brief Set variables and functions on other channels
 *
 * \author Naveen Albert <gabpbx@phreaknet.org>
 *
 * \ingroup functions
 */

/*** MODULEINFO
	<support_level>extended</support_level>
 ***/

#include "gabpbx.h"

#include "gabpbx/module.h"
#include "gabpbx/channel.h"
#include "gabpbx/pbx.h"
#include "gabpbx/utils.h"
#include "gabpbx/app.h"
#include "gabpbx/stringfields.h"

/*** DOCUMENTATION
	<function name="EXPORT" language="en_US">
		<since>
			<version>16.30.0</version>
			<version>18.16.0</version>
			<version>19.8.0</version>
			<version>20.1.0</version>
		</since>
		<synopsis>
			Set variables or dialplan functions on any arbitrary channel that exists.
		</synopsis>
		<syntax>
			<parameter name="channel" required="true">
				<para>The complete channel name: <literal>SIP/12-abcd1234</literal>.</para>
			</parameter>
			<parameter name="var" required="true">
				<para>Variable name</para>
			</parameter>
		</syntax>
		<description>
			<para>Allows setting variables or functions on any existing channel if it exists.</para>
		</description>
		<see-also>
			<ref type="function">IMPORT</ref>
			<ref type="function">MASTER_CHANNEL</ref>
			<ref type="function">SHARED</ref>
		</see-also>
	</function>
 ***/

static int func_export_write(struct ast_channel *chan, const char *function, char *data, const char *value)
{
	struct ast_channel *ochan;

	AST_DECLARE_APP_ARGS(args,
		AST_APP_ARG(channel);
		AST_APP_ARG(var);
	);
	AST_STANDARD_APP_ARGS(args, data);

	if (!args.channel) {
		ast_log_chan(NULL, LOG_WARNING, "No channel was provided to %s function.\n", function);
		return -1;
	}
	if (!args.var) {
		ast_log_chan(NULL, LOG_WARNING, "No variable name was provided to %s function.\n", function);
		return -1;
	}
	ochan = ast_channel_get_by_name(args.channel);
	if (!ochan) {
		ast_log_chan(NULL, LOG_WARNING, "Channel '%s' not found! '%s' not set.\n", args.channel, args.var);
		return -1;
	}

	pbx_builtin_setvar_helper(ochan, args.var, value);
	ast_channel_unref(ochan);
	return 0;
}

static struct ast_custom_function export_function = {
	.name = "EXPORT",
	.write = func_export_write,
};

static int unload_module(void)
{
	return ast_custom_function_unregister(&export_function);
}

static int load_module(void)
{
	return ast_custom_function_register(&export_function);
}

AST_MODULE_INFO_STANDARD_EXTENDED(GABPBX_GPL_KEY, "Set variables and functions on other channels");
