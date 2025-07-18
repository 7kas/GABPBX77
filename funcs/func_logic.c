/*
 * GABpbx -- An open source telephony toolkit.
 *
 * Copyright (C) 1999 - 2006, Digium, Inc.
 * Portions Copyright (C) 2005, Anthony Minessale II
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
 * \brief Conditional logic dialplan functions
 *
 * \author Anthony Minessale II
 *
 * \ingroup functions
 */

/*** MODULEINFO
	<support_level>core</support_level>
 ***/

#include "gabpbx.h"

#include "gabpbx/module.h"
#include "gabpbx/channel.h"
#include "gabpbx/pbx.h"
#include "gabpbx/utils.h"
#include "gabpbx/app.h"

/*** DOCUMENTATION
	<function name="ISNULL" language="en_US">
		<since>
			<version>1.2.0</version>
		</since>
		<synopsis>
			Check if a value is NULL.
		</synopsis>
		<syntax>
			<parameter name="data" required="true" />
		</syntax>
		<description>
			<para>Returns <literal>1</literal> if NULL or <literal>0</literal> otherwise.</para>
		</description>
	</function>
	<function name="SET" language="en_US">
		<since>
			<version>1.2.0</version>
		</since>
		<synopsis>
			SET assigns a value to a channel variable.
		</synopsis>
		<syntax argsep="=">
			<parameter name="varname" required="true" />
			<parameter name="value" />
		</syntax>
		<description>
		</description>
	</function>
	<function name="EXISTS" language="en_US">
		<since>
			<version>1.2.0</version>
		</since>
		<synopsis>
			Test the existence of a value.
		</synopsis>
		<syntax>
			<parameter name="data" required="true" />
		</syntax>
		<description>
			<para>Returns <literal>1</literal> if exists, <literal>0</literal> otherwise.</para>
		</description>
	</function>
	<function name="IF" language="en_US">
		<since>
			<version>1.2.0</version>
		</since>
		<synopsis>
			Check for an expression.
		</synopsis>
		<syntax argsep="?">
			<parameter name="expression" required="true" />
			<parameter name="retvalue" argsep=":" required="true">
				<argument name="true" />
				<argument name="false" />
			</parameter>
		</syntax>
		<description>
			<para>Returns the data following <literal>?</literal> if true, else the data following <literal>:</literal></para>
		</description>
	</function>
	<function name="IFTIME" language="en_US">
		<since>
			<version>1.2.0</version>
		</since>
		<synopsis>
			Temporal Conditional.
		</synopsis>
		<syntax argsep="?">
			<parameter name="timespec" required="true" />
			<parameter name="retvalue" required="true" argsep=":">
				<argument name="true" />
				<argument name="false" />
			</parameter>
		</syntax>
		<description>
			<para>Returns the data following <literal>?</literal> if true, else the data following <literal>:</literal></para>
		</description>
	</function>
	<function name="IMPORT" language="en_US">
		<since>
			<version>1.6.0</version>
		</since>
		<synopsis>
			Retrieve the value of a variable from another channel.
		</synopsis>
		<syntax>
			<parameter name="channel" required="true" />
			<parameter name="variable" required="true" />
		</syntax>
		<description>
		</description>
	</function>
	<function name="DELETE" language="en_US">
		<since>
			<version>18.21.0</version>
			<version>20.6.0</version>
			<version>21.1.0</version>
		</since>
		<synopsis>
			Deletes a specified channel variable.
		</synopsis>
		<syntax>
			<parameter name="varname" required="true">
				<para>Channel variable name</para>
			</parameter>
		</syntax>
		<description>
			<para>Delete the channel variable specified in <replaceable>varname</replaceable>.
			Will succeed if the channel variable exists or not.</para>
		</description>
		<see-also>
			<ref type="function">GLOBAL_DELETE</ref>
		</see-also>
	</function>
	<function name="VARIABLE_EXISTS" language="en_US">
		<since>
			<version>18.21.0</version>
			<version>20.6.0</version>
			<version>21.1.0</version>
		</since>
		<synopsis>
			Check if a dialplan variable exists or not.
		</synopsis>
		<syntax>
			<parameter name="varname" required="true">
				<para>Channel variable name</para>
			</parameter>
		</syntax>
		<description>
			<para>Returns <literal>1</literal> if channel variable exists or <literal>0</literal> otherwise.</para>
		</description>
		<see-also>
			<ref type="function">GLOBAL_EXISTS</ref>
		</see-also>
	</function>
 ***/

static int isnull(struct ast_channel *chan, const char *cmd, char *data,
		  char *buf, size_t len)
{
	strcpy(buf, data && *data ? "0" : "1");

	return 0;
}

static int exists(struct ast_channel *chan, const char *cmd, char *data, char *buf,
		  size_t len)
{
	strcpy(buf, data && *data ? "1" : "0");

	return 0;
}

static int iftime(struct ast_channel *chan, const char *cmd, char *data, char *buf,
		  size_t len)
{
	struct ast_timing timing;
	char *expr;
	char *iftrue;
	char *iffalse;

	data = ast_strip_quoted(data, "\"", "\"");
	expr = strsep(&data, "?");
	iftrue = strsep(&data, ":");
	iffalse = data;

	if (ast_strlen_zero(expr) || !(iftrue || iffalse)) {
		ast_log_chan(NULL, LOG_WARNING,
				"Syntax IFTIME(<timespec>?[<true>][:<false>])\n");
		return -1;
	}

	if (!ast_build_timing(&timing, expr)) {
		ast_log_chan(NULL, LOG_WARNING, "Invalid Time Spec.\n");
		ast_destroy_timing(&timing);
		return -1;
	}

	if (iftrue)
		iftrue = ast_strip_quoted(iftrue, "\"", "\"");
	if (iffalse)
		iffalse = ast_strip_quoted(iffalse, "\"", "\"");

	ast_copy_string(buf, ast_check_timing(&timing) ? S_OR(iftrue, "") : S_OR(iffalse, ""), len);
	ast_destroy_timing(&timing);

	return 0;
}

static int acf_if(struct ast_channel *chan, const char *cmd, char *data, char *buf,
		  size_t len)
{
	AST_DECLARE_APP_ARGS(args1,
		AST_APP_ARG(expr);
		AST_APP_ARG(remainder);
	);
	AST_DECLARE_APP_ARGS(args2,
		AST_APP_ARG(iftrue);
		AST_APP_ARG(iffalse);
	);
	args2.iftrue = args2.iffalse = NULL; /* you have to set these, because if there is nothing after the '?',
											then args1.remainder will be NULL, not a pointer to a null string, and
											then any garbage in args2.iffalse will not be cleared, and you'll crash.
										    -- and if you mod the ast_app_separate_args func instead, you'll really
											mess things up badly, because the rest of everything depends on null args
											for non-specified stuff. */

	AST_NONSTANDARD_APP_ARGS(args1, data, '?');
	AST_NONSTANDARD_APP_ARGS(args2, args1.remainder, ':');

	if (ast_strlen_zero(args1.expr) || !(args2.iftrue || args2.iffalse)) {
		ast_debug(1, "<expr>='%s', <true>='%s', and <false>='%s'\n", args1.expr, args2.iftrue, args2.iffalse);
		return -1;
	}

	args1.expr = ast_strip(args1.expr);
	if (args2.iftrue)
		args2.iftrue = ast_strip(args2.iftrue);
	if (args2.iffalse)
		args2.iffalse = ast_strip(args2.iffalse);

	ast_copy_string(buf, pbx_checkcondition(args1.expr) ? (S_OR(args2.iftrue, "")) : (S_OR(args2.iffalse, "")), len);

	return 0;
}

static int set(struct ast_channel *chan, const char *cmd, char *data, char *buf,
	       size_t len)
{
	char *varname;
	char *val;

	varname = strsep(&data, "=");
	val = data;

	if (ast_strlen_zero(varname) || !val) {
		ast_log_chan(NULL, LOG_WARNING, "Syntax SET(<varname>=[<value>])\n");
		return -1;
	}

	varname = ast_strip(varname);
	val = ast_strip(val);
	pbx_builtin_setvar_helper(chan, varname, val);
	ast_copy_string(buf, val, len);

	return 0;
}

static int set2(struct ast_channel *chan, const char *cmd, char *data, struct ast_str **str, ssize_t len)
{
	if (len > -1) {
		ast_str_make_space(str, len == 0 ? strlen(data) : len);
	}
	return set(chan, cmd, data, ast_str_buffer(*str), ast_str_size(*str));
}

static int import_helper(struct ast_channel *chan, const char *cmd, char *data, char *buf, struct ast_str **str, ssize_t len)
{
	AST_DECLARE_APP_ARGS(args,
		AST_APP_ARG(channel);
		AST_APP_ARG(varname);
	);
	AST_STANDARD_APP_ARGS(args, data);
	if (buf) {
		*buf = '\0';
	}

	if (!ast_strlen_zero(args.varname)) {
		struct ast_channel *chan2;

		if ((chan2 = ast_channel_get_by_name(args.channel))) {
			char *s = ast_alloca(strlen(args.varname) + 4);
			sprintf(s, "${%s}", args.varname);
			ast_channel_lock(chan2);
			if (buf) {
				pbx_substitute_variables_helper(chan2, s, buf, len);
			} else {
				ast_str_substitute_variables(str, len, chan2, s);
			}
			ast_channel_unlock(chan2);
			chan2 = ast_channel_unref(chan2);
		}
	}

	return 0;
}

static int import_read(struct ast_channel *chan, const char *cmd, char *data, char *buf, size_t len)
{
	return import_helper(chan, cmd, data, buf, NULL, len);
}

static int import_read2(struct ast_channel *chan, const char *cmd, char *data, struct ast_str **str, ssize_t len)
{
	return import_helper(chan, cmd, data, NULL, str, len);
}

static int delete_write(struct ast_channel *chan, const char *cmd, char *data, const char *value)
{
	pbx_builtin_setvar_helper(chan, data, NULL);

	return 0;
}

static int variable_exists_read(struct ast_channel *chan, const char *cmd, char *data,
		  char *buf, size_t len)
{
	const char *var = pbx_builtin_getvar_helper(chan, data);

	strcpy(buf, var ? "1" : "0");

	return 0;
}

static struct ast_custom_function isnull_function = {
	.name = "ISNULL",
	.read = isnull,
	.read_max = 2,
};

static struct ast_custom_function set_function = {
	.name = "SET",
	.read = set,
	.read2 = set2,
};

static struct ast_custom_function exists_function = {
	.name = "EXISTS",
	.read = exists,
	.read_max = 2,
};

static struct ast_custom_function if_function = {
	.name = "IF",
	.read = acf_if,
};

static struct ast_custom_function if_time_function = {
	.name = "IFTIME",
	.read = iftime,
};

static struct ast_custom_function import_function = {
	.name = "IMPORT",
	.read = import_read,
	.read2 = import_read2,
};

static struct ast_custom_function delete_function = {
	.name = "DELETE",
	.write = delete_write,
};

static struct ast_custom_function variable_exists_function = {
	.name = "VARIABLE_EXISTS",
	.read = variable_exists_read,
};

static int unload_module(void)
{
	int res = 0;

	res |= ast_custom_function_unregister(&isnull_function);
	res |= ast_custom_function_unregister(&set_function);
	res |= ast_custom_function_unregister(&exists_function);
	res |= ast_custom_function_unregister(&if_function);
	res |= ast_custom_function_unregister(&if_time_function);
	res |= ast_custom_function_unregister(&import_function);
	res |= ast_custom_function_unregister(&delete_function);
	res |= ast_custom_function_unregister(&variable_exists_function);

	return res;
}

static int load_module(void)
{
	int res = 0;

	res |= ast_custom_function_register(&isnull_function);
	res |= ast_custom_function_register(&set_function);
	res |= ast_custom_function_register(&exists_function);
	res |= ast_custom_function_register(&if_function);
	res |= ast_custom_function_register(&if_time_function);
	res |= ast_custom_function_register(&import_function);
	res |= ast_custom_function_register(&delete_function);
	res |= ast_custom_function_register(&variable_exists_function);

	return res;
}

AST_MODULE_INFO_STANDARD(GABPBX_GPL_KEY, "Logical dialplan functions");
