/*
 * GABpbx -- An open source telephony toolkit.
 *
 * Copyright (C) 1999 - 2006, Digium, Inc.
 *
 * Created by Olle E. Johansson, Edvina.net
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
 * \brief URI encoding / decoding
 *
 * \author Olle E. Johansson <oej@edvina.net>
 *
 * \note For now this code only supports 8 bit characters, not unicode,
         which we ultimately will need to support.
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
	<function name="URIENCODE" language="en_US">
		<since>
			<version>1.2.0</version>
		</since>
		<synopsis>
			Encodes a string to URI-safe encoding according to RFC 2396.
		</synopsis>
		<syntax>
			<parameter name="data" required="true">
				<para>Input string to be encoded.</para>
			</parameter>
		</syntax>
		<description>
			<para>Returns the encoded string defined in <replaceable>data</replaceable>.</para>
		</description>
	</function>
	<function name="URIDECODE" language="en_US">
		<since>
			<version>1.2.0</version>
		</since>
		<synopsis>
			Decodes a URI-encoded string according to RFC 2396.
		</synopsis>
		<syntax>
			<parameter name="data" required="true">
				<para>Input string to be decoded.</para>
			</parameter>
		</syntax>
		<description>
			<para>Returns the decoded URI-encoded <replaceable>data</replaceable> string.</para>
		</description>
	</function>
 ***/

/*! \brief uriencode: Encode URL according to RFC 2396 */
static int uriencode(struct ast_channel *chan, const char *cmd, char *data,
		     char *buf, size_t len)
{
	if (ast_strlen_zero(data)) {
		buf[0] = '\0';
		return 0;
	}

	ast_uri_encode(data, buf, len, ast_uri_http);

	return 0;
}

/*!\brief uridecode: Decode URI according to RFC 2396 */
static int uridecode(struct ast_channel *chan, const char *cmd, char *data,
		     char *buf, size_t len)
{
	if (ast_strlen_zero(data)) {
		buf[0] = '\0';
		return 0;
	}

	ast_copy_string(buf, data, len);
	ast_uri_decode(buf, ast_uri_http);

	return 0;
}

static struct ast_custom_function urldecode_function = {
	.name = "URIDECODE",
	.read = uridecode,
};

static struct ast_custom_function urlencode_function = {
	.name = "URIENCODE",
	.read = uriencode,
};

static int unload_module(void)
{
	return ast_custom_function_unregister(&urldecode_function)
		|| ast_custom_function_unregister(&urlencode_function);
}

static int load_module(void)
{
	return ast_custom_function_register(&urldecode_function)
		|| ast_custom_function_register(&urlencode_function);
}

AST_MODULE_INFO_STANDARD(GABPBX_GPL_KEY, "URI encode/decode dialplan functions");
