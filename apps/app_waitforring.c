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
 * \brief Wait for Ring Application
 *
 * \author Mark Spencer <markster@digium.com>
 *
 * \ingroup applications
 */

/*** MODULEINFO
	<support_level>extended</support_level>
 ***/

#include "gabpbx.h"

#include "gabpbx/file.h"
#include "gabpbx/channel.h"
#include "gabpbx/pbx.h"
#include "gabpbx/module.h"
#include "gabpbx/lock.h"

/*** DOCUMENTATION
	<application name="WaitForRing" language="en_US">
		<since>
			<version>0.4.0</version>
		</since>
		<synopsis>
			Wait for Ring Application.
		</synopsis>
		<syntax>
			<parameter name="timeout" required="true" />
		</syntax>
		<description>
			<para>Returns <literal>0</literal> after waiting at least <replaceable>timeout</replaceable> seconds,
			and only after the next ring has completed. Returns <literal>0</literal> on success or
			<literal>-1</literal> on hangup.</para>
		</description>
	</application>
 ***/

static char *app = "WaitForRing";

static int waitforring_exec(struct ast_channel *chan, const char *data)
{
	struct ast_frame *f;
	struct ast_silence_generator *silgen = NULL;
	int res = 0;
	double s;
	int timeout_ms;
	int ms;
	struct timeval start = ast_tvnow();

	if (!data || (sscanf(data, "%30lg", &s) != 1)) {
		ast_log_chan(NULL, LOG_WARNING, "WaitForRing requires an argument (minimum seconds)\n");
		return 0;
	}

	if (s < 0.0) {
		ast_log_chan(NULL, LOG_WARNING, "Invalid timeout provided for WaitForRing (%lg)\n", s);
		return 0;
	}

	if (ast_opt_transmit_silence) {
		silgen = ast_channel_start_silence_generator(chan);
	}

	timeout_ms = s * 1000.0;
	while ((ms = ast_remaining_ms(start, timeout_ms))) {
		ms = ast_waitfor(chan, ms);
		if (ms < 0) {
			res = -1;
			break;
		}
		if (ms > 0) {
			f = ast_read(chan);
			if (!f) {
				res = -1;
				break;
			}
			if ((f->frametype == AST_FRAME_CONTROL) && (f->subclass.integer == AST_CONTROL_RING)) {
				ast_verb_chan(NULL, 3, "Got a ring but still waiting for timeout\n");
			}
			ast_frfree(f);
		}
	}
	/* Now we're really ready for the ring */
	if (!res) {
		for (;;) {
			int wait_res = ast_waitfor(chan, -1);
			if (wait_res < 0) {
				res = -1;
				break;
			} else {
				f = ast_read(chan);
				if (!f) {
					res = -1;
					break;
				}
				if ((f->frametype == AST_FRAME_CONTROL) && (f->subclass.integer == AST_CONTROL_RING)) {
					ast_verb_chan(NULL, 3, "Got a ring after the timeout\n");
					ast_frfree(f);
					break;
				}
				ast_frfree(f);
			}
		}
	}

	if (silgen) {
		ast_channel_stop_silence_generator(chan, silgen);
	}

	return res;
}

static int unload_module(void)
{
	return ast_unregister_application(app);
}

static int load_module(void)
{
	return ast_register_application_xml(app, waitforring_exec);
}

AST_MODULE_INFO_STANDARD_EXTENDED(GABPBX_GPL_KEY, "Waits until first ring after time");
