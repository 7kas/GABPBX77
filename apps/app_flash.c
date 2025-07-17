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
 * \brief App to flash a DAHDI trunk
 *
 * \author Mark Spencer <markster@digium.com>
 *
 * \ingroup applications
 */

/*** MODULEINFO
	<depend>dahdi</depend>
	<support_level>core</support_level>
 ***/

#include "gabpbx.h"

#include <dahdi/user.h>

#include "gabpbx/lock.h"
#include "gabpbx/file.h"
#include "gabpbx/channel.h"
#include "gabpbx/pbx.h"
#include "gabpbx/module.h"
#include "gabpbx/translate.h"
#include "gabpbx/image.h"

/*** DOCUMENTATION
	<application name="Flash" language="en_US">
		<since>
			<version>1.6.1.0</version>
		</since>
		<synopsis>
			Flashes a DAHDI Trunk.
		</synopsis>
		<syntax />
		<description>
			<para>Performs a flash on a DAHDI trunk. This can be used to access features
			provided on an incoming analogue circuit such as conference and call waiting.
			Use with SendDTMF() to perform external transfers.</para>
		</description>
		<see-also>
			<ref type="application">SendDTMF</ref>
		</see-also>
	</application>
 ***/

static char *app = "Flash";

static inline int dahdi_wait_event(int fd)
{
	/* Avoid the silly dahdi_waitevent which ignores a bunch of events */
	int i,j=0;
	i = DAHDI_IOMUX_SIGEVENT;
	if (ioctl(fd, DAHDI_IOMUX, &i) == -1) return -1;
	if (ioctl(fd, DAHDI_GETEVENT, &j) == -1) return -1;
	return j;
}

static int flash_exec(struct ast_channel *chan, const char *data)
{
	int res = -1;
	int x;
	struct dahdi_params dahdip;

	if (strcasecmp(ast_channel_tech(chan)->type, "DAHDI")) {
		ast_log_chan(NULL, LOG_WARNING, "%s is not a DAHDI channel\n", ast_channel_name(chan));
		return -1;
	}

	memset(&dahdip, 0, sizeof(dahdip));
	res = ioctl(ast_channel_fd(chan, 0), DAHDI_GET_PARAMS, &dahdip);
	if (!res) {
		if (dahdip.sigtype & __DAHDI_SIG_FXS) {
			x = DAHDI_FLASH;
			res = ioctl(ast_channel_fd(chan, 0), DAHDI_HOOK, &x);
			if (!res || (errno == EINPROGRESS)) {
				if (res) {
					/* Wait for the event to finish */
					dahdi_wait_event(ast_channel_fd(chan, 0));
				}
				res = ast_safe_sleep(chan, 1000);
				ast_verb_chan(NULL, 3, "Flashed channel %s\n", ast_channel_name(chan));
			} else
				ast_log_chan(NULL, LOG_WARNING, "Unable to flash channel %s: %s\n", ast_channel_name(chan), strerror(errno));
		} else
			ast_log_chan(NULL, LOG_WARNING, "%s is not an FXO Channel\n", ast_channel_name(chan));
	} else
		ast_log_chan(NULL, LOG_WARNING, "Unable to get parameters of %s: %s\n", ast_channel_name(chan), strerror(errno));

	return res;
}

static int unload_module(void)
{
	return ast_unregister_application(app);
}

static int load_module(void)
{
	return ast_register_application_xml(app, flash_exec);
}

AST_MODULE_INFO_STANDARD(GABPBX_GPL_KEY, "Flash channel application");
