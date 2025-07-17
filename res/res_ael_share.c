/*
 * GABpbx -- An open source telephony toolkit.
 *
 * Copyright (C) 2007, Digium, Inc.
 *
 * Steve Murphy <murf@digium.com>
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
 * \brief Shareable AEL code -- mainly between internal and external modules
 *
 * \author Steve Murphy <murf@digium.com>
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
#include "gabpbx/config.h"
#include "gabpbx/module.h"
#include "gabpbx/lock.h"
#include "gabpbx/cli.h"


static int unload_module(void)
{
	return 0;
}

static int load_module(void)
{
	return AST_MODULE_LOAD_SUCCESS;
}

AST_MODULE_INFO(GABPBX_GPL_KEY, AST_MODFLAG_GLOBAL_SYMBOLS, "share-able code for AEL",
	.support_level = AST_MODULE_SUPPORT_EXTENDED,
	.load = load_module,
	.unload = unload_module
);
