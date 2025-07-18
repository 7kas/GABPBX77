/*
 * GABpbx -- An open source telephony toolkit.
 *
 * Copyright (C) 1999 - 2007, Digium, Inc.
 *
 * Mark Michelson <mmichelson@digium.com>
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
 * \brief globally accessible channel datastores
 * \author Mark Michelson <mmichelson@digium.com>
 */

#ifndef _GABPBX_GLOBAL_DATASTORE_H
#define _GABPBX_GLOBAL_DATASTORE_H

#include "gabpbx/channel.h"

extern const struct ast_datastore_info secure_call_info;

struct ast_secure_call_store {
	unsigned int signaling:1;
	unsigned int media:1;
};
#endif
