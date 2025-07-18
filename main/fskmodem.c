/*
 * GABpbx -- An open source telephony toolkit.
 *
 * Copyright (C) 1999 - 2008, Digium, Inc.
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
 * \brief FSK Modem Support
 * \note Includes code and algorithms from the Zapata library.
 */

/*** MODULEINFO
	<support_level>core</support_level>
 ***/

#include "gabpbx.h"

#ifdef INTEGER_CALLERID
#include "fskmodem_int.c"
#else
#include "fskmodem_float.c"
#endif
