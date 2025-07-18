/*
 * GABpbx -- An open source telephony toolkit.
 *
 * Copyright (C) 2015, Digium, Inc.
 *
 * Joshua Colp <jcolp@digium.com>
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
 * \brief DNS TLSA Record Support
 *
 * \author Joshua Colp <jcolp@digium.com>
 */

/*** MODULEINFO
	<support_level>core</support_level>
 ***/

#include "gabpbx.h"

#include "gabpbx/dns_core.h"
#include "gabpbx/dns_tlsa.h"

unsigned int ast_dns_tlsa_get_usage(const struct ast_dns_record *record)
{
	return 0;
}

unsigned int ast_dns_tlsa_get_selector(const struct ast_dns_record *record)
{
	return 0;
}

unsigned int ast_dns_tlsa_get_matching_type(const struct ast_dns_record *record)
{
	return 0;
}

const char *ast_dns_tlsa_get_association_data(const struct ast_dns_record *record)
{
	return NULL;
}
