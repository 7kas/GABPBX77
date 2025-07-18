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
 * \brief DNS NAPTR Record Parsing API
 * \author Joshua Colp <jcolp@digium.com>
 */

#ifndef _GABPBX_DNS_NAPTR_H
#define _GABPBX_DNS_NAPTR_H

#if defined(__cplusplus) || defined(c_plusplus)
extern "C" {
#endif

/*!
 * \brief Get the flags from a NAPTR record
 *
 * \param record The DNS record
 *
 * \return the flags
 */
const char *ast_dns_naptr_get_flags(const struct ast_dns_record *record);

/*!
 * \brief Get the service from a NAPTR record
 *
 * \param record The DNS record
 *
 * \return the service
 */
const char *ast_dns_naptr_get_service(const struct ast_dns_record *record);

/*!
 * \brief Get the regular expression from a NAPTR record
 *
 * \param record The DNS record
 *
 * \return the regular expression
 */
const char *ast_dns_naptr_get_regexp(const struct ast_dns_record *record);

/*!
 * \brief Get the replacement value from a NAPTR record
 *
 * \param record The DNS record
 *
 * \return the replacement value
 */
const char *ast_dns_naptr_get_replacement(const struct ast_dns_record *record);

/*!
 * \brief Get the order from a NAPTR record
 *
 * \param record The DNS record
 *
 * \return the order
 */
unsigned short ast_dns_naptr_get_order(const struct ast_dns_record *record);

/*!
 * \brief Get the preference from a NAPTR record
 *
 * \param record The DNS record
 *
 * \return the preference
 */
unsigned short ast_dns_naptr_get_preference(const struct ast_dns_record *record);

#if defined(__cplusplus) || defined(c_plusplus)
}
#endif

#endif /* _GABPBX_DNS_NAPTR_H */
