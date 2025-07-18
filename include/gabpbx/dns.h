/*
 * GABpbx -- An open source telephony toolkit.
 *
 * Written by Thorsten Lockert <tholo@trollphone.org>
 *
 * Funding provided by Troll Phone Networks AS
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
 * \brief DNS support for GABpbx
 * \author Thorsten Lockert <tholo@trollphone.org>
 */

#ifndef _GABPBX_DNS_H
#define _GABPBX_DNS_H

/*! \brief DNS search return values */
enum ast_dns_search_result {
	AST_DNS_SEARCH_FAILURE = -1,     /*!< DNS search resulted in failure */
	AST_DNS_SEARCH_NO_RECORDS = 0,   /*!< DNS search yielded no results */
	AST_DNS_SEARCH_SUCCESS = 1       /*!< DNS search yielded at least one discovered record */
};

/*!
 * \brief Perform DNS lookup (used by DNS, enum and SRV lookups)
 *
 * \param  context   Void pointer containing data to use in the callback function.
 * \param  dname     Domain name to lookup (host, SRV domain, TXT record name).
 * \param  class     Record Class (see "man res_search").
 * \param  type      Record type (see "man res_search").
 * \param  callback  Callback function for handling the discovered resource records from
 *                   the DNS search. len gets the length of the full DNS response.
 *
 * \retval -1 on search failure
 * \retval  0 on no records found
 * \retval  1 on success
 *
 * \note GABpbx DNS is synchronus at this time. This means that if your DNS
 *       service does not work, GABpbx may lock while waiting for a response.
 */
int ast_search_dns(void *context, const char *dname, int class, int type,
	int (*callback)(void *context, unsigned char *answer, int len, unsigned char *fullanswer));

/*!
 * \brief Extended version of the DNS search function.
 *
 * \details Performs a DNS lookup, (used by DNS, enum and SRV lookups), parses the
 *          results and notifies the observer with the response and discovered records
 *          via invoking the provided callbacks (used by ast_dns_system_resolver).
 *
 * \param  context           Void pointer containing data to use in the handler functions.
 * \param  dname             Domain name to lookup (host, SRV domain, TXT record name).
 * \param  rr_class          Record Class (see "man res_search").
 * \param  rr_type           Record type (see "man res_search").
 * \param  response_handler  Callback function for handling the DNS response. Invoked upon
 *                           completion of the DNS search.
 * \param  record_handler    Callback function for handling the discovered resource
 *                           records from the DNS search. Invoked n times, where n is the
 *                           number of records discovered while parsing the DNS
 *                           response.
 *
 * \retval AST_DNS_SEARCH_FAILURE    on search failure
 * \retval AST_DNS_SEARCH_NO_RECORDS on no records found
 * \retval AST_DNS_SEARCH_SUCCESS    on success
 *
 * \note GABpbx DNS is synchronus at this time. This means that if your DNS
 *       service does not work, GABpbx may lock while waiting for a response.
 */
enum ast_dns_search_result ast_search_dns_ex(void *context, const char *dname, int rr_class, int rr_type,
	int (*response_handler)(void *context, unsigned char *dns_response, int dns_response_len, int rcode),
	int (*record_handler)(void *context, unsigned char *record, int record_len, int ttl));

/*! \brief Retrieve the configured nameservers of the system */
struct ao2_container *ast_dns_get_nameservers(void);

#endif /* _GABPBX_DNS_H */
