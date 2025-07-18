/*
 * GABpbx -- An open source telephony toolkit.
 *
 * Copyright (C) 2013, Digium, Inc.
 *
 * Kinsey Moore <kmoore@digium.com>
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

/*** MODULEINFO
	<depend>pjproject</depend>
	<depend>res_pjsip</depend>
	<depend>res_pjsip_session</depend>
	<support_level>core</support_level>
 ***/

#include "gabpbx.h"

#include <pjsip.h>
#include <pjsip_ua.h>

#include "gabpbx/res_pjsip.h"
#include "gabpbx/res_pjsip_session.h"
#include "gabpbx/module.h"
#include "gabpbx/strings.h"

static const pj_str_t PATH_NAME = { "Path", 4 };
static pj_str_t PATH_SUPPORTED_NAME = { "path", 4 };

static struct ast_sip_aor *find_aor(struct ast_sip_contact *contact)
{
	if (!contact) {
		return NULL;
	}
	if (ast_strlen_zero(contact->aor)) {
		return NULL;
	}

	return ast_sip_location_retrieve_aor(contact->aor);
}

static struct ast_sip_aor *find_aor2(struct ast_sip_endpoint *endpoint, pjsip_uri *uri)
{
	char *configured_aors, *aor_name;
	const pj_str_t *uri_username;
	const pj_str_t *uri_hostname;
	char *domain_name;
	char *username;
	struct ast_str *id = NULL;

	if (ast_strlen_zero(endpoint->aors)) {
		return NULL;
	}

	uri_hostname = ast_sip_pjsip_uri_get_hostname(uri);
	domain_name = ast_alloca(uri_hostname->slen + 1);
	ast_copy_pj_str(domain_name, uri_hostname, uri_hostname->slen + 1);

	uri_username = ast_sip_pjsip_uri_get_username(uri);
	username = ast_alloca(uri_username->slen + 1);
	ast_copy_pj_str(username, uri_username, uri_username->slen + 1);

	/*
	 * We may want to match without any user options getting
	 * in the way.
	 */
	AST_SIP_USER_OPTIONS_TRUNCATE_CHECK(username);

	configured_aors = ast_strdupa(endpoint->aors);

	/* Iterate the configured AORs to see if the user or the user+domain match */
	while ((aor_name = ast_strip(strsep(&configured_aors, ",")))) {
		struct ast_sip_domain_alias *alias = NULL;

		if (ast_strlen_zero(aor_name)) {
			continue;
		}

		if (!strcmp(username, aor_name)) {
			break;
		}

		if (!id && !(id = ast_str_create(strlen(username) + uri_hostname->slen + 2))) {
			aor_name = NULL;
			break;
		}

		ast_str_set(&id, 0, "%s@", username);
		if ((alias = ast_sorcery_retrieve_by_id(ast_sip_get_sorcery(), "domain_alias", domain_name))) {
			ast_str_append(&id, 0, "%s", alias->domain);
			ao2_cleanup(alias);
		} else {
			ast_str_append(&id, 0, "%s", domain_name);
		}

		if (!strcmp(aor_name, ast_str_buffer(id))) {
			break;
		}
	}
	ast_free(id);

	if (ast_strlen_zero(aor_name)) {
		return NULL;
	}

	return ast_sip_location_retrieve_aor(aor_name);
}

static struct ast_sip_contact *find_contact(struct ast_sip_aor *aor, pjsip_uri *uri)
{
	struct ao2_iterator it_contacts;
	struct ast_sip_contact *contact;
	char contact_buf[512];
	int contact_buf_len;
	int res = 0;

	RAII_VAR(struct ao2_container *, contacts, NULL, ao2_cleanup);

	if (!(contacts = ast_sip_location_retrieve_aor_contacts(aor))) {
		/* No contacts are available, skip it as well */
		return NULL;
	} else if (!ao2_container_count(contacts)) {
		/* We were given a container but no contacts are in it... */
		return NULL;
	}

	contact_buf_len = pjsip_uri_print(PJSIP_URI_IN_CONTACT_HDR, uri, contact_buf, 512);
	contact_buf[contact_buf_len] = '\0';

	it_contacts = ao2_iterator_init(contacts, 0);
	for (; (contact = ao2_iterator_next(&it_contacts)); ao2_ref(contact, -1)) {
		if (!strcmp(contact_buf, contact->uri)) {
			res = 1;
			break;
		}
	}
	ao2_iterator_destroy(&it_contacts);
	if (!res) {
		return NULL;
	}
	return contact;
}


/*!
 * \brief Get the path string associated with this contact and tdata
 *
 * \param pool
 * \param contact The URI identifying the associated contact
 * \param path_str The place to store the retrieved path information
 *
 * \retval zero on success
 * \retval non-zero on failure or no available path information
 */
static int path_get_string(pj_pool_t *pool, struct ast_sip_contact *contact, pj_str_t *path_str)
{
	if (!contact || ast_strlen_zero(contact->path)) {
		return -1;
	}

	*path_str = pj_strdup3(pool, contact->path);
	return 0;
}

static int add_supported(pjsip_tx_data *tdata)
{
	pjsip_supported_hdr *hdr;
	int i;

	hdr = pjsip_msg_find_hdr(tdata->msg, PJSIP_H_SUPPORTED, NULL);
	if (!hdr) {
		/* insert a new Supported header */
		hdr = pjsip_supported_hdr_create(tdata->pool);
		if (!hdr) {
			return -1;
		}

		pjsip_msg_add_hdr(tdata->msg, (pjsip_hdr *)hdr);
	}

	/* Don't add the value if it's already there */
	for (i = 0; i < hdr->count; ++i) {
		if (pj_stricmp(&hdr->values[i], &PATH_SUPPORTED_NAME) == 0) {
			return 0;
		}
	}

	if (hdr->count >= PJSIP_GENERIC_ARRAY_MAX_COUNT) {
		return -1;
	}

	/* add on to the existing Supported header */
	pj_strassign(&hdr->values[hdr->count++], &PATH_SUPPORTED_NAME);

	return 0;
}

/*!
 * \internal
 * \brief Adds a Route header to an outgoing request if
 * path information is available.
 *
 * \param endpoint The endpoint with which this request is associated
 * \param contact The contact to which this request is being sent
 * \param tdata The outbound request
 */
static void path_outgoing_request(struct ast_sip_endpoint *endpoint, struct ast_sip_contact *contact, pjsip_tx_data *tdata)
{
	RAII_VAR(struct ast_sip_aor *, aor, NULL, ao2_cleanup);

	if (!endpoint) {
		return;
	}

	aor = find_aor(contact);
	if (!aor) {
		aor = find_aor2(endpoint, tdata->msg->line.req.uri);
	}
	if (!aor || !aor->support_path) {
		return;
	}

	if (add_supported(tdata)) {
		return;
	}

	if (!contact) {
		contact = find_contact(aor, tdata->msg->line.req.uri);
		if (contact) {
			if (!ast_strlen_zero(contact->path)) {
				ast_sip_set_outbound_proxy(tdata, contact->path);
			}
			ao2_ref(contact, -1);
			contact = NULL;
		}
	} else {
		if (!ast_strlen_zero(contact->path)) {
			ast_sip_set_outbound_proxy(tdata, contact->path);
		}
	}
}

static void path_session_outgoing_request(struct ast_sip_session *session, pjsip_tx_data *tdata)
{
	path_outgoing_request(session->endpoint, session->contact, tdata);
}

/*!
 * \internal
 * \brief Adds a path header to an outgoing 2XX response
 *
 * \param endpoint The endpoint to which the INVITE response is to be sent
 * \param contact The contact to which the INVITE response is to be sent
 * \param tdata The outbound INVITE response
 */
static void path_outgoing_response(struct ast_sip_endpoint *endpoint, struct ast_sip_contact *contact, pjsip_tx_data *tdata)
{
	struct pjsip_status_line status = tdata->msg->line.status;
	pj_str_t path_dup;
	pjsip_generic_string_hdr *path_hdr;
	RAII_VAR(struct ast_sip_aor *, aor, NULL, ao2_cleanup);
	pjsip_cseq_hdr *cseq = pjsip_msg_find_hdr(tdata->msg, PJSIP_H_CSEQ, NULL);
	const pj_str_t REGISTER_METHOD = {"REGISTER", 8};

	if (!endpoint
		|| !pj_stristr(&REGISTER_METHOD, &cseq->method.name)
		|| !PJSIP_IS_STATUS_IN_CLASS(status.code, 200)) {
		return;
	}

	aor = find_aor(contact);
	if (!aor || !aor->support_path || add_supported(tdata)
		|| path_get_string(tdata->pool, contact, &path_dup)) {
		return;
	}

	path_hdr = pjsip_generic_string_hdr_create(tdata->pool, &PATH_NAME, &path_dup);
	if (!path_hdr) {
		return;
	}

	pjsip_msg_add_hdr(tdata->msg, (pjsip_hdr*)path_hdr);
}

static void path_session_outgoing_response(struct ast_sip_session *session, pjsip_tx_data *tdata)
{
	path_outgoing_response(session->endpoint, session->contact, tdata);
}

static struct ast_sip_supplement path_supplement = {
	.priority = AST_SIP_SUPPLEMENT_PRIORITY_CHANNEL - 100,
	.outgoing_request = path_outgoing_request,
	.outgoing_response = path_outgoing_response,
};

static struct ast_sip_session_supplement path_session_supplement = {
	.priority = AST_SIP_SUPPLEMENT_PRIORITY_CHANNEL - 100,
	.outgoing_request = path_session_outgoing_request,
	.outgoing_response = path_session_outgoing_response,
};

static int load_module(void)
{
	ast_sip_register_supplement(&path_supplement);
	ast_sip_session_register_supplement(&path_session_supplement);

	return AST_MODULE_LOAD_SUCCESS;
}

static int unload_module(void)
{
	ast_sip_unregister_supplement(&path_supplement);
	ast_sip_session_unregister_supplement(&path_session_supplement);
	return 0;
}

AST_MODULE_INFO(GABPBX_GPL_KEY, AST_MODFLAG_LOAD_ORDER, "PJSIP Path Header Support",
	.support_level = AST_MODULE_SUPPORT_CORE,
	.load = load_module,
	.unload = unload_module,
	.load_pri = AST_MODPRI_APP_DEPEND,
	.requires = "res_pjsip,res_pjsip_session",
);
