/*
 * GABpbx -- An open source telephony toolkit.
 *
 * Copyright (C) 2025, 7kas servicios de internet SL.
 *
 * Germán Aracil Boned <garacilb@gmail.com>
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
 * \brief Chan_Sofia SIP OPTIONS Method Handler
 *
 * \author Germán Aracil Boned <garacilb@gmail.com>
 * 
 * \ingroup channel_drivers
 */

/* Headers already included by chan_sofia.c */

/* Structure to hold parsed OPTIONS request data */
struct options_request {
    /* Request details */
    char from_uri[512];         /* From URI */
    char to_uri[512];           /* To URI */
    char call_id[256];          /* Call-ID */
    uint32_t cseq;              /* CSeq number */
    
    /* Headers */
    char accept[512];           /* Accept header */
    char accept_encoding[256];  /* Accept-Encoding header */
    char accept_language[256];  /* Accept-Language header */
    char user_agent[256];       /* User-Agent header */
    
    /* Flags */
    int is_keepalive;           /* Is this a NAT keepalive? */
    int in_dialog;              /* Is this in-dialog OPTIONS? */
};

/* Forward declarations */
static int parse_options_headers(sip_t const *sip, struct options_request *req);
static void send_options_response(nua_handle_t *nh, struct sip_profile *profile, 
                                 struct options_request *req, msg_t *response_msg);
static int is_options_keepalive(struct options_request *req);

/*!
 * \brief Main OPTIONS handler
 * 
 * Handles OPTIONS requests for capability discovery and keepalive.
 * Implements RFC 3261 Section 11.
 */
void handle_options_request(struct sip_profile *profile, nua_handle_t *nh, 
                           sip_t const *sip, nua_t *nua, msg_t *msg,
                           tagi_t tags[], nua_saved_event_t *saved)
{
    struct options_request req;
    nua_event_data_t const *event_data = NULL;
    msg_t *response_msg = NULL;
    
    ast_debug(2, "=== OPTIONS REQUEST RECEIVED ===\n");
    
    /* Clear request structure */
    memset(&req, 0, sizeof(req));
    
    /* Get event data for proper response association */
    if (saved) {
        event_data = nua_event_data(saved);
        if (event_data && event_data->e_msg) {
            response_msg = event_data->e_msg;
        }
    }
    
    /* Check if OPTIONS is enabled */
    if (!profile->enable_options) {
        ast_log(LOG_DEBUG, "OPTIONS disabled for profile %s\n", profile->name);
        if (response_msg) {
            nua_respond(nh, SIP_501_NOT_IMPLEMENTED,
                       NUTAG_WITH_THIS_MSG(response_msg),
                       TAG_END());
        } else {
            nua_respond(nh, SIP_501_NOT_IMPLEMENTED,
                       TAG_END());
        }
        return;
    }
    
    /* Parse OPTIONS headers */
    if (sip && parse_options_headers(sip, &req) < 0) {
        ast_log(LOG_WARNING, "Failed to parse OPTIONS headers\n");
        if (response_msg) {
            nua_respond(nh, SIP_400_BAD_REQUEST,
                       NUTAG_WITH_THIS_MSG(response_msg),
                       TAG_END());
        } else {
            nua_respond(nh, SIP_400_BAD_REQUEST,
                       TAG_END());
        }
        return;
    }
    
    /* Check if this is a keepalive */
    req.is_keepalive = is_options_keepalive(&req);
    
    if (req.is_keepalive) {
        ast_debug(3, "OPTIONS keepalive from %s\n", req.from_uri);
    } else {
        ast_log(LOG_NOTICE, "OPTIONS capability query from %s to %s\n", 
                req.from_uri, req.to_uri);
    }
    
    /* Send appropriate response */
    send_options_response(nh, profile, &req, response_msg);
    
    /* Update endpoint status if this is a keepalive response */
    if (req.is_keepalive) {
        /* Extract username from From URI */
        char *username = ast_strdupa(req.from_uri);
        char *at = strchr(username, '@');
        if (at) *at = '\0';
        
        /* Skip "sip:" prefix if present */
        if (!strncasecmp(username, "sip:", 4)) {
            username += 4;
        }
        
        /* Find endpoint and update last_options timestamp */
        struct sip_endpoint *endpoint = sip_endpoint_find(profile, username);
        if (endpoint) {
            endpoint->last_options = time(NULL);
            ao2_ref(endpoint, -1);
        }
    }
    
    ast_debug(2, "=== OPTIONS REQUEST COMPLETED ===\n");
}

/*! \brief Parse OPTIONS headers */
static int parse_options_headers(sip_t const *sip, struct options_request *req)
{
    if (!sip || !req) {
        return -1;
    }
    
    /* Extract From URI */
    if (sip->sip_from) {
        const char *from_str = url_as_string(NULL, sip->sip_from->a_url);
        if (from_str) {
            ast_copy_string(req->from_uri, from_str, sizeof(req->from_uri));
        }
    }
    
    /* Extract To URI */
    if (sip->sip_to) {
        const char *to_str = url_as_string(NULL, sip->sip_to->a_url);
        if (to_str) {
            ast_copy_string(req->to_uri, to_str, sizeof(req->to_uri));
        }
    }
    
    /* Get Call-ID and CSeq */
    if (sip->sip_call_id && sip->sip_call_id->i_id) {
        ast_copy_string(req->call_id, sip->sip_call_id->i_id, sizeof(req->call_id));
    }
    
    if (sip->sip_cseq) {
        req->cseq = sip->sip_cseq->cs_seq;
    }
    
    /* Get Accept header if present */
    if (sip->sip_accept) {
        /* Build comma-separated list of accepted types */
        sip_accept_t *accept = sip->sip_accept;
        char *ptr = req->accept;
        size_t remaining = sizeof(req->accept);
        
        while (accept && remaining > 1) {
            const char *type = accept->ac_type;
            const char *subtype = accept->ac_subtype;
            
            if (type && subtype) {
                int written = snprintf(ptr, remaining, "%s%s/%s",
                                     ptr == req->accept ? "" : ", ",
                                     type, subtype);
                if (written > 0 && written < remaining) {
                    ptr += written;
                    remaining -= written;
                }
            }
            accept = accept->ac_next;
        }
    }
    
    /* Get Accept-Encoding if present */
    if (sip->sip_accept_encoding) {
        sip_accept_encoding_t *enc = sip->sip_accept_encoding;
        char *ptr = req->accept_encoding;
        size_t remaining = sizeof(req->accept_encoding);
        
        while (enc && remaining > 1) {
            if (enc->aa_value) {
                int written = snprintf(ptr, remaining, "%s%s",
                                     ptr == req->accept_encoding ? "" : ", ",
                                     enc->aa_value);
                if (written > 0 && written < remaining) {
                    ptr += written;
                    remaining -= written;
                }
            }
            enc = enc->aa_next;
        }
    }
    
    /* Get Accept-Language if present */
    if (sip->sip_accept_language) {
        sip_accept_language_t *lang = sip->sip_accept_language;
        char *ptr = req->accept_language;
        size_t remaining = sizeof(req->accept_language);
        
        while (lang && remaining > 1) {
            if (lang->aa_value) {
                int written = snprintf(ptr, remaining, "%s%s",
                                     ptr == req->accept_language ? "" : ", ",
                                     lang->aa_value);
                if (written > 0 && written < remaining) {
                    ptr += written;
                    remaining -= written;
                }
            }
            lang = lang->aa_next;
        }
    }
    
    /* Get User-Agent if present */
    if (sip->sip_user_agent && sip->sip_user_agent->g_string) {
        ast_copy_string(req->user_agent, sip->sip_user_agent->g_string, 
                       sizeof(req->user_agent));
    }
    
    /* Check if this is in-dialog */
    req->in_dialog = (sip->sip_to && sip->sip_to->a_tag != NULL);
    
    return 0;
}

/*! \brief Send OPTIONS response with capabilities */
static void send_options_response(nua_handle_t *nh, struct sip_profile *profile,
                                 struct options_request *req, msg_t *response_msg)
{
    /* Build Allow header with supported methods */
    const char *allow_methods = "INVITE, ACK, CANCEL, OPTIONS, BYE, "
                               "REFER, SUBSCRIBE, NOTIFY, INFO, "
                               "PUBLISH, MESSAGE, UPDATE, REGISTER";
    
    /* Build Accept header with supported content types */
    const char *accept_types = "application/sdp, application/dtmf-relay, "
                              "application/dialog-info+xml, "
                              "message/sipfrag";
    
    /* Build Supported header for extensions */
    const char *supported = "replaces, timer, path";
    
    /* Add User-Agent */
    char user_agent[256];
    snprintf(user_agent, sizeof(user_agent), "GABpbx-Sofia/22.0");
    
    /* Send 200 OK with capabilities */
    if (response_msg) {
        nua_respond(nh, SIP_200_OK,
                   NUTAG_WITH_THIS_MSG(response_msg),
                   SIPTAG_ALLOW_STR(allow_methods),
                   SIPTAG_ACCEPT_STR(accept_types),
                   SIPTAG_SUPPORTED_STR(supported),
                   SIPTAG_USER_AGENT_STR(user_agent),
                   TAG_IF(req->accept_encoding[0], 
                          SIPTAG_ACCEPT_ENCODING_STR("identity")),
                   TAG_IF(req->accept_language[0],
                          SIPTAG_ACCEPT_LANGUAGE_STR("en")),
                   TAG_END());
    } else {
        nua_respond(nh, SIP_200_OK,
                   SIPTAG_ALLOW_STR(allow_methods),
                   SIPTAG_ACCEPT_STR(accept_types),
                   SIPTAG_SUPPORTED_STR(supported),
                   SIPTAG_USER_AGENT_STR(user_agent),
                   TAG_IF(req->accept_encoding[0], 
                          SIPTAG_ACCEPT_ENCODING_STR("identity")),
                   TAG_IF(req->accept_language[0],
                          SIPTAG_ACCEPT_LANGUAGE_STR("en")),
                   TAG_END());
    }
}

/*! \brief Check if OPTIONS is a keepalive ping */
static int is_options_keepalive(struct options_request *req)
{
    /* Heuristics to detect keepalive:
     * 1. No Accept header (just checking if we're alive)
     * 2. From and To are the same
     * 3. Short or no body
     */
    
    if (!req->accept[0]) {
        /* No Accept header - likely a keepalive */
        return 1;
    }
    
    if (strcasecmp(req->from_uri, req->to_uri) == 0) {
        /* From and To are identical - likely keepalive */
        return 1;
    }
    
    /* Otherwise, assume it's a capability query */
    return 0;
}

/*! \brief Send OPTIONS keepalive to endpoint */
int send_options_keepalive(struct sip_profile *profile, struct sip_endpoint *endpoint)
{
    nua_handle_t *nh = NULL;
    char to_uri[512];
    struct sip_registration *reg;
    
    if (!profile || !endpoint || !profile->nua) {
        return -1;
    }
    
    /* Find an active registration for this endpoint */
    reg = find_active_registration(endpoint);
    if (!reg) {
        ast_log(LOG_DEBUG, "No active registration for endpoint %s\n", endpoint->name);
        return -1;
    }
    
    /* Build To URI from registration contact */
    ast_copy_string(to_uri, reg->contact, sizeof(to_uri));
    ao2_ref(reg, -1);
    
    /* Create handle for OPTIONS */
    nh = nua_handle(profile->nua, NULL, NUTAG_URL(to_uri), TAG_END());
    if (!nh) {
        ast_log(LOG_ERROR, "Failed to create handle for OPTIONS\n");
        return -1;
    }
    
    /* Send OPTIONS */
    nua_options(nh,
               SIPTAG_FROM_STR(profile->from_uri),
               SIPTAG_TO_STR(to_uri),
               TAG_END());
    
    /* Handle will be destroyed when response is received */
    
    ast_debug(1, "Sent OPTIONS keepalive to %s\n", endpoint->name);
    return 0;
}

/*! \brief Schedule periodic OPTIONS keepalives */
void schedule_options_keepalives(struct sip_profile *profile)
{
    struct ao2_iterator iter;
    struct sip_endpoint *endpoint;
    time_t now = time(NULL);
    int keepalive_interval = profile->keepalive_interval > 0 ? 
                            profile->keepalive_interval : 60; /* Default 60 seconds */
    
    if (!profile->enable_options_keepalive) {
        return;
    }
    
    /* Iterate through all endpoints */
    iter = ao2_iterator_init(endpoints, 0);
    while ((endpoint = ao2_iterator_next(&iter))) {
        /* Check if endpoint has keepalive enabled */
        if (endpoint->keepalive_enabled) {
            /* Check if it's time to send keepalive */
            if ((now - endpoint->last_options) >= keepalive_interval) {
                send_options_keepalive(profile, endpoint);
                endpoint->last_options = now;
            }
        }
        ao2_ref(endpoint, -1);
    }
    ao2_iterator_destroy(&iter);
}