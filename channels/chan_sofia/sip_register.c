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
 * \brief Chan_Sofia SIP REGISTER Method Handler
 *
 * \author Germán Aracil Boned <garacilb@gmail.com>
 * 
 * \ingroup channel_drivers
 */

/* Headers already included by chan_sofia.c */

/* Structure to hold parsed REGISTER request data */
struct register_request {
    /* Basic fields */
    char aor[256];              /* Address of Record */
    char contact_uri[512];      /* Contact URI */
    char call_id[256];          /* Call-ID */
    uint32_t cseq;              /* CSeq number */
    int expires;                /* Expiration time */
    
    /* Authentication fields */
    const char *auth_user;      /* Username from auth */
    const char *auth_realm;     /* Realm from auth */
    const char *auth_nonce;     /* Nonce from auth */
    const char *auth_uri;       /* URI from auth */
    const char *auth_response;  /* Response from auth */
    char *auth_header_value;    /* Raw auth header if needed */
    
    /* Additional fields */
    char user_agent[256];       /* User-Agent header */
    char path_header[2048];     /* Path header (RFC 3327) */
    struct sockaddr_in addr;    /* Source address */
    
    /* State flags */
    int is_deregistration;      /* Contact: * with expires=0 */
    int is_query;               /* No Contact header */
    int has_auth;               /* Has authorization header */
};

/* Forward declarations */
static int validate_register_request(sip_t const *sip);
static int parse_register_headers(sip_t const *sip, struct register_request *req);
static int authenticate_register(struct sip_profile *profile, struct sip_endpoint *endpoint, 
                                struct register_request *req, nua_handle_t *nh, nua_t *nua, 
                                msg_t *msg, sip_t const *sip, nua_saved_event_t *saved);
static int process_registration(struct sip_profile *profile, struct sip_endpoint *endpoint,
                               struct register_request *req);
static void send_register_response(nua_handle_t *nh, int status, char const *phrase,
                                  struct register_request *req, msg_t *response_msg);
static void cleanup_expired_registrations(void);
int count_active_registrations(struct sip_endpoint *endpoint);
void remove_oldest_registration(struct sip_endpoint *endpoint);

/*!
 * \brief Main REGISTER handler - simplified and thread-safe
 * 
 * This function is called from sofia_event_callback when a REGISTER is received.
 * It follows RFC 3261 Section 10.3 for REGISTER processing.
 */
/* Track recently processed REGISTERs to avoid duplicates */
struct processed_register {
    char call_id[256];
    uint32_t cseq;
    time_t timestamp;
};

static struct processed_register last_registers[10];
static int last_register_idx = 0;
static ast_mutex_t register_history_lock = AST_MUTEX_INIT_VALUE;

static int is_duplicate_register(const char *call_id, uint32_t cseq)
{
    int i;
    time_t now = time(NULL);
    
    ast_mutex_lock(&register_history_lock);
    
    /* Check last 10 registers */
    for (i = 0; i < 10; i++) {
        if (last_registers[i].call_id[0] && 
            !strcmp(last_registers[i].call_id, call_id) &&
            last_registers[i].cseq == cseq &&
            (now - last_registers[i].timestamp) < 2) { /* Within 2 seconds */
            ast_mutex_unlock(&register_history_lock);
            return 1; /* Duplicate */
        }
    }
    
    /* Not found, add it */
    ast_copy_string(last_registers[last_register_idx].call_id, call_id, 
                    sizeof(last_registers[last_register_idx].call_id));
    last_registers[last_register_idx].cseq = cseq;
    last_registers[last_register_idx].timestamp = now;
    last_register_idx = (last_register_idx + 1) % 10;
    
    ast_mutex_unlock(&register_history_lock);
    return 0; /* Not duplicate */
}

void handle_register_request(struct sip_profile *profile, nua_handle_t *nh, 
                           sip_t const *sip, nua_t *nua, msg_t *msg, 
                           tagi_t tags[], nua_saved_event_t *saved)
{
    struct register_request req;
    struct sip_endpoint *endpoint = NULL;
    msg_t *response_msg = NULL;
    int res;
    
    /* Check if sip is NULL */
    if (!sip) {
        ast_log(LOG_ERROR, "handle_register_request: sip parameter is NULL\n");
        nua_respond(nh, SIP_500_INTERNAL_SERVER_ERROR, TAG_END());
        return;
    }
    
    /* Clear request structure */
    memset(&req, 0, sizeof(req));
    
    /* Use the msg parameter for proper response association */
    response_msg = msg;
    
    /* Step 1: Validate basic REGISTER structure (RFC 3261 Section 10.3) */
    if (!validate_register_request(sip)) {
        ast_log(LOG_ERROR, "Invalid REGISTER - missing required headers\n");
        send_register_response(nh, SIP_400_BAD_REQUEST, &req, response_msg);
        return;
    }
    
    /* Step 2: Parse REGISTER headers */
    if (parse_register_headers(sip, &req) < 0) {
        ast_log(LOG_ERROR, "Failed to parse REGISTER headers\n");
        send_register_response(nh, SIP_400_BAD_REQUEST, &req, response_msg);
        return;
    }
    
    ast_log(LOG_NOTICE, "REGISTER: AOR=%s, Contact=%s, Expires=%d, Call-ID=%s\n",
            req.aor, req.contact_uri, req.expires, req.call_id);
    
    /* Check for duplicate REGISTER (Sofia-SIP quirk with CSeq > 1) */
    if (is_duplicate_register(req.call_id, req.cseq)) {
        ast_log(LOG_DEBUG, "Duplicate REGISTER detected for Call-ID=%s, CSeq=%d - sending cached response\n", 
                req.call_id, req.cseq);
        /* Still need to send a response, not silently drop */
        /* For now, comment out the return to process normally */
        /* return; */
    }
    
    /* Step 3: Check for special cases */
    if (req.is_query) {
        /* Query for current bindings - return all active registrations */
        ast_log(LOG_DEBUG, "REGISTER query for %s\n", req.aor);
        
        /* Find all registrations for this AOR */
        struct ao2_iterator iter;
        struct sip_registration *reg;
        sip_contact_t *contact_list = NULL;
        sip_contact_t *last_contact = NULL;
        su_home_t *home = su_home_new(sizeof(*home));
        int count = 0;
        time_t now = time(NULL);
        
        if (!home) {
            send_register_response(nh, SIP_500_INTERNAL_SERVER_ERROR, &req, response_msg);
            return;
        }
        
        iter = ao2_iterator_init(registrations, 0);
        while ((reg = ao2_iterator_next(&iter))) {
            if (!strcmp(reg->aor, req.aor) && reg->expires > now) {
                /* Build contact header with remaining expiry */
                char contact_str[1024];
                long remaining = reg->expires - now;
                snprintf(contact_str, sizeof(contact_str), "<%s>;expires=%ld",
                    reg->contact, remaining > 0 ? remaining : 0);
                
                sip_contact_t *new_contact = sip_contact_make(home, contact_str);
                if (new_contact) {
                    if (!contact_list) {
                        contact_list = new_contact;
                    } else {
                        last_contact->m_next = new_contact;
                    }
                    last_contact = new_contact;
                    count++;
                }
            }
            ao2_ref(reg, -1);
        }
        ao2_iterator_destroy(&iter);
        
        ast_log(LOG_DEBUG, "Returning %d current bindings for %s\n", count, req.aor);
        
        if (response_msg) {
            nua_respond(nh, SIP_200_OK,
                       NUTAG_WITH_THIS_MSG(response_msg),
                       TAG_IF(contact_list, SIPTAG_CONTACT(contact_list)),
                       TAG_END());
        } else {
            nua_respond(nh, SIP_200_OK,
                       NUTAG_WITH_THIS(nua),
                       TAG_IF(contact_list, SIPTAG_CONTACT(contact_list)),
                       TAG_END());
        }
        
        su_home_unref(home);
        return;
    }
    
    if (req.is_deregistration) {
        /* Remove all bindings - mark them as expired */
        ast_log(LOG_NOTICE, "De-registration request for %s\n", req.aor);
        
        /* Find all registrations for this AOR and mark as expired */
        struct ao2_iterator iter;
        struct sip_registration *reg;
        int count = 0;
        
        iter = ao2_iterator_init(registrations, 0);
        while ((reg = ao2_iterator_next(&iter))) {
            if (!strcmp(reg->aor, req.aor) && reg->expires > 0) {
                /* Mark as expired (chan_sip compatible) */
                reg->expires = -1;
                count++;
                ast_log(LOG_DEBUG, "Marked registration %s as expired\n", reg->contact);
                
                /* Cancel any scheduled refresh */
                if (reg->refresh_sched_id > -1) {
                    AST_SCHED_DEL(profile->sched, reg->refresh_sched_id);
                }
            }
            ao2_ref(reg, -1);
        }
        ao2_iterator_destroy(&iter);
        
        ast_log(LOG_NOTICE, "De-registered %d binding(s) for %s\n", count, req.aor);
        
        /* Update device state to unavailable */
        char device[256];
        char *username = ast_strdupa(req.aor);
        char *at = strchr(username, '@');
        if (at) *at = '\0';
        
        snprintf(device, sizeof(device), "SIP/%s", username);
        ast_devstate_changed(AST_DEVICE_UNAVAILABLE, AST_DEVSTATE_CACHABLE, "%s", device);
        
        send_register_response(nh, SIP_200_OK, &req, response_msg);
        return;
    }
    
    /* Step 4: Enforce minimum expiration (RFC 3261 Section 10.3 Step 7) */
    if (req.expires > 0 && req.expires < 60) {
        ast_log(LOG_WARNING, "Registration interval too brief: %d\n", req.expires);
        send_register_response(nh, SIP_423_INTERVAL_TOO_BRIEF, &req, response_msg);
        return;
    }
    
    /* Step 5: Find endpoint */
    /* Extract username from AOR */
    char *username = ast_strdupa(req.aor);
    char *at = strchr(username, '@');
    if (at) *at = '\0';
    
    endpoint = sip_endpoint_find(profile, username);
    if (!endpoint) {
        ast_log(LOG_WARNING, "Unknown endpoint '%s' trying to register\n", username);
        send_register_response(nh, SIP_404_NOT_FOUND, &req, response_msg);
        return;
    }
    
    /* Step 6: Authentication */
    res = authenticate_register(profile, endpoint, &req, nh, nua, msg, sip, saved);
    ast_log(LOG_NOTICE, "authenticate_register returned %d for user '%s'\n", res, username);
    if (res < 0) {
        /* Error already handled by authenticate_register */
        ast_log(LOG_NOTICE, "Authentication error for user '%s', returning\n", username);
        ao2_ref(endpoint, -1);
        return;
    } else if (res == 0) {
        /* 401 challenge sent */
        ast_log(LOG_NOTICE, "401 challenge sent for user '%s', returning\n", username);
        ao2_ref(endpoint, -1);
        return;
    }
    
    ast_log(LOG_DEBUG, "Authentication successful, proceeding to process registration\n");
    
    /* Step 7: Process the registration */
    if (process_registration(profile, endpoint, &req) < 0) {
        ast_log(LOG_ERROR, "Failed to process registration\n");
        send_register_response(nh, SIP_500_INTERNAL_SERVER_ERROR, &req, response_msg);
        ao2_ref(endpoint, -1);
        return;
    }
    
    /* Step 8: Send 200 OK with all current bindings */
    struct ao2_container *bindings = get_endpoint_registrations(endpoint);
    if (bindings) {
        /* Build contact list */
        su_home_t home[1] = { SU_HOME_INIT(home) };
        sip_contact_t *contact_list = NULL;
        sip_contact_t **contact_tail = &contact_list;
        struct ao2_iterator iter;
        struct sip_registration *reg;
        time_t now = time(NULL);
        int binding_count = 0;
        
        iter = ao2_iterator_init(bindings, 0);
        while ((reg = ao2_iterator_next(&iter))) {
            if (reg->expires > 0) {
                int remaining = reg->expires - now;
                if (remaining > 0) {
                    char contact_str[1024];
                    snprintf(contact_str, sizeof(contact_str), "<%s>;expires=%d", 
                            reg->contact, remaining);
                    *contact_tail = sip_contact_make(home, contact_str);
                    if (*contact_tail) {
                        contact_tail = &(*contact_tail)->m_next;
                        binding_count++;
                    }
                }
            }
            ao2_ref(reg, -1);
        }
        ao2_iterator_destroy(&iter);
        
        ast_log(LOG_DEBUG, "Sending 200 OK with %d contact bindings\n", binding_count);
        
        /* Send response with contacts */
        /* Use saved event if available */
        if (saved) {
            nua_saved_event_t saved_event[1];
            memcpy(saved_event, saved, sizeof(saved_event));
            nua_respond(nh, SIP_200_OK,
                       NUTAG_WITH_SAVED(saved_event),
                       TAG_IF(contact_list, SIPTAG_CONTACT(contact_list)),
                       TAG_END());
        } else {
            nua_respond(nh, SIP_200_OK,
                       TAG_IF(contact_list, SIPTAG_CONTACT(contact_list)),
                       TAG_END());
        }
        
        su_home_deinit(home);
        ao2_ref(bindings, -1);
    } else {
        /* No bindings, send simple 200 OK */
        send_register_response(nh, SIP_200_OK, &req, response_msg);
    }
    
    /* Update peer status */
    sofia_update_peer_status(endpoint, (req.expires > 0) ? 1 : 0);
    
    /* Cleanup */
    ao2_ref(endpoint, -1);
}

/*! \brief Validate REGISTER request has required headers */
static int validate_register_request(sip_t const *sip)
{
    if (!sip || !sip->sip_from || !sip->sip_to || !sip->sip_call_id || !sip->sip_cseq) {
        return 0;
    }
    return 1;
}

/*! \brief Parse REGISTER headers into request structure */
static int parse_register_headers(sip_t const *sip, struct register_request *req)
{
    const char *to_user = NULL;
    
    /* Extract Address of Record from To header */
    to_user = sip->sip_to->a_url->url_user;
    snprintf(req->aor, sizeof(req->aor), "%s@%s", 
             to_user ? to_user : "unknown",
             sip->sip_to->a_url->url_host ? sip->sip_to->a_url->url_host : "unknown");
    
    /* Get Call-ID and CSeq */
    ast_copy_string(req->call_id, sip->sip_call_id->i_id, sizeof(req->call_id));
    req->cseq = sip->sip_cseq->cs_seq;
    
    /* Get User-Agent if present */
    if (sip->sip_user_agent && sip->sip_user_agent->g_string) {
        ast_copy_string(req->user_agent, sip->sip_user_agent->g_string, 
                       sizeof(req->user_agent));
    } else {
        strcpy(req->user_agent, "Unknown");
    }
    
    /* Get Path header if present (RFC 3327) */
    if (sip->sip_path) {
        sip_route_t *path = (sip_route_t *)sip->sip_path;
        char *path_ptr = req->path_header;
        size_t path_remaining = sizeof(req->path_header);
        su_home_t path_home[1] = { SU_HOME_INIT(path_home) };
        
        while (path && path_remaining > 1) {
            const char *path_url = url_as_string(path_home, path->r_url);
            if (path_url) {
                int written = snprintf(path_ptr, path_remaining, "%s%s", 
                                     path_ptr == req->path_header ? "" : ",", path_url);
                if (written > 0 && written < path_remaining) {
                    path_ptr += written;
                    path_remaining -= written;
                }
            }
            path = path->r_next;
        }
        su_home_deinit(path_home);
    }
    
    /* Get source address from Via header */
    memset(&req->addr, 0, sizeof(req->addr));
    req->addr.sin_family = AF_INET;
    if (sip->sip_via && sip->sip_via->v_host) {
        inet_pton(AF_INET, sip->sip_via->v_host, &req->addr.sin_addr);
        if (sip->sip_via->v_port) {
            req->addr.sin_port = htons(atoi(sip->sip_via->v_port));
        }
    }
    
    /* Process Contact header */
    if (!sip->sip_contact) {
        /* Query for bindings */
        req->is_query = 1;
        return 0;
    }
    
    /* Check for de-registration (Contact: *) */
    if (sip->sip_contact->m_url->url_user && 
        !strcmp(sip->sip_contact->m_url->url_user, "*")) {
        req->is_deregistration = 1;
        return 0;
    }
    
    /* Build full contact URI */
    const url_t *url = sip->sip_contact->m_url;
    snprintf(req->contact_uri, sizeof(req->contact_uri), "sip:%s@%s:%s",
             url->url_user ? url->url_user : to_user,
             url->url_host ? url->url_host : "unknown",
             url->url_port ? url->url_port : "5060");
    
    /* Get expiration time */
    req->expires = 3600; /* Default */
    if (sip->sip_contact->m_expires) {
        req->expires = atoi(sip->sip_contact->m_expires);
    } else if (sip->sip_expires) {
        req->expires = sip->sip_expires->ex_delta;
    }
    
    /* Check for authorization */
    sip_authorization_t const *auth = sip->sip_authorization ? 
                                     sip->sip_authorization : sip->sip_proxy_authorization;
    
    if (auth) {
        req->has_auth = 1;
        /* Authorization will be parsed in authenticate_register */
    } else if (sip->sip_unknown) {
        /* Check unknown headers for Authorization */
        msg_unknown_t *u;
        for (u = sip->sip_unknown; u; u = u->un_next) {
            if (u->un_name && !strcasecmp(u->un_name, "Authorization")) {
                req->auth_header_value = ast_strdupa(u->un_value);
                req->has_auth = 1;
                break;
            }
        }
    }
    
    return 0;
}

/*! \brief Authenticate REGISTER request */
static int authenticate_register(struct sip_profile *profile, struct sip_endpoint *endpoint,
                               struct register_request *req, nua_handle_t *nh, 
                               nua_t *nua, msg_t *msg, sip_t const *sip, nua_saved_event_t *saved)
{
    char realm[256];
    char nonce[256];
    char auth_header[1024];
    char auth_user_clean[256] = "";
    time_t current_time = time(NULL);
    int nonce_valid_time = profile->nonce_ttl > 0 ? profile->nonce_ttl : 30;
    
    /* If no authorization present, send 401 challenge */
    if (!req->has_auth) {
        snprintf(realm, sizeof(realm), "%s", profile->name);
        
        /* Generate or reuse nonce */
        ast_mutex_lock(&profile->lock);
        if (profile->cached_nonce[0] && 
            (current_time - profile->nonce_generated) < nonce_valid_time) {
            ast_copy_string(nonce, profile->cached_nonce, sizeof(nonce));
        } else {
            snprintf(nonce, sizeof(nonce), "%08x", (unsigned int)current_time);
            ast_copy_string(profile->cached_nonce, nonce, sizeof(profile->cached_nonce));
            profile->nonce_generated = current_time;
        }
        ast_mutex_unlock(&profile->lock);
        
        snprintf(auth_header, sizeof(auth_header), 
                "Digest realm=\"%s\", nonce=\"%s\", algorithm=MD5",
                realm, nonce);
        
        ast_log(LOG_DEBUG, "Sending 401 Unauthorized challenge\n");
        
        /* Send 401 - use saved event if available */
        if (saved) {
            nua_saved_event_t saved_event[1];
            memcpy(saved_event, saved, sizeof(saved_event));
            nua_respond(nh, SIP_401_UNAUTHORIZED,
                       NUTAG_WITH_SAVED(saved_event),
                       SIPTAG_WWW_AUTHENTICATE_STR(auth_header),
                       TAG_END());
        } else {
            nua_respond(nh, SIP_401_UNAUTHORIZED,
                       SIPTAG_WWW_AUTHENTICATE_STR(auth_header),
                       TAG_END());
        }
        return 0; /* Challenge sent */
    }
    
    /* Validate the authorization response */
    char ip_addr[INET6_ADDRSTRLEN] = "";
    int auth_valid = 0;
    
    /* Get source IP */
    if (msg) {
        get_source_ip(msg, ip_addr, sizeof(ip_addr));
    }
    
    /* Only process auth if we have auth header */
    if (req->has_auth) {
        /* Check if we have Sofia-SIP parsed auth first */
        sip_authorization_t const *sip_auth = sip->sip_authorization ? 
                                             sip->sip_authorization : sip->sip_proxy_authorization;
        
        if (sip_auth && sip_auth->au_params) {
            /* Use Sofia-SIP parsed authorization */
            for (int i = 0; sip_auth->au_params[i]; i++) {
                const char *param = sip_auth->au_params[i];
                
                if (!strncmp(param, "username=", 9)) {
                    req->auth_user = ast_strdupa(param + 9);
                    /* Remove quotes if present */
                    if (*req->auth_user == '"') {
                        req->auth_user++;
                        char *p = strchr(req->auth_user, '"');
                        if (p) *p = '\0';
                    }
                } else if (!strncmp(param, "realm=", 6)) {
                    req->auth_realm = ast_strdupa(param + 6);
                    /* Remove quotes if present */
                    if (*req->auth_realm == '"') {
                        req->auth_realm++;
                        char *p = strchr(req->auth_realm, '"');
                        if (p) *p = '\0';
                    }
                } else if (!strncmp(param, "nonce=", 6)) {
                    req->auth_nonce = ast_strdupa(param + 6);
                    /* Remove quotes if present */
                    if (*req->auth_nonce == '"') {
                        req->auth_nonce++;
                        char *p = strchr(req->auth_nonce, '"');
                        if (p) *p = '\0';
                    }
                } else if (!strncmp(param, "uri=", 4)) {
                    req->auth_uri = ast_strdupa(param + 4);
                    /* Remove quotes if present */
                    if (*req->auth_uri == '"') {
                        req->auth_uri++;
                        char *p = strchr(req->auth_uri, '"');
                        if (p) *p = '\0';
                    }
                } else if (!strncmp(param, "response=", 9)) {
                    req->auth_response = ast_strdupa(param + 9);
                    /* Remove quotes if present */
                    if (*req->auth_response == '"') {
                        req->auth_response++;
                        char *p = strchr(req->auth_response, '"');
                        if (p) *p = '\0';
                    }
                }
            }
        } else if (req->auth_header_value) {
            /* Fallback to manual parsing of Authorization header */
            char *auth_copy = ast_strdupa(req->auth_header_value);
            char *p, *token, *saveptr;
            
            /* Skip "Digest " prefix */
            if (strncasecmp(auth_copy, "Digest ", 7) == 0) {
                auth_copy += 7;
            }
            
            /* Parse comma-separated parameters */
            for (token = strtok_r(auth_copy, ",", &saveptr); token; 
                 token = strtok_r(NULL, ",", &saveptr)) {
                while (*token == ' ') token++; /* Skip leading spaces */
                
                if (!strncmp(token, "username=", 9)) {
                    req->auth_user = token + 9;
                    if (*req->auth_user == '"') {
                        req->auth_user++;
                        p = strchr(req->auth_user, '"');
                        if (p) *p = '\0';
                    }
                    req->auth_user = ast_strdupa(req->auth_user);
                } else if (!strncmp(token, "realm=", 6)) {
                    req->auth_realm = token + 6;
                    if (*req->auth_realm == '"') {
                        req->auth_realm++;
                        p = strchr(req->auth_realm, '"');
                        if (p) *p = '\0';
                    }
                    req->auth_realm = ast_strdupa(req->auth_realm);
                } else if (!strncmp(token, "nonce=", 6)) {
                    req->auth_nonce = token + 6;
                    if (*req->auth_nonce == '"') {
                        req->auth_nonce++;
                        p = strchr(req->auth_nonce, '"');
                        if (p) *p = '\0';
                    }
                    req->auth_nonce = ast_strdupa(req->auth_nonce);
                } else if (!strncmp(token, "uri=", 4)) {
                    req->auth_uri = token + 4;
                    if (*req->auth_uri == '"') {
                        req->auth_uri++;
                        p = strchr(req->auth_uri, '"');
                        if (p) *p = '\0';
                    }
                    req->auth_uri = ast_strdupa(req->auth_uri);
                } else if (!strncmp(token, "response=", 9)) {
                    req->auth_response = token + 9;
                    if (*req->auth_response == '"') {
                        req->auth_response++;
                        p = strchr(req->auth_response, '"');
                        if (p) *p = '\0';
                    }
                    req->auth_response = ast_strdupa(req->auth_response);
                }
            }
        }
        
        /* Validate parsed values */
        if (!req->auth_user || !req->auth_realm || !req->auth_nonce || 
            !req->auth_uri || !req->auth_response) {
            ast_log(LOG_WARNING, "Missing auth parameters\n");
            send_register_response(nh, SIP_400_BAD_REQUEST, req, msg);
            return -1;
        }
        
        /* Remove @ from username if present */
        ast_copy_string(auth_user_clean, req->auth_user, sizeof(auth_user_clean));
        char *at = strchr(auth_user_clean, '@');
        if (at) *at = '\0';
        
        /* Check auth cache first if enabled */
        if (profile->auth_cache_enabled) {
            auth_valid = sip_auth_cache_check(auth_user_clean, req->auth_realm, 
                                            req->auth_nonce, req->auth_uri, 
                                            req->auth_response, ip_addr);
            if (auth_valid) {
                ast_log(LOG_DEBUG, "Auth cache hit for user '%s'\n", auth_user_clean);
            }
        }
        
        /* If not in cache, calculate MD5 */
        if (!auth_valid) {
            char a1_input[512];
        char a2_input[512];
        char final_input[1024];
        su_md5_t md5_ctx;
        unsigned char a1_hash[SU_MD5_DIGEST_SIZE], a2_hash[SU_MD5_DIGEST_SIZE], 
                      final_hash[SU_MD5_DIGEST_SIZE];
        char a1_hex[33], a2_hex[33], final_hex[33];
        int i;
        
        /* A1 = MD5(username:realm:password) */
        snprintf(a1_input, sizeof(a1_input), "%s:%s:%s", 
                auth_user_clean, req->auth_realm, endpoint->secret);
        su_md5_init(&md5_ctx);
        su_md5_update(&md5_ctx, a1_input, strlen(a1_input));
        su_md5_digest(&md5_ctx, a1_hash);
        for (i = 0; i < SU_MD5_DIGEST_SIZE; i++) {
            sprintf(a1_hex + i*2, "%02x", a1_hash[i]);
        }
        a1_hex[32] = '\0';
        
        /* A2 = MD5(method:uri) */
        snprintf(a2_input, sizeof(a2_input), "REGISTER:%s", req->auth_uri);
        su_md5_init(&md5_ctx);
        su_md5_update(&md5_ctx, a2_input, strlen(a2_input));
        su_md5_digest(&md5_ctx, a2_hash);
        for (i = 0; i < SU_MD5_DIGEST_SIZE; i++) {
            sprintf(a2_hex + i*2, "%02x", a2_hash[i]);
        }
        a2_hex[32] = '\0';
        
        /* Response = MD5(A1:nonce:A2) */
        snprintf(final_input, sizeof(final_input), "%s:%s:%s", 
                a1_hex, req->auth_nonce, a2_hex);
        su_md5_init(&md5_ctx);
        su_md5_update(&md5_ctx, final_input, strlen(final_input));
        su_md5_digest(&md5_ctx, final_hash);
        for (i = 0; i < SU_MD5_DIGEST_SIZE; i++) {
            sprintf(final_hex + i*2, "%02x", final_hash[i]);
        }
        final_hex[32] = '\0';
        
        if (strcasecmp(final_hex, req->auth_response) == 0) {
            auth_valid = 1;
            /* Store successful auth in cache */
            if (profile->auth_cache_enabled) {
                sip_auth_cache_store(auth_user_clean, req->auth_realm, req->auth_nonce,
                                   req->auth_uri, req->auth_response, ip_addr, 
                                   profile->auth_cache_ttl);
            }
        }
        }
        
        if (!auth_valid) {
            ast_log(LOG_WARNING, "Authentication failed for user '%s'\n", auth_user_clean);
            send_register_response(nh, SIP_403_FORBIDDEN, req, msg);
            return -1;
        }
        
        /* Check User-Agent requirement if configured */
        if (endpoint->require_useragent && endpoint->num_useragents > 0) {
            if (!req->user_agent[0] || !useragent_matches_allowed(req->user_agent, endpoint)) {
                ast_log(LOG_WARNING, "User-Agent mismatch for %s - received: %s\n", 
                    auth_user_clean, req->user_agent[0] ? req->user_agent : "none");
                
                /* Track auth failure for wrong User-Agent in blacklist */
                if (profile->blacklist_enabled) {
                    char ip_str[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &req->addr.sin_addr, ip_str, sizeof(ip_str));
                    sip_blacklist_add_failure(ip_str, auth_user_clean, "Invalid User-Agent");
                }
                
                send_register_response(nh, SIP_403_FORBIDDEN, req, msg);
                return -1;
            }
        }
        
        ast_log(LOG_DEBUG, "Authentication successful for user '%s'\n", auth_user_clean);
        return 1; /* Auth successful */
    } /* End of if (req->has_auth) */
    
    /* Should never reach here */
    return -1;
}

/*! \brief Process the registration */
static int process_registration(struct sip_profile *profile, struct sip_endpoint *endpoint,
                               struct register_request *req)
{
    struct sip_registration *reg = NULL;
    time_t now = time(NULL);
    
    ast_log(LOG_DEBUG, "process_registration: AOR=%s, Contact=%s, Expires=%d, Call-ID=%s\n",
            req->aor, req->contact_uri, req->expires, req->call_id);
    
    /* Clean up expired registrations */
    cleanup_expired_registrations();
    
    /* Find existing registration by contact */
    reg = find_registration_by_contact(req->aor, req->contact_uri);
    ast_log(LOG_DEBUG, "find_registration_by_contact returned %p\n", reg);
    
    if (req->expires > 0) {
        /* Register or update */
        if (reg) {
            /* RFC 3261: If Call-ID is different, it's a new registration (e.g. phone restart).
             * The old entry should be replaced. CSeq check doesn't apply. */
            if (strcmp(reg->call_id, req->call_id) != 0) {
                ast_log(LOG_NOTICE, "New Call-ID detected for existing Contact. Replacing registration for %s.\n", req->aor);
                /* The 'reg' entry is now obsolete. We'll treat it as a new creation below. */
                ao2_unlink(registrations, reg); /* Remove old entry from container */
                ao2_ref(reg, -1);                /* Release find reference */
                reg = NULL;                      /* Set to NULL to force new entry creation */
            } else {
                /* If Call-ID is the same, it's a refresh. Check CSeq. */
                if (req->cseq <= reg->cseq) {
                    ast_log(LOG_WARNING, "Out of order REGISTER - CSeq %u <= %u\n", 
                           req->cseq, reg->cseq);
                    ao2_ref(reg, -1);
                    return -1;
                }
                
                /* Update existing registration */
                ao2_lock(reg);
                ast_copy_string(reg->contact, req->contact_uri, sizeof(reg->contact));
                ast_copy_string(reg->user_agent, req->user_agent, sizeof(reg->user_agent));
                ast_copy_string(reg->path, req->path_header, sizeof(reg->path));
                reg->cseq = req->cseq;
                reg->registered = now;
                reg->expires = now + req->expires;
                memcpy(&reg->addr, &req->addr, sizeof(req->addr));
                ao2_unlock(reg);
                
                ast_log(LOG_NOTICE, "Updated registration for %s (expires in %d seconds)\n", 
                       req->aor, req->expires);
                
                /* Schedule refresh if enabled */
                schedule_registration_refresh(reg);
                
                ao2_ref(reg, -1);
            }
        }
        
        /* If reg is NULL (because it didn't exist or we set it to NULL above), create new entry */
        if (!reg) {
            /* Check max_contacts limit */
            int max_contacts = endpoint->max_contacts > 0 ? endpoint->max_contacts :
                             (profile->max_contacts_global > 0 ? profile->max_contacts_global : 3);
            int active_count = count_active_registrations(endpoint);
            
            if (active_count >= max_contacts) {
                ast_log(LOG_NOTICE, "Max contacts limit (%d) reached for %s\n",
                       max_contacts, endpoint->name);
                remove_oldest_registration(endpoint);
            }
            
            /* Create new registration */
            reg = ao2_alloc(sizeof(*reg), registration_destructor);
            if (!reg) {
                ast_log(LOG_ERROR, "Failed to allocate registration record\n");
                return -1;
            }
            
            reg->endpoint = endpoint;
            ast_copy_string(reg->aor, req->aor, sizeof(reg->aor));
            ast_copy_string(reg->contact, req->contact_uri, sizeof(reg->contact));
            ast_copy_string(reg->call_id, req->call_id, sizeof(reg->call_id));
            reg->cseq = req->cseq;
            ast_copy_string(reg->user_agent, req->user_agent, sizeof(reg->user_agent));
            ast_copy_string(reg->path, req->path_header, sizeof(reg->path));
            reg->registered = now;
            reg->expires = now + req->expires;
            memcpy(&reg->addr, &req->addr, sizeof(reg->addr));
            reg->refresh_sched_id = -1;
            
            ao2_link(registrations, reg);
            endpoint->registration_count = count_active_registrations(endpoint);
            
            ast_log(LOG_NOTICE, "New registration for %s (expires in %d seconds)\n", 
                   req->aor, req->expires);
            
            /* Schedule refresh if enabled */
            schedule_registration_refresh(reg);
        }
    } else {
        /* Unregister - expires = 0 */
        if (reg) {
            /* Remove the registration from the container */
            ao2_unlink(registrations, reg);
            ao2_ref(reg, -1);
            ast_log(LOG_NOTICE, "Registration expired for %s (unregistered)\n", req->aor);
        }
    }
    
    return 0;
}

/*! \brief Send REGISTER response with proper message association */
static void send_register_response(nua_handle_t *nh, int status, char const *phrase,
                                  struct register_request *req, msg_t *response_msg)
{
    /* Build response based on status code */
    switch (status) {
    case 200:
        /* 200 OK - handled separately with Contact headers */
        /* Always use default response mechanism for synchronous processing */
        nua_respond(nh, status, phrase, TAG_END());
        break;
        
    case 423:
        /* 423 Interval Too Brief - include Min-Expires header */
        if (response_msg) {
            nua_respond(nh, status, phrase,
                       NUTAG_WITH_THIS_MSG(response_msg),
                       SIPTAG_MIN_EXPIRES_STR("3600"),
                       TAG_END());
        } else {
            nua_respond(nh, status, phrase,
                       SIPTAG_MIN_EXPIRES_STR("3600"),
                       TAG_END());
        }
        break;
        
    default:
        /* All other responses */
        if (response_msg) {
            nua_respond(nh, status, phrase, 
                       NUTAG_WITH_THIS_MSG(response_msg),
                       TAG_END());
        } else {
            nua_respond(nh, status, phrase, TAG_END());
        }
        break;
    }
}

/*! \brief Count active (non-expired) registrations for an endpoint */
int count_active_registrations(struct sip_endpoint *endpoint)
{
    struct ao2_iterator iter;
    struct sip_registration *reg;
    int count = 0;
    time_t now = time(NULL);
    
    iter = ao2_iterator_init(registrations, 0);
    while ((reg = ao2_iterator_next(&iter))) {
        if (reg->endpoint == endpoint && reg->expires > 0 && reg->expires > now) {
            count++;
        }
        ao2_ref(reg, -1);
    }
    ao2_iterator_destroy(&iter);
    
    return count;
}

/*! \brief Remove oldest registration for an endpoint */
void remove_oldest_registration(struct sip_endpoint *endpoint)
{
    struct ao2_iterator iter;
    struct sip_registration *reg, *oldest = NULL;
    time_t oldest_time = 0;
    
    /* Find the oldest active registration */
    iter = ao2_iterator_init(registrations, 0);
    while ((reg = ao2_iterator_next(&iter))) {
        if (reg->endpoint == endpoint && reg->expires > 0) {
            if (!oldest || reg->registered < oldest_time) {
                if (oldest) {
                    ao2_ref(oldest, -1);
                }
                oldest = reg;
                oldest_time = reg->registered;
                ao2_ref(oldest, +1); /* Keep a reference */
            }
        }
        ao2_ref(reg, -1);
    }
    ao2_iterator_destroy(&iter);
    
    /* Remove the oldest */
    if (oldest) {
        ao2_unlink(registrations, oldest);
        ast_log(LOG_NOTICE, "Removed oldest registration for %s (contact: %s)\n",
                endpoint->name, oldest->contact);
        ao2_ref(oldest, -1);
    }
}

/*! \brief Clean up expired registrations - keep only the most recent expired per endpoint */
static void cleanup_expired_registrations(void)
{
    struct ao2_iterator iter;
    struct sip_registration *reg;
    time_t now = time(NULL);
    
    /* For each endpoint, find all its expired registrations and keep only the most recent */
    struct sip_endpoint *current_endpoint = NULL;
    struct sip_registration *most_recent_expired = NULL;
    time_t most_recent_time = 0;
    
    /* We'll do multiple passes - one per unique endpoint */
    int done = 0;
    while (!done) {
        done = 1;
        current_endpoint = NULL;
        most_recent_expired = NULL;
        most_recent_time = 0;
        
        /* Pass 1: Find an endpoint with expired registrations */
        iter = ao2_iterator_init(registrations, 0);
        while ((reg = ao2_iterator_next(&iter))) {
            if (reg->expires == -1 || (reg->expires > 0 && reg->expires <= now)) {
                if (!current_endpoint) {
                    current_endpoint = reg->endpoint;
                    done = 0;
                }
                
                if (reg->endpoint == current_endpoint) {
                    /* Track the most recent expired for this endpoint */
                    if (!most_recent_expired || reg->registered > most_recent_time) {
                        most_recent_expired = reg;
                        most_recent_time = reg->registered;
                    }
                }
            }
            ao2_ref(reg, -1);
        }
        ao2_iterator_destroy(&iter);
        
        if (!current_endpoint) {
            /* No more endpoints with expired registrations */
            break;
        }
        
        /* Pass 2: Remove all expired registrations for this endpoint except the most recent */
        iter = ao2_iterator_init(registrations, 0);
        while ((reg = ao2_iterator_next(&iter))) {
            if (reg->endpoint == current_endpoint && 
                (reg->expires == -1 || (reg->expires > 0 && reg->expires <= now))) {
                if (reg != most_recent_expired) {
                    /* This is not the most recent expired, remove it */
                    ao2_unlink(registrations, reg);
                    ast_log(LOG_DEBUG, "Removed old expired registration for %s (contact: %s)\n",
                            reg->endpoint->name, reg->contact);
                }
            }
            ao2_ref(reg, -1);
        }
        ao2_iterator_destroy(&iter);
    }
}