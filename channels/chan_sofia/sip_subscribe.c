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
 * \brief Chan_Sofia SIP SUBSCRIBE Method Handler
 *
 * \author Germán Aracil Boned <garacilb@gmail.com>
 * 
 * \ingroup channel_drivers
 */

/* Headers already included by chan_sofia.c */

/* External function from chan_sofia.c */
extern int get_source_ip(msg_t *msg, char *ip_addr, size_t ip_size);

/* RFC 3265 - SIP-Specific Event Notification */

/* Subscription states */
enum subscription_state {
    SUB_STATE_PENDING,      /* Initial state, waiting for authorization */
    SUB_STATE_ACTIVE,       /* Active subscription */
    SUB_STATE_TERMINATED    /* Subscription terminated */
};

/* Structure to hold subscription information */
struct sip_subscription {
    /* Subscription identification */
    char id[128];                      /* Unique subscription ID */
    char call_id[256];                 /* SIP Call-ID */
    char from_tag[128];                /* From tag */
    char to_tag[128];                  /* To tag */
    
    /* Subscription details */
    char event_package[64];            /* Event package (e.g., "dialog", "presence") */
    char accept[512];                  /* Accept header value */
    char watcher_uri[512];             /* Subscriber URI (watcher) */
    char presentity_uri[512];          /* Monitored resource URI (presentity) */
    char watcher_contact[512];         /* Real contact for NAT (if different) */
    
    /* Timing */
    time_t created;                    /* Subscription creation time */
    time_t expires;                    /* Expiration time */
    int refresh_interval;              /* Refresh interval in seconds */
    
    /* State */
    enum subscription_state state;     /* Current subscription state */
    int version;                       /* Event state version for NOTIFYs */
    
    /* Transport */
    nua_handle_t *nh;                  /* NUA handle for this subscription */
    struct sip_profile *profile;       /* Associated profile */
    
    /* Extension monitoring */
    char monitored_exten[AST_MAX_EXTENSION]; /* Extension being monitored */
    int last_device_state;             /* Last known device state */
};

/* Global subscription container */
static struct ao2_container *subscriptions;

/* Forward declarations */
static void subscription_destructor(void *obj);
static int subscription_hash_fn(const void *obj, int flags);
static int subscription_cmp_fn(void *obj, void *arg, int flags);
static struct sip_subscription *find_subscription(const char *call_id, const char *from_tag);
static struct sip_subscription *create_subscription(struct sip_profile *profile, nua_handle_t *nh, sip_t const *sip);
static void send_notify(struct sip_subscription *sub, const char *state_str, const char *xml_body);
static char *build_dialog_info_xml(struct sip_subscription *sub, const char *state);
static const char *device_state_to_dialog_state(enum ast_device_state state);

/*!
 * \brief Initialize subscription subsystem
 */
int sip_subscription_init(void)
{
    /* Create subscription container */
    subscriptions = ao2_container_alloc_hash(AO2_ALLOC_OPT_LOCK_MUTEX, 0,
                                           SOFIA_MAX_SUBSCRIPTIONS,
                                           subscription_hash_fn, NULL,
                                           subscription_cmp_fn);
    if (!subscriptions) {
        ast_log(LOG_ERROR, "Failed to create subscription container\n");
        return -1;
    }
    
    return 0;
}

/*!
 * \brief Destroy subscription subsystem
 */
void sip_subscription_destroy(void)
{
    if (subscriptions) {
        ao2_ref(subscriptions, -1);
        subscriptions = NULL;
    }
}

/*!
 * \brief Main SUBSCRIBE handler
 * 
 * Handles SUBSCRIBE requests for event notification.
 * Implements RFC 3265.
 */
void handle_subscribe_request(struct sip_profile *profile, nua_handle_t *nh, 
                            sip_t const *sip, nua_t *nua, msg_t *msg,
                            tagi_t tags[], nua_saved_event_t *saved)
{
    const char *event = NULL;
    const char *from_user = NULL;
    const char *to_user = NULL;
    const char *call_id = NULL;
    const char *from_tag = NULL;
    int expires = 3600;
    msg_t *response_msg = NULL;
    struct sip_subscription *sub = NULL;
    
    ast_debug(2, "=== SUBSCRIBE REQUEST RECEIVED ===\n");
    
    /* Get event data for proper response association */
    if (saved) {
        nua_event_data_t const *event_data = nua_event_data(saved);
        if (event_data && event_data->e_msg) {
            response_msg = event_data->e_msg;
        }
    }
    
    /* Get current message if sip is NULL */
    if (!sip && msg) {
        sip = sip_object(msg);
    }
    
    if (!sip) {
        ast_log(LOG_WARNING, "SUBSCRIBE handler: sip is NULL\n");
        if (response_msg) {
            nua_respond(nh, SIP_400_BAD_REQUEST,
                       NUTAG_WITH_THIS_MSG(response_msg),
                       TAG_END());
        } else {
            nua_respond(nh, SIP_400_BAD_REQUEST, TAG_END());
        }
        return;
    }
    
    /* Check if subscriptions are enabled */
    if (!profile->enable_presence) {
        ast_log(LOG_DEBUG, "Subscriptions disabled for profile %s\n", profile->name);
        if (response_msg) {
            nua_respond(nh, SIP_501_NOT_IMPLEMENTED,
                       NUTAG_WITH_THIS_MSG(response_msg),
                       TAG_END());
        } else {
            nua_respond(nh, SIP_501_NOT_IMPLEMENTED, TAG_END());
        }
        return;
    }
    
    /* Extract Event header */
    if (sip->sip_event && sip->sip_event->o_type) {
        event = sip->sip_event->o_type;
    } else {
        /* Sofia-SIP may not parse Event header properly, try manual extraction */
        if (msg) {
            char const *payload = msg_as_string(nua_handle_home(nh), msg, NULL, 0, NULL);
            if (payload) {
                const char *event_line = strstr(payload, "\nEvent:");
                if (!event_line) {
                    event_line = strstr(payload, "\r\nEvent:");
                }
                if (event_line) {
                    event_line = strchr(event_line, ':');
                    if (event_line) {
                        event_line++;
                        while (*event_line == ' ') event_line++;
                        
                        static char event_buf[64];
                        int i = 0;
                        while (event_line[i] && event_line[i] != '\r' && 
                               event_line[i] != '\n' && event_line[i] != ';' && 
                               i < sizeof(event_buf) - 1) {
                            event_buf[i] = event_line[i];
                            i++;
                        }
                        event_buf[i] = '\0';
                        event = event_buf;
                    }
                }
            }
        }
    }
    
    if (!event) {
        ast_log(LOG_WARNING, "SUBSCRIBE without Event header\n");
        if (response_msg) {
            nua_respond(nh, SIP_400_BAD_REQUEST,
                       NUTAG_WITH_THIS_MSG(response_msg),
                       SIPTAG_WARNING_STR("399 GABpbx \"Missing Event header\""),
                       TAG_END());
        } else {
            nua_respond(nh, SIP_400_BAD_REQUEST,
                       SIPTAG_WARNING_STR("399 GABpbx \"Missing Event header\""),
                       TAG_END());
        }
        return;
    }
    
    /* Check if we support this event package */
    if (strcasecmp(event, "dialog") != 0 && 
        strcasecmp(event, "presence") != 0 &&
        strcasecmp(event, "message-summary") != 0) {
        ast_log(LOG_NOTICE, "Unsupported event package: %s\n", event);
        if (response_msg) {
            nua_respond(nh, SIP_489_BAD_EVENT,
                       NUTAG_WITH_THIS_MSG(response_msg),
                       SIPTAG_ALLOW_EVENTS_STR("dialog, presence, message-summary"),
                       TAG_END());
        } else {
            nua_respond(nh, SIP_489_BAD_EVENT,
                       SIPTAG_ALLOW_EVENTS_STR("dialog, presence, message-summary"),
                       TAG_END());
        }
        return;
    }
    
    /* Extract subscription details */
    if (sip->sip_from) {
        if (sip->sip_from->a_url->url_user) {
            from_user = sip->sip_from->a_url->url_user;
        }
        if (sip->sip_from->a_tag) {
            from_tag = sip->sip_from->a_tag;
        }
    }
    
    if (sip->sip_to && sip->sip_to->a_url->url_user) {
        to_user = sip->sip_to->a_url->url_user;
    }
    
    if (sip->sip_call_id && sip->sip_call_id->i_id) {
        call_id = sip->sip_call_id->i_id;
    }
    
    /* Get expires value */
    if (sip->sip_expires) {
        expires = sip->sip_expires->ex_delta;
    }
    
    ast_log(LOG_NOTICE, "SUBSCRIBE for '%s' event from '%s' to '%s' (expires: %d)\n",
            event, from_user ? from_user : "unknown", 
            to_user ? to_user : "unknown", expires);
    
    /* Check if this is a refresh or termination */
    if (call_id && from_tag) {
        sub = find_subscription(call_id, from_tag);
        if (sub) {
            if (expires == 0) {
                /* Subscription termination */
                ast_log(LOG_NOTICE, "Terminating subscription %s\n", sub->id);
                sub->state = SUB_STATE_TERMINATED;
                
                /* Send final NOTIFY */
                send_notify(sub, "terminated", NULL);
                
                /* Remove subscription */
                ao2_unlink(subscriptions, sub);
                ao2_ref(sub, -1);
                sub = NULL;
            } else {
                /* Subscription refresh */
                ast_log(LOG_DEBUG, "Refreshing subscription %s\n", sub->id);
                sub->expires = time(NULL) + expires;
            }
        }
    }
    
    /* Create new subscription if needed */
    if (!sub && expires > 0) {
        sub = create_subscription(profile, nh, sip);
        if (!sub) {
            ast_log(LOG_ERROR, "Failed to create subscription\n");
            if (response_msg) {
                nua_respond(nh, SIP_500_INTERNAL_SERVER_ERROR,
                           NUTAG_WITH_THIS_MSG(response_msg),
                           TAG_END());
            } else {
                nua_respond(nh, SIP_500_INTERNAL_SERVER_ERROR, TAG_END());
            }
            return;
        }
        
        /* Handle NAT: Update contact if source IP differs from Contact */
        if (msg && sip->sip_contact) {
            char source_ip[INET6_ADDRSTRLEN];
            if (get_source_ip(msg, source_ip, sizeof(source_ip)) == 0) {
                const char *contact_host = sip->sip_contact->m_url->url_host;
                if (contact_host && strcmp(contact_host, source_ip) != 0) {
                    /* Source IP differs from Contact - likely NAT */
                    ast_log(LOG_DEBUG, "NAT detected: Contact=%s, Source=%s\n", 
                            contact_host, source_ip);
                    
                    /* Update NUA handle to use the real source IP */
                    char real_contact[512];
                    snprintf(real_contact, sizeof(real_contact), 
                             "sip:%s@%s:%d",
                             sip->sip_contact->m_url->url_user ? sip->sip_contact->m_url->url_user : from_user,
                             source_ip,
                             sip->sip_contact->m_url->url_port ? 
                                atoi(sip->sip_contact->m_url->url_port) : 5060);
                    
                    /* Store the real contact for NOTIFY */
                    ast_copy_string(sub->watcher_contact, real_contact, sizeof(sub->watcher_contact));
                } else {
                    /* No NAT - use the Contact as-is */
                    const char *contact_str = url_as_string(NULL, sip->sip_contact->m_url);
                    if (contact_str) {
                        ast_copy_string(sub->watcher_contact, contact_str, sizeof(sub->watcher_contact));
                    }
                }
            }
        } else if (sip->sip_contact) {
            /* No source IP available - use Contact as-is */
            const char *contact_str = url_as_string(NULL, sip->sip_contact->m_url);
            if (contact_str) {
                ast_copy_string(sub->watcher_contact, contact_str, sizeof(sub->watcher_contact));
            }
        }
        
        /* Set subscription details */
        ast_copy_string(sub->event_package, event, sizeof(sub->event_package));
        sub->expires = time(NULL) + expires;
        sub->refresh_interval = expires;
        
        /* Store URIs */
        if (sip->sip_from) {
            const char *from_str = url_as_string(NULL, sip->sip_from->a_url);
            if (from_str) {
                ast_copy_string(sub->watcher_uri, from_str, sizeof(sub->watcher_uri));
            }
        }
        
        if (sip->sip_to) {
            const char *to_str = url_as_string(NULL, sip->sip_to->a_url);
            if (to_str) {
                ast_copy_string(sub->presentity_uri, to_str, sizeof(sub->presentity_uri));
            }
        }
        
        /* Store monitored extension */
        if (to_user) {
            ast_copy_string(sub->monitored_exten, to_user, sizeof(sub->monitored_exten));
        }
        
        /* Add to container */
        ao2_link(subscriptions, sub);
        
        /* Subscribe to device state changes */
        if (strcasecmp(event, "dialog") == 0 && to_user) {
            /* TODO: Subscribe to device state stasis topic */
            ast_log(LOG_DEBUG, "Would subscribe to device state for SIP/%s\n", to_user);
        }
    }
    
    /* Send 202 Accepted response */
    char expires_str[16];
    snprintf(expires_str, sizeof(expires_str), "%d", expires);
    
    ast_log(LOG_DEBUG, "Sending 202 Accepted for SUBSCRIBE\n");
    
    if (response_msg) {
        nua_respond(nh, SIP_202_ACCEPTED,
                   NUTAG_WITH_THIS_MSG(response_msg),
                   SIPTAG_EXPIRES_STR(expires_str),
                   TAG_END());
    } else {
        nua_respond(nh, SIP_202_ACCEPTED,
                   SIPTAG_EXPIRES_STR(expires_str),
                   TAG_END());
    }
    
    /* Send initial NOTIFY if new subscription */
    if (sub && sub->state == SUB_STATE_PENDING) {
        sub->state = SUB_STATE_ACTIVE;
        
        if (strcasecmp(event, "dialog") == 0 && to_user) {
            /* Get current device state */
            char device[64];
            snprintf(device, sizeof(device), "SIP/%s", to_user);
            enum ast_device_state state = ast_device_state(device);
            sub->last_device_state = state;
            
            /* Build and send NOTIFY */
            const char *dialog_state = device_state_to_dialog_state(state);
            char *xml_body = build_dialog_info_xml(sub, dialog_state);
            if (xml_body) {
                send_notify(sub, "active", xml_body);
                ast_free(xml_body);
            }
        } else {
            /* Send empty NOTIFY for other event types */
            send_notify(sub, "active", NULL);
        }
    }
    
    if (sub) {
        ao2_ref(sub, -1);
    }
    
    ast_debug(2, "=== SUBSCRIBE REQUEST COMPLETED ===\n");
}

/* Subscription destructor */
static void subscription_destructor(void *obj)
{
    struct sip_subscription *sub = obj;
    
    if (sub->nh) {
        /* NUA handle will be destroyed by Sofia-SIP */
        sub->nh = NULL;
    }
}

/* Hash function for subscriptions */
static int subscription_hash_fn(const void *obj, int flags)
{
    const struct sip_subscription *sub;
    const char *key;
    
    switch (flags & OBJ_SEARCH_MASK) {
    case OBJ_SEARCH_KEY:
        key = obj;
        break;
    case OBJ_SEARCH_OBJECT:
        sub = obj;
        key = sub->call_id;
        break;
    default:
        ast_assert(0);
        return 0;
    }
    
    return ast_str_case_hash(key);
}

/* Comparison function for subscriptions */
static int subscription_cmp_fn(void *obj, void *arg, int flags)
{
    const struct sip_subscription *sub1 = obj;
    const struct sip_subscription *sub2 = arg;
    const char *call_id = arg;
    int cmp;
    
    switch (flags & OBJ_SEARCH_MASK) {
    case OBJ_SEARCH_OBJECT:
        cmp = strcasecmp(sub1->call_id, sub2->call_id);
        if (cmp == 0) {
            cmp = strcasecmp(sub1->from_tag, sub2->from_tag);
        }
        break;
    case OBJ_SEARCH_KEY:
        cmp = strcasecmp(sub1->call_id, call_id);
        break;
    default:
        cmp = 0;
        break;
    }
    
    return cmp ? 0 : CMP_MATCH;
}

/* Find existing subscription */
static struct sip_subscription *find_subscription(const char *call_id, const char *from_tag)
{
    struct sip_subscription tmp = {0};
    
    ast_copy_string(tmp.call_id, call_id, sizeof(tmp.call_id));
    if (from_tag) {
        ast_copy_string(tmp.from_tag, from_tag, sizeof(tmp.from_tag));
    }
    
    return ao2_find(subscriptions, &tmp, OBJ_SEARCH_OBJECT);
}

/* Create new subscription */
static struct sip_subscription *create_subscription(struct sip_profile *profile, 
                                                   nua_handle_t *nh, sip_t const *sip)
{
    struct sip_subscription *sub;
    
    sub = ao2_alloc(sizeof(*sub), subscription_destructor);
    if (!sub) {
        return NULL;
    }
    
    /* Generate unique ID */
    snprintf(sub->id, sizeof(sub->id), "%s-%ld-%ld", 
             profile->name, (long)time(NULL), ast_random());
    
    /* Extract Call-ID and tags */
    if (sip->sip_call_id && sip->sip_call_id->i_id) {
        ast_copy_string(sub->call_id, sip->sip_call_id->i_id, sizeof(sub->call_id));
    }
    
    if (sip->sip_from && sip->sip_from->a_tag) {
        ast_copy_string(sub->from_tag, sip->sip_from->a_tag, sizeof(sub->from_tag));
    }
    
    if (sip->sip_to && sip->sip_to->a_tag) {
        ast_copy_string(sub->to_tag, sip->sip_to->a_tag, sizeof(sub->to_tag));
    }
    
    /* Extract Accept header */
    if (sip->sip_accept) {
        sip_accept_t *accept = sip->sip_accept;
        char *ptr = sub->accept;
        size_t remaining = sizeof(sub->accept);
        
        while (accept && remaining > 1) {
            const char *type = accept->ac_type;
            const char *subtype = accept->ac_subtype;
            
            if (type && subtype) {
                int written = snprintf(ptr, remaining, "%s%s/%s",
                                     ptr == sub->accept ? "" : ", ",
                                     type, subtype);
                if (written > 0 && written < remaining) {
                    ptr += written;
                    remaining -= written;
                }
            }
            accept = accept->ac_next;
        }
    }
    
    /* Initialize state */
    sub->created = time(NULL);
    sub->state = SUB_STATE_PENDING;
    sub->version = 0;
    sub->nh = nh;
    sub->profile = profile;
    sub->last_device_state = AST_DEVICE_UNKNOWN;
    
    return sub;
}

/* Send NOTIFY message */
static void send_notify(struct sip_subscription *sub, const char *state_str, const char *xml_body)
{
    char subscription_state[256];
    
    if (!sub || !sub->nh) {
        return;
    }
    
    /* Build Subscription-State header */
    if (sub->state == SUB_STATE_TERMINATED) {
        snprintf(subscription_state, sizeof(subscription_state),
                 "%s;reason=timeout", state_str);
    } else {
        int remaining = sub->expires - time(NULL);
        if (remaining < 0) remaining = 0;
        snprintf(subscription_state, sizeof(subscription_state),
                 "%s;expires=%d", state_str, remaining);
    }
    
    sub->version++;
    
    ast_log(LOG_DEBUG, "Sending NOTIFY for %s event (state: %s, version: %d)\n",
            sub->event_package, state_str, sub->version);
    
    /* If we detected NAT and have a corrected contact, use it */
    if (!ast_strlen_zero(sub->watcher_contact)) {
        ast_log(LOG_DEBUG, "Using NAT-corrected contact: %s\n", sub->watcher_contact);
        /* Send NOTIFY */
        if (xml_body) {
            nua_notify(sub->nh,
                      NUTAG_URL(sub->watcher_contact),
                      SIPTAG_EVENT_STR(sub->event_package),
                      SIPTAG_SUBSCRIPTION_STATE_STR(subscription_state),
                      SIPTAG_CONTENT_TYPE_STR("application/dialog-info+xml"),
                      SIPTAG_PAYLOAD_STR(xml_body),
                      TAG_END());
        } else {
            nua_notify(sub->nh,
                      NUTAG_URL(sub->watcher_contact),
                      SIPTAG_EVENT_STR(sub->event_package),
                      SIPTAG_SUBSCRIPTION_STATE_STR(subscription_state),
                      TAG_END());
        }
    } else {
        /* Send NOTIFY normally */
        if (xml_body) {
            nua_notify(sub->nh,
                      SIPTAG_EVENT_STR(sub->event_package),
                      SIPTAG_SUBSCRIPTION_STATE_STR(subscription_state),
                      SIPTAG_CONTENT_TYPE_STR("application/dialog-info+xml"),
                      SIPTAG_PAYLOAD_STR(xml_body),
                      TAG_END());
        } else {
            nua_notify(sub->nh,
                      SIPTAG_EVENT_STR(sub->event_package),
                      SIPTAG_SUBSCRIPTION_STATE_STR(subscription_state),
                      TAG_END());
        }
    }
}

/* Convert device state to dialog state */
static const char *device_state_to_dialog_state(enum ast_device_state state)
{
    switch (state) {
    case AST_DEVICE_NOT_INUSE:
    case AST_DEVICE_UNKNOWN:
    case AST_DEVICE_INVALID:
    case AST_DEVICE_UNAVAILABLE:
        return "terminated";
        
    case AST_DEVICE_INUSE:
    case AST_DEVICE_BUSY:
        return "confirmed";
        
    case AST_DEVICE_RINGING:
    case AST_DEVICE_RINGINUSE:
        return "early";
        
    case AST_DEVICE_ONHOLD:
        return "confirmed";
        
    default:
        return "terminated";
    }
}

/* Build dialog-info XML body */
static char *build_dialog_info_xml(struct sip_subscription *sub, const char *dialog_state)
{
    char *xml;
    int len;
    char entity[256];
    
    /* Extract entity from presentity URI */
    ast_copy_string(entity, sub->presentity_uri, sizeof(entity));
    
    /* Allocate buffer */
    len = 1024;
    xml = ast_malloc(len);
    if (!xml) {
        return NULL;
    }
    
    /* Build XML */
    snprintf(xml, len,
             "<?xml version=\"1.0\"?>\r\n"
             "<dialog-info xmlns=\"urn:ietf:params:xml:ns:dialog-info\" "
             "version=\"%d\" state=\"full\" entity=\"%s\">\r\n"
             "  <dialog id=\"%s\" call-id=\"%s\">\r\n"
             "    <state>%s</state>\r\n"
             "  </dialog>\r\n"
             "</dialog-info>\r\n",
             sub->version,
             entity,
             sub->monitored_exten,
             sub->call_id,
             dialog_state);
    
    return xml;
}

/* TODO: Implement these functions */
#if 0
static void subscription_timeout_callback(const void *data)
{
    /* Handle subscription timeout */
}

static void device_state_cb(void *data, struct stasis_subscription *sub, struct stasis_message *msg)
{
    /* Handle device state changes and send NOTIFYs */
}
#endif

/* Clean up expired subscriptions */
void sip_subscription_cleanup(void)
{
    struct ao2_iterator iter;
    struct sip_subscription *sub;
    time_t now = time(NULL);
    
    if (!subscriptions) {
        return;
    }
    
    iter = ao2_iterator_init(subscriptions, 0);
    while ((sub = ao2_iterator_next(&iter))) {
        if (sub->expires <= now) {
            ast_log(LOG_DEBUG, "Subscription %s expired\n", sub->id);
            sub->state = SUB_STATE_TERMINATED;
            send_notify(sub, "terminated", NULL);
            ao2_unlink(subscriptions, sub);
        }
        ao2_ref(sub, -1);
    }
    ao2_iterator_destroy(&iter);
}

/* Show active subscriptions for CLI */
void sip_subscription_show_cli(int fd)
{
    struct ao2_iterator iter;
    struct sip_subscription *sub;
    time_t now = time(NULL);
    int count = 0;
    
    if (!subscriptions) {
        ast_cli(fd, "Subscription subsystem not initialized\n");
        return;
    }
    
    ast_cli(fd, "\nActive Subscriptions\n");
    ast_cli(fd, "================================================================================\n");
    ast_cli(fd, "%-15s %-10s %-20s %-20s %-10s %-8s %s\n",
            "Event", "State", "Watcher", "Presentity", "Expires", "Version", "Call-ID");
    ast_cli(fd, "%-15s %-10s %-20s %-20s %-10s %-8s %s\n",
            "---------------", "----------", "--------------------", "--------------------", 
            "----------", "--------", "--------------------------------");
    
    iter = ao2_iterator_init(subscriptions, 0);
    while ((sub = ao2_iterator_next(&iter))) {
        char state_str[16];
        char expires_str[16];
        char watcher[64];
        char presentity[64];
        
        /* Extract username from URIs */
        ast_copy_string(watcher, sub->watcher_uri, sizeof(watcher));
        ast_copy_string(presentity, sub->presentity_uri, sizeof(presentity));
        
        /* Simplify URIs to just user@host */
        char *p;
        if ((p = strstr(watcher, "sip:"))) {
            memmove(watcher, p + 4, strlen(p + 4) + 1);
        }
        if ((p = strchr(watcher, '>'))) {
            *p = '\0';
        }
        if ((p = strstr(presentity, "sip:"))) {
            memmove(presentity, p + 4, strlen(p + 4) + 1);
        }
        if ((p = strchr(presentity, '>'))) {
            *p = '\0';
        }
        
        /* State string */
        switch (sub->state) {
        case SUB_STATE_PENDING:
            strcpy(state_str, "pending");
            break;
        case SUB_STATE_ACTIVE:
            strcpy(state_str, "active");
            break;
        case SUB_STATE_TERMINATED:
            strcpy(state_str, "terminated");
            break;
        default:
            strcpy(state_str, "unknown");
            break;
        }
        
        /* Expires string */
        if (sub->expires > now) {
            int remaining = sub->expires - now;
            if (remaining > 3600) {
                snprintf(expires_str, sizeof(expires_str), "%dh%dm", 
                         remaining / 3600, (remaining % 3600) / 60);
            } else if (remaining > 60) {
                snprintf(expires_str, sizeof(expires_str), "%dm%ds", 
                         remaining / 60, remaining % 60);
            } else {
                snprintf(expires_str, sizeof(expires_str), "%ds", remaining);
            }
        } else {
            strcpy(expires_str, "expired");
        }
        
        ast_cli(fd, "%-15s %-10s %-20.20s %-20.20s %-10s %-8d %.32s\n",
                sub->event_package,
                state_str,
                watcher,
                presentity,
                expires_str,
                sub->version,
                sub->call_id);
        
        count++;
        ao2_ref(sub, -1);
    }
    ao2_iterator_destroy(&iter);
    
    ast_cli(fd, "\nTotal: %d active subscription%s\n", count, count != 1 ? "s" : "");
}

/* Get subscription statistics */
void sip_subscription_get_stats(int *total, int *active, int *pending, int *terminated)
{
    struct ao2_iterator iter;
    struct sip_subscription *sub;
    
    *total = *active = *pending = *terminated = 0;
    
    if (!subscriptions) {
        return;
    }
    
    iter = ao2_iterator_init(subscriptions, 0);
    while ((sub = ao2_iterator_next(&iter))) {
        (*total)++;
        
        switch (sub->state) {
        case SUB_STATE_ACTIVE:
            (*active)++;
            break;
        case SUB_STATE_PENDING:
            (*pending)++;
            break;
        case SUB_STATE_TERMINATED:
            (*terminated)++;
            break;
        }
        
        ao2_ref(sub, -1);
    }
    ao2_iterator_destroy(&iter);
}