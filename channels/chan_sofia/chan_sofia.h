/*
 * GABpbx -- An open source telephony toolkit.
 *
 * Copyright (C) 2024, GABpbx Development Team
 *
 * chan_sofia.h - Sofia-SIP Channel Driver Header
 *
 * See http://www.gabpbx.org for more information about
 * the GABpbx project.
 */

#ifndef CHAN_SOFIA_H
#define CHAN_SOFIA_H

#include "gabpbx.h"
#include <sofia-sip/su.h>
#include <sofia-sip/nua.h>
#include <sofia-sip/sip_status.h>
#include <sofia-sip/soa.h>

/* Configuration constants */
#define SOFIA_CONFIG "sofia.conf"
#define SOFIA_MAX_PROFILES 10
#define SOFIA_RTP_PORT_START 10000
#define SOFIA_RTP_PORT_END 20000
#define SOFIA_MAX_REG_PER_USER 10
#define SOFIA_PRESENCE_DB "sofia_presence"
#define SOFIA_REGISTRATION_DB "sofia_registrations"

/* Endpoint types */
enum sofia_endpoint_type {
	SOFIA_ENDPOINT_TYPE_USER = 0,
	SOFIA_ENDPOINT_TYPE_TRUNK,
	SOFIA_ENDPOINT_TYPE_GATEWAY,
};

/* Registration states */
enum sofia_reg_state {
	SOFIA_REG_STATE_UNREGISTERED = 0,
	SOFIA_REG_STATE_TRYING,
	SOFIA_REG_STATE_REGISTERED,
	SOFIA_REG_STATE_FAILED,
};

/* Presence states */
enum sofia_presence_state {
	SOFIA_PRESENCE_UNKNOWN = 0,
	SOFIA_PRESENCE_AVAILABLE,
	SOFIA_PRESENCE_BUSY,
	SOFIA_PRESENCE_AWAY,
	SOFIA_PRESENCE_DND,
	SOFIA_PRESENCE_OFFLINE,
};

/* Forward declarations */
struct sofia_profile;
struct sofia_endpoint;
struct sofia_trunk;
struct sofia_registration;
struct sofia_presence;
struct sofia_pvt;

/* Registration structure - supports multiple registrations per user */
struct sofia_registration {
	AST_LIST_ENTRY(sofia_registration) list;
	char username[80];
	char contact[256];
	char user_agent[256];
	char call_id[256];
	time_t expires;
	time_t registered;
	struct sockaddr_in addr;
	enum sofia_reg_state state;
	int cseq;
	struct sofia_endpoint *endpoint;
};

/* Presence/BLF structure */
struct sofia_presence {
	AST_LIST_ENTRY(sofia_presence) list;
	char exten[80];
	char context[AST_MAX_CONTEXT];
	enum sofia_presence_state state;
	char state_text[80];
	AST_LIST_HEAD_NOLOCK(, sofia_subscription) subscriptions;
};

/* Subscription structure for presence */
struct sofia_subscription {
	AST_LIST_ENTRY(sofia_subscription) list;
	nua_handle_t *nh;
	char from[256];
	char to[256];
	char call_id[256];
	time_t expires;
};

/* Endpoint structure - user devices */
struct sofia_endpoint {
	AST_LIST_ENTRY(sofia_endpoint) list;
	char name[80];
	char username[80];
	char secret[80];
	char md5secret[33];
	char context[AST_MAX_CONTEXT];
	char callerid[256];
	char mailbox[80];
	struct sofia_profile *profile;
	
	/* Registration support */
	int max_registrations;
	AST_LIST_HEAD_NOLOCK(, sofia_registration) registrations;
	
	/* Capabilities */
	struct ast_format_cap *caps;
	char dtmfmode[20];
	
	/* OPTIONS qualify */
	int qualify;
	int qualify_frequency;
	time_t last_qualify;
	int qualify_status;
	
	/* Limits */
	int call_limit;
	int busy_level;
	int current_calls;
	
	/* Features */
	unsigned int allowsubscribe:1;
	unsigned int allowpresence:1;
	unsigned int sendrpid:1;
	unsigned int trustrpid:1;
	unsigned int send_options:1;
	unsigned int accept_messages:1;
};

/* Trunk structure - IP-based connections */
struct sofia_trunk {
	AST_LIST_ENTRY(sofia_trunk) list;
	char name[80];
	char host[256];
	int port;
	char username[80];
	char secret[80];
	char context[AST_MAX_CONTEXT];
	char callerid[256];
	struct sofia_profile *profile;
	
	/* Authentication */
	char realm[256];
	char from_user[80];
	char from_domain[256];
	
	/* Registration */
	int register_trunk;
	int registration_expire;
	nua_handle_t *reg_handle;
	enum sofia_reg_state reg_state;
	
	/* OPTIONS monitoring */
	int monitor;
	int monitor_frequency;
	time_t last_monitor;
	int monitor_status;
	
	/* Capabilities */
	struct ast_format_cap *caps;
	char dtmfmode[20];
	
	/* IP ACL */
	struct ast_acl_list *acl;
};

/* Profile structure - enhanced with new features */
struct sofia_profile {
	AST_LIST_ENTRY(sofia_profile) list;
	char name[80];
	nua_t *nua;
	char bindip[80];
	int bindport;
	char context[AST_MAX_CONTEXT];
	int enabled;
	ast_mutex_t lock;
	
	/* Network settings */
	char external_ip[80];
	char stun_server[256];
	char local_net[256];
	
	/* Authentication */
	/* unsigned int auth_calls:1; -- Removed: auth now per endpoint */
	/* unsigned int auth_registrations:1; -- Removed: auth now per endpoint */
	unsigned int auth_messages:1;
	unsigned int accept_blind_reg:1;
	
	/* Registration settings */
	int max_registrations;
	int registration_timeout;
	int registration_min_expires;
	int registration_max_expires;
	
	/* Features */
	unsigned int enable_presence:1;
	unsigned int enable_messaging:1;
	unsigned int enable_options_ping:1;
	
	/* Lists */
	AST_LIST_HEAD_NOLOCK(, sofia_endpoint) endpoints;
	AST_LIST_HEAD_NOLOCK(, sofia_trunk) trunks;
	AST_LIST_HEAD_NOLOCK(, sofia_registration) registrations;
	AST_LIST_HEAD_NOLOCK(, sofia_presence) presences;
	
	/* Database */
	struct ast_db_entry *db;
};

/* Private channel structure */
struct sofia_pvt {
	ast_mutex_t lock;
	struct ast_channel *owner;
	struct sofia_profile *profile;
	nua_handle_t *nh;
	char exten[AST_MAX_EXTENSION];
	char context[AST_MAX_CONTEXT];
	struct ast_format_cap *caps;
	struct ast_format_cap *jointcaps;
	struct ast_rtp_instance *rtp;
	char remote_sdp[2048];
	char local_sdp[2048];
	
	/* Endpoint/Trunk reference */
	struct sofia_endpoint *endpoint;
	struct sofia_trunk *trunk;
	
	/* Call info */
	char from_uri[512];
	char to_uri[512];
	char contact_uri[512];
	
	/* Features */
	unsigned int destroyed:1;
	unsigned int is_message:1;
	unsigned int is_options:1;
};

/* Function prototypes */

/* Registration functions */
int sofia_register_endpoint(struct sofia_profile *profile, struct sofia_endpoint *endpoint, 
                           const char *contact, const char *user_agent, struct sockaddr_in *addr);
void sofia_unregister_endpoint(struct sofia_endpoint *endpoint, const char *contact);
void sofia_expire_registrations(struct sofia_profile *profile);
struct sofia_registration *sofia_find_registration(struct sofia_endpoint *endpoint, const char *contact);

/* OPTIONS functions */
int sofia_send_options(struct sofia_profile *profile, const char *uri);
void sofia_qualify_endpoint(struct sofia_endpoint *endpoint);
void sofia_qualify_trunk(struct sofia_trunk *trunk);
void sofia_schedule_qualify(struct sofia_profile *profile);

/* MESSAGE functions */
int sofia_send_message(struct sofia_profile *profile, const char *from, const char *to, const char *body);
void sofia_handle_message(struct sofia_profile *profile, nua_handle_t *nh, sip_t const *sip);

/* Presence functions */
void sofia_update_presence(struct sofia_profile *profile, const char *exten, const char *context, 
                          enum sofia_presence_state state, const char *state_text);
void sofia_handle_subscribe(struct sofia_profile *profile, nua_handle_t *nh, sip_t const *sip);
void sofia_send_notify(struct sofia_subscription *sub, enum sofia_presence_state state, const char *state_text);
void sofia_presence_cleanup(struct sofia_profile *profile);

/* Trunk functions */
struct sofia_trunk *sofia_find_trunk_by_host(struct sofia_profile *profile, const char *host, int port);
int sofia_register_trunk(struct sofia_trunk *trunk);
void sofia_unregister_trunk(struct sofia_trunk *trunk);

/* Database functions */
int sofia_db_init(void);
int sofia_db_put_registration(struct sofia_registration *reg);
int sofia_db_del_registration(const char *username, const char *contact);
int sofia_db_get_registrations(struct sofia_endpoint *endpoint);
int sofia_db_put_presence(const char *exten, const char *context, enum sofia_presence_state state);
int sofia_db_get_presence(const char *exten, const char *context);

#endif /* CHAN_SOFIA_H */