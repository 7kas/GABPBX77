/*
 * GABpbx -- An open source telephony toolkit.
 *
 * Copyright (C) 2024, GABpbx Development Team
 *
 * sip_sofia.h - Sofia-SIP Channel Driver Header
 */

#ifndef _SIP_SOFIA_H
#define _SIP_SOFIA_H

#include "gabpbx.h"
#include "gabpbx/linkedlists.h"
#include "gabpbx/lock.h"
#include "gabpbx/channel.h"
#include "gabpbx/format_cap.h"

/* Forward declarations to avoid Sofia-SIP dependency in headers */
typedef struct su_root_s su_root_t;
typedef struct nua_s nua_t;
typedef struct nua_handle_s nua_handle_t;
typedef struct sip_s sip_t;

/* Forward declaration of sofia_pvt */
struct sofia_pvt;

/* Configuration constants */
#define SOFIA_CONFIG "sofia.conf"
#define SOFIA_MAX_PROFILES 10
#define SOFIA_MAX_REG_PER_USER 10
#define SOFIA_HASH_SIZE 1543          /* Prime number for hash table */
#define SOFIA_MAX_SUBSCRIPTIONS 5000  /* Max concurrent BLF subscriptions */
#define SOFIA_QUALIFY_DEFAULT 60000   /* Default qualify frequency (60s) */
#define SOFIA_MAX_THREADS 50          /* Worker threads for high load */

/* Blacklist constants */
#define SOFIA_BLACKLIST_SIZE 16384    /* Hash table size for blacklist (power of 2) */
#define SOFIA_BLACKLIST_MAX_IPS 10000 /* Maximum IPs in blacklist */
#define SOFIA_DEFAULT_FAIL_THRESHOLD 5 /* Default auth failures before ban */
#define SOFIA_DEFAULT_BAN_TIME 3600   /* Default ban duration (1 hour) */

/* Authentication cache constants */
#define SOFIA_AUTH_CACHE_SIZE 4096    /* Hash table size for auth cache */
#define SOFIA_AUTH_CACHE_TTL 300      /* Default cache TTL (5 minutes) */

/* Media state machine */
enum sofia_media_state {
	MEDIA_STATE_NONE = 0,
	MEDIA_STATE_OFFERED,    /* Received offer, need to answer */
	MEDIA_STATE_ANSWERED,   /* Sent answer, waiting for ACK */
	MEDIA_STATE_ACTIVE,     /* Media flowing */
	MEDIA_STATE_HOLD,       /* On hold */
	MEDIA_STATE_ERROR       /* Media negotiation failed */
};

/* Blacklist entry structure */
struct sip_blacklist_entry {
	char ip_addr[INET6_ADDRSTRLEN];  /* IP address string (IPv4 or IPv6) */
	time_t banned_until;              /* Ban expiration time */
	int fail_count;                   /* Number of auth failures */
	time_t last_attempt;              /* Last attempt timestamp */
	char last_user[80];               /* Last attempted username */
	char reason[256];                 /* Ban reason */
	unsigned int is_banned:1;         /* Current ban status flag */
};

/* Authentication cache entry */
struct sip_auth_cache_entry {
	char key[256];                    /* Key: username:realm:nonce:uri */
	char response[33];                /* Expected MD5 response */
	time_t expires;                   /* Cache expiration time */
	char ip_addr[INET6_ADDRSTRLEN];   /* Source IP for additional validation */
};

/* Profile structure */
struct sip_profile {
	AST_RWLIST_ENTRY(sip_profile) list;
	char name[80];
	nua_t *nua;
	char bindip[80];
	int bindport;
	char context[AST_MAX_CONTEXT];
	int enabled;
	ast_mutex_t lock;
	struct ast_sched_context *sched;  /* Scheduler context for timers */
	
	/* Transport settings */
	char transport_protocol[32];   /* Transport protocol: UDP, TCP, TLS, or combinations like UDP,TCP */
	int tls_bindport;             /* TLS port (default: bindport + 1) */
	
	/* Features */
	/* unsigned int auth_calls:1; -- Removed: auth now per endpoint */
	/* unsigned int auth_registrations:1; -- Removed: auth now per endpoint */
	unsigned int enable_options:1;
	unsigned int enable_messaging:1;
	unsigned int enable_presence:1;
	
	/* Registration settings */
	int max_contacts_global;       /* Global default max contacts per peer */
	int registration_timeout;
	int registration_refresh_percent; /* Refresh when X% of time remains (default: 90) */
	unsigned int ring_all_except_inuse_global:1;  /* Global ring behavior */
	
	/* Blacklist settings */
	int blacklist_enabled;         /* Enable IP blacklisting */
	int blacklist_threshold;       /* Auth failures before ban */
	int blacklist_duration;        /* Ban duration in seconds */
	
	/* Auth cache settings */
	int auth_cache_enabled;        /* Enable authentication caching */
	
	/* Nonce cache for challenges */
	char cached_nonce[256];        /* Cached nonce value */
	time_t nonce_generated;        /* When nonce was generated */
	int nonce_ttl;                 /* Nonce TTL in seconds (default: 30) */
	int auth_cache_ttl;           /* Cache TTL in seconds */
	
	/* OPTIONS keepalive settings */
	int enable_options_keepalive;  /* Enable OPTIONS keepalive */
	int keepalive_interval;        /* Interval in seconds */
	char from_uri[256];            /* From URI for OPTIONS */
	
	/* Session Timer settings (RFC 4028) */
	int session_timers_enabled;    /* Enable session timers */
	int session_min_se;            /* Minimum session expiration (default: 1800) */
	int session_default_se;        /* Default session expiration if not specified */
	
	/* Event queue settings */
	int event_queue_size;          /* Max events in queue (default: 1000) */
	int event_queue_workers;       /* Number of worker threads (default: CPU/2+1) */
	
	/* NAT settings */
	unsigned int nat_mode:1;       /* Enable NAT detection and handling */
	char externip[80];             /* External IP for NAT traversal */
	char localnet[256];            /* Local network definitions (multiple) */
};

/* Endpoint structure */
struct sip_endpoint {
	char name[80];
	char username[80];
	char secret[80];
	char context[AST_MAX_CONTEXT];
	struct sip_profile *profile;
	
	/* User-Agent authentication */
	char allowed_useragents[3][256]; /* Up to 3 allowed User-Agent prefixes */
	int num_useragents;              /* Number of configured User-Agent patterns */
	unsigned int require_useragent:1; /* Require specific User-Agent for auth */
	
       /* Multiple registrations support */
       int max_contacts;        /* Maximum simultaneous registrations (default: 1) */
       int registration_count;   /* Current active registrations */

       /* Capabilities */
       struct ast_format_cap *caps;
       char dtmfmode[20];
	
	/* Authentication type */
	enum {
		AUTH_TYPE_REGISTER = 0,    /* Default: requires registration */
		AUTH_TYPE_IP = 1           /* Trunk: validated by IP/port */
	} auth_type;
	
	/* Trunk IP validation (when auth_type = AUTH_TYPE_IP) */
	char host[128];                    /* Allowed source IP address */
	int port;                          /* Allowed source port (0 = any) */
	
	/* Features */
	unsigned int can_send_message:1;
	unsigned int can_subscribe:1;
	unsigned int send_options:1;
	unsigned int ring_all_except_inuse:1;  /* Skip ringing devices with active calls */
	
	/* OPTIONS keepalive */
	unsigned int keepalive_enabled:1;  /* Enable keepalive for this endpoint */
	time_t last_options;               /* Last OPTIONS timestamp */
};

/* Registration entry */
struct sip_registration {
	struct sip_endpoint *endpoint;
	char aor[256];           /* Address of record (user@domain) */
	char contact[512];       /* Full contact URI */
	char call_id[256];       /* Call-ID from REGISTER */
	uint32_t cseq;          /* CSeq number */
	char user_agent[256];    /* User-Agent header */
	time_t registered;       /* Registration time */
	time_t expires;         /* Expiration time */
	struct sockaddr_in addr; /* Source address - using sockaddr_in for now */
	char received[128];      /* Received parameter for NAT */
	char via_branch[128];    /* Via branch parameter */
	char path[2048];         /* Path header value (RFC 3327) - multiple URIs */
	int refresh_sched_id;    /* Scheduler ID for refresh timer */
};

/* Trunk structure */
struct sip_trunk {
	AST_RWLIST_ENTRY(sip_trunk) list;
	char name[80];
	char host[256];
	int port;
	char username[80];
	char secret[80];
	char context[AST_MAX_CONTEXT];
	struct sip_profile *profile;
	
	/* OPTIONS monitoring */
	unsigned int monitor:1;
	int monitor_frequency;
	time_t last_monitor;
	int status; /* 0=unknown, 1=up, 2=down */
};

/* Private structure */
struct sip_pvt {
	ast_mutex_t lock;
	struct ast_channel *owner;
	struct sip_profile *profile;
	nua_handle_t *nh;
	struct sip_endpoint *endpoint;
	struct sip_trunk *trunk;
	
	/* Call info */
	char exten[AST_MAX_EXTENSION];
	char context[AST_MAX_CONTEXT];
	
	/* Media */
	struct ast_format_cap *caps;
	struct ast_format_cap *offered_caps;	/* Codecs offered by remote */
	struct ast_rtp_instance *rtp;
	struct ast_sockaddr remote_addr;
	unsigned int remote_addr_set:1;
	
	/* Media state */
	enum sofia_media_state media_state;
	unsigned int rtp_dtmf:1;		/* RFC 2833 DTMF supported */
	int rtp_dtmf_pt;			/* DTMF payload type */
	
	/* Flags */
	unsigned int destroyed:1;
	unsigned int is_message:1;
	unsigned int is_options:1;
};

/* Function declarations */
struct sip_profile *sip_profile_find(const char *name);
struct sip_endpoint *sip_endpoint_find(struct sip_profile *profile, const char *name);
struct sip_trunk *sip_trunk_find(struct sip_profile *profile, const char *host);

int sip_register_endpoint(struct sip_endpoint *endpoint, const char *contact, const char *user_agent, struct sockaddr_in *addr);
void sip_unregister_endpoint(struct sip_endpoint *endpoint, const char *contact);

int sip_send_options(struct sip_profile *profile, const char *uri);
int sip_send_message(struct sip_profile *profile, const char *from, const char *to, const char *text);

void sip_handle_registration(struct sip_profile *profile, nua_handle_t *nh, const sip_t *sip);
void sip_handle_options(struct sip_profile *profile, nua_handle_t *nh, const sip_t *sip);
void sip_handle_message(struct sip_profile *profile, nua_handle_t *nh, const sip_t *sip);
void sip_handle_subscribe(struct sip_profile *profile, nua_handle_t *nh, const sip_t *sip);

/* Configuration functions */
int sip_config_load(int reload);
void sip_config_destroy(void);

/* Media handling functions */
int sofia_parse_sdp_offer(struct sofia_pvt *pvt, const char *sdp_str, size_t sdp_len);
int sofia_negotiate_media(struct sofia_pvt *pvt);
int sofia_build_sdp_answer(struct sofia_pvt *pvt, struct ast_sockaddr *local_addr);
int sofia_activate_rtp(struct sofia_pvt *pvt);
int sofia_media_hold(struct sofia_pvt *pvt);
int sofia_media_unhold(struct sofia_pvt *pvt);

/* Global lists - defined in sip_config.c */
AST_RWLIST_HEAD(sip_profile_list, sip_profile);
AST_RWLIST_HEAD(sip_trunk_list, sip_trunk);

extern struct sip_profile_list profiles;
extern struct ao2_container *endpoints;  /* Hash table for O(1) lookups */
extern struct sip_trunk_list trunks;
extern struct ao2_container *blacklist;  /* Global IP blacklist hash table */
extern struct ao2_container *auth_cache; /* Global auth cache hash table */

/* Blacklist management functions */
int sip_blacklist_check(const char *ip_addr);
void sip_blacklist_add_failure(const char *ip_addr, const char *username, const char *reason);
void sip_blacklist_reset_failures(const char *ip_addr);
void sip_blacklist_ban(const char *ip_addr, int duration, const char *reason);
void sip_blacklist_unban(const char *ip_addr);
void sip_blacklist_cleanup(void);
int sip_blacklist_init(void);
void sip_blacklist_destroy(void);

/* Path header support (RFC 3327) */
char *sip_path_to_route(const char *path, su_home_t *home);

/* Authentication cache functions */
int sip_auth_cache_init(void);
void sip_auth_cache_destroy(void);
int sip_auth_cache_check(const char *username, const char *realm, const char *nonce, 
                        const char *uri, const char *response, const char *ip_addr);
void sip_auth_cache_store(const char *username, const char *realm, const char *nonce,
                         const char *uri, const char *response, const char *ip_addr, int ttl);
void sip_auth_cache_cleanup(void);

/* Async Event Queue System */
#define SOFIA_EVENT_QUEUE_SIZE 1000
#define SOFIA_MAX_WORKER_THREADS 16
#define SOFIA_MIN_WORKER_THREADS 1
#define SOFIA_QUEUE_HIGH_WATER 900  /* 90% of queue size */

/* Event queue entry */
struct sofia_queued_event {
	AST_LIST_ENTRY(sofia_queued_event) list;
	nua_saved_event_t saved[1];          /* Saved event data */
	nua_handle_t *nh;                    /* NUA handle */
	sip_t *sip;                          /* Parsed SIP message */
	struct sip_profile *profile;         /* Profile that received event */
	enum nua_event_e event;              /* Event type */
	msg_t *msg;                          /* Original message */
	su_home_t *home;                     /* Memory home for this event */
	time_t queued_time;                  /* When event was queued */
};

/* Event queue structure */
struct sofia_event_queue {
	AST_LIST_HEAD_NOLOCK(, sofia_queued_event) events;
	ast_mutex_t lock;
	ast_cond_t cond;
	int shutdown;
	int num_events;
	int max_events;
	int num_workers;
	int max_workers;
	int events_processed;
	int events_dropped;
	pthread_t *worker_threads;
};

/* Global event queue */
extern struct sofia_event_queue *sofia_queue;

/* Event queue functions */
int sofia_queue_init(void);
void sofia_queue_destroy(void);
int sofia_queue_event(struct sip_profile *profile, nua_handle_t *nh, 
                     enum nua_event_e event, int status, char const *phrase,
                     nua_t *nua, msg_t *msg, sip_t const *sip, 
                     nua_saved_event_t *saved);
struct sofia_queued_event *sofia_dequeue_event(void);
void sofia_free_queued_event(struct sofia_queued_event *event);
void *sofia_worker_thread(void *data);
int sofia_spawn_worker_thread(void);
void sofia_check_queue_depth(void);

#endif /* _SIP_SOFIA_H */