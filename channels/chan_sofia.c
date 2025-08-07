/*
 * GABpbx -- An open source telephony toolkit.
 *
 * Copyright (C) 2024, GABpbx Development Team
 *
 * chan_sofia - High-Performance Sofia-SIP Channel Driver
 *
 * See http://www.gabpbx.org for more information about
 * the GABpbx project.
 *
 * This channel driver supports both "SOFIA" and "SIP" technology names
 * since chan_sip doesn't exist in Asterisk 22.
 */

/*! \file
 *
 * \brief Sofia-SIP Channel Driver
 *
 * \author GABpbx Development Team
 *
 * \ingroup channel_drivers
 */

/*** MODULEINFO
	<support_level>extended</support_level>
	<defaultenabled>yes</defaultenabled>
	<depend>sofia</depend>
 ***/

#define AST_MODULE_SELF_SYM __internal_chan_sofia_self

#include "gabpbx.h"

#include "gabpbx/module.h"
#include "gabpbx/channel.h"
#include "gabpbx/config.h"
#include "gabpbx/logger.h"
#include "gabpbx/cli.h"
#include "gabpbx/causes.h"
#include "gabpbx/format_cap.h"
#include "gabpbx/format_cache.h"
#include "gabpbx/strings.h"
#include "gabpbx/rtp_engine.h"
#include "gabpbx/acl.h"
#include "gabpbx/manager.h"
#include "gabpbx/callerid.h"
#include "gabpbx/app.h"
#include "gabpbx/message.h"
#include "gabpbx/stasis.h"
#include "gabpbx/stasis_channels.h"
#include "gabpbx/devicestate.h"
#include "gabpbx/presencestate.h"
#include "gabpbx/netsock2.h"
#include "gabpbx/pbx.h"
#include "gabpbx/astobj2.h"
#include "gabpbx/sched.h"

/* Sofia-SIP includes */
#include <sofia-sip/su.h>
#include <sofia-sip/nua.h>
#include <sofia-sip/sip_status.h>
#include <sofia-sip/soa.h>
#include <sofia-sip/url.h>
#include <sofia-sip/sdp.h>
#include <sofia-sip/sip_header.h>
#include <sofia-sip/msg_addr.h>
#include <sofia-sip/su_md5.h>
#include <sofia-sip/sip_tag.h>

/* Include our header */
#include "chan_sofia/include/sip_sofia.h"

/* FreeSWITCH compatibility - for proper SUBSCRIBE response handling */
#ifndef NUTAG_WITH_THIS_MSG
#define NUTAG_WITH_THIS_MSG(msg) nutag_with, tag_ptr_v(msg)
#endif

static const char tdesc[] = "Sofia-SIP Channel Driver";

/* SIP User Agent string */
#define SIP_USER_AGENT "GABpbx/22.0.0"

/* Forward declarations */
struct sofia_pvt;

/* Helper function to get source IP from message */
static int get_source_ip(msg_t *msg, char *ip_addr, size_t ip_size);

/* Registration refresh callback */
static int registration_refresh_callback(const void *data);

/* Session timer refresh callback */
static int session_refresh_callback(const void *data);

/* ACK method functions */
void handle_ack_request(nua_handle_t *nh, struct sip_profile *profile,
	sip_t const *sip, tagi_t tags[]);
int sofia_send_ack(struct sofia_pvt *pvt, int response_code);
int sofia_ack_received(struct sofia_pvt *pvt);
void sofia_reset_ack_state(struct sofia_pvt *pvt);

/* BYE method functions */
void handle_bye_request(nua_handle_t *nh, struct sip_profile *profile,
	sip_t const *sip, tagi_t tags[], msg_t *msg);
int sofia_send_bye(struct sofia_pvt *pvt, int cause);
int sofia_should_send_bye(struct sofia_pvt *pvt);

/* CANCEL method functions */
void handle_cancel_request(nua_handle_t *nh, struct sip_profile *profile,
	sip_t const *sip, tagi_t tags[]);
int sofia_send_cancel(struct sofia_pvt *pvt);
int sofia_should_send_cancel(struct sofia_pvt *pvt);

/* INFO method functions */
void handle_info_request(nua_handle_t *nh, struct sip_profile *profile,
	sip_t const *sip, tagi_t tags[], msg_t *msg);
int sofia_send_info(struct sofia_pvt *pvt, const char *content_type, const char *payload);
int sofia_send_dtmf_info(struct sofia_pvt *pvt, char digit, int duration);

/* Function prototypes */
static struct ast_channel *sofia_request(const char *type, struct ast_format_cap *cap,
	const struct ast_assigned_ids *assignedids, const struct ast_channel *requestor,
	const char *addr, int *cause);
static int sofia_call(struct ast_channel *ast, const char *dest, int timeout);
static int sofia_hangup(struct ast_channel *ast);
static int sofia_answer(struct ast_channel *ast);
static struct ast_frame *sofia_read(struct ast_channel *ast);
static int sofia_write(struct ast_channel *ast, struct ast_frame *frame);
static int sofia_indicate(struct ast_channel *ast, int condition, const void *data, size_t datalen);
static int sofia_fixup(struct ast_channel *oldchan, struct ast_channel *newchan);
static int sofia_sendtext(struct ast_channel *ast, const char *text);
static int sofia_senddigit_begin(struct ast_channel *ast, char digit);
static int sofia_senddigit_end(struct ast_channel *ast, char digit, unsigned int duration);
static int sofia_devicestate(const char *data);
static enum ast_device_state sofia_devicestate_cb(const char *data);

/* Channel driver instance - register as "SIP" to replace old chan_sip */
static struct ast_channel_tech sip_tech = {
	.type = "SIP",
	.description = tdesc,
	.properties = AST_CHAN_TP_WANTSJITTER | AST_CHAN_TP_CREATESJITTER,
	.requester = sofia_request,
	.call = sofia_call,
	.hangup = sofia_hangup,
	.answer = sofia_answer,
	.read = sofia_read,
	.write = sofia_write,
	.indicate = sofia_indicate,
	.fixup = sofia_fixup,
	.send_text = sofia_sendtext,
	.send_digit_begin = sofia_senddigit_begin,
	.send_digit_end = sofia_senddigit_end,
	.devicestate = sofia_devicestate,
};

/* Global state */
static int sofia_loaded = 0;
static su_root_t *sofia_root = NULL;
static pthread_t sofia_thread = AST_PTHREADT_NULL;
static int sofia_running = 0;
static int sip_debug = 0;  /* SIP debug flag */

/* Private structure */
struct sofia_pvt {
	ast_mutex_t lock;
	struct ast_channel *owner;
	struct sip_profile *profile;
	nua_handle_t *nh;
	char exten[AST_MAX_EXTENSION];
	char context[AST_MAX_CONTEXT];
	struct ast_format_cap *caps;
	struct ast_format_cap *offered_caps;	/* Codecs offered by remote */
	struct ast_rtp_instance *rtp;
	struct ast_sockaddr remote_addr;
	unsigned int remote_addr_set:1;
	char remote_sdp[2048];
	char local_sdp[2048];
	
	/* Media state */
	enum sofia_media_state media_state;
	unsigned int rtp_dtmf:1;		/* RFC 2833 DTMF supported */
	int rtp_dtmf_pt;			/* DTMF payload type */
	
	/* Session Timer fields (RFC 4028) */
	int session_interval;		/* Session interval in seconds (0 = disabled) */
	int min_se;			/* Minimum session expiration */
	time_t session_expires;		/* Absolute time when session expires */
	time_t last_refresh;		/* Time of last refresh */
	int refresh_sched_id;		/* Scheduler ID for refresh timer */
	enum { REFRESHER_AUTO, REFRESHER_UAC, REFRESHER_UAS } refresher;
	
	/* Features */
	unsigned int text_messaging:1;
	unsigned int options_ping:1;
	unsigned int destroyed:1;
	unsigned int session_timer_active:1;
	unsigned int we_are_refresher:1;
	
	/* ACK tracking */
	unsigned int ack_received:1;
	unsigned int ack_sent:1;
	
	/* NAT detection */
	unsigned int nat_detected:1;
	struct ast_sockaddr source_addr;	/* Actual source IP/port from network */
	unsigned int source_addr_set:1;
	
	/* Dialog state */
	enum {
		DIALOG_STATE_INITIAL,
		DIALOG_STATE_EARLY,
		DIALOG_STATE_CONFIRMED,
		DIALOG_STATE_TERMINATED
	} dialog_state;
	
	/* Saved event for responses */
	nua_saved_event_t saved[1];
};

/* Registration storage - global hash table of active registrations */
static struct ao2_container *registrations = NULL;

/* Hash function for registrations - based on AOR */
static int registration_hash_fn(const void *obj, const int flags)
{
	const struct sip_registration *reg;
	const char *key;
	
	switch (flags & OBJ_SEARCH_MASK) {
	case OBJ_SEARCH_KEY:
		key = obj;
		break;
	case OBJ_SEARCH_OBJECT:
		reg = obj;
		key = reg->aor;
		break;
	default:
		ast_assert(0);
		return 0;
	}
	
	return ast_str_hash(key);
}

/* Comparison function for registrations */
static int registration_cmp_fn(void *obj, void *arg, int flags)
{
	const struct sip_registration *object_left = obj;
	const struct sip_registration *object_right = arg;
	const char *right_key = arg;
	int cmp;
	
	switch (flags & OBJ_SEARCH_MASK) {
	case OBJ_SEARCH_OBJECT:
		right_key = object_right->aor;
		/* Fall through */
	case OBJ_SEARCH_KEY:
		cmp = strcmp(object_left->aor, right_key);
		break;
	case OBJ_SEARCH_PARTIAL_KEY:
		/* Not supported by this container. */
		ast_assert(0);
		return 0;
	default:
		cmp = 0;
		break;
	}
	
	if (cmp) {
		return 0;
	}
	
	/* For exact object match, also check contact URI to allow multiple contacts per AOR */
	if ((flags & OBJ_SEARCH_MASK) == OBJ_SEARCH_OBJECT) {
		/* Match if same AOR AND same contact URI */
		return !strcmp(object_left->contact, object_right->contact) ? CMP_MATCH : 0;
	}
	
	return CMP_MATCH;
}

/* Destructor for registration objects */
static void registration_destructor(void *obj)
{
	struct sip_registration *reg = obj;
	struct sip_profile *profile;
	
	/* Cancel any scheduled refresh */
	if (reg->refresh_sched_id > -1 && reg->endpoint && reg->endpoint->profile) {
		profile = reg->endpoint->profile;
		if (profile->sched) {
			AST_SCHED_DEL(profile->sched, reg->refresh_sched_id);
		}
	}
	/* Nothing else to free - all fields are static arrays */
}

/* Forward declarations for handlers */
static void sofia_handle_invite(struct sip_profile *profile, nua_handle_t *nh, sip_t const *sip, nua_t *nua, nua_saved_event_t *saved);
static void sofia_handle_register(struct sip_profile *profile, nua_handle_t *nh, sip_t const *sip, nua_t *nua, msg_t *msg, tagi_t tags[], nua_saved_event_t *saved);
static void sofia_handle_message(struct sip_profile *profile, nua_handle_t *nh, sip_t const *sip, nua_t *nua);
static struct ao2_container *get_endpoint_registrations(struct sip_endpoint *endpoint);

#if 0
/* Helper function to extract auth parameter value - Not needed with new sip_register.c */
static const char *extract_auth_param(const char *param, const char *name)
{
	size_t name_len = strlen(name);
	if (strncmp(param, name, name_len) == 0 && param[name_len] == '=') {
		const char *value = param + name_len + 1;
		if (*value == '"') {
			/* Value is quoted - skip quote */
			return value + 1;
		}
		return value;
	}
	return NULL;
}
#endif

/* Configuration functions - declarations removed since they're in header */

/* Forward declarations for functions used by included modules. */
void sofia_update_peer_status(struct sip_endpoint *peer, int registered);
struct sip_registration *find_registration_by_contact(const char *aor, const char *contact);
void schedule_registration_refresh(struct sip_registration *reg);
int useragent_matches_allowed(const char *user_agent, struct sip_endpoint *endpoint);
void handle_register_request(struct sip_profile *profile, nua_handle_t *nh, sip_t const *sip, nua_t *nua, msg_t *msg, tagi_t tags[], nua_saved_event_t *saved);
void handle_options_request(struct sip_profile *profile, nua_handle_t *nh, sip_t const *sip, nua_t *nua, msg_t *msg, tagi_t tags[], nua_saved_event_t *saved);
struct sip_registration *find_active_registration(struct sip_endpoint *endpoint);
int send_options_keepalive(struct sip_profile *profile, struct sip_endpoint *endpoint);
void schedule_options_keepalives(struct sip_profile *profile);
void handle_subscribe_request(struct sip_profile *profile, nua_handle_t *nh, sip_t const *sip, nua_t *nua, msg_t *msg, tagi_t tags[], nua_saved_event_t *saved);
int sip_subscription_init(void);
void sip_subscription_destroy(void);
void sip_subscription_cleanup(void);
void sip_subscription_show_cli(int fd);
void sip_subscription_get_stats(int *total, int *active, int *pending, int *terminated);
void handle_publish_request(nua_handle_t *nh, struct sip_profile *profile, sip_t const *sip, tagi_t tags[], nua_t *nua, nua_saved_event_t *saved);
int sip_publish_init(void);
void sip_publish_destroy(void);
void sip_publish_cleanup(void);
void sip_publish_register_cli(void);
void sip_publish_unregister_cli(void);

/* Include implementation files */
/* Since we cannot modify the build system, include source files directly */
#include "chan_sofia/sip_config.c"
#include "chan_sofia/sip_core.c"
#include "chan_sofia/sip_advanced.c"
#include "chan_sofia/sip_blacklist.c"
#include "chan_sofia/sip_auth_cache.c"
#include "chan_sofia/sip_media.c"
#include "chan_sofia/sip_invite.c"
#include "chan_sofia/sip_register.c"
#include "chan_sofia/sip_options.c"
#include "chan_sofia/sip_subscribe.c"
#include "chan_sofia/sip_publish.c"
#include "chan_sofia/sip_ack.c"
#include "chan_sofia/sip_bye.c"
#include "chan_sofia/sip_cancel.c"
#include "chan_sofia/sip_info.c"
#include "chan_sofia/sip_event_queue.c"

/* Helper function to convert Path header to Route header for outbound requests (RFC 3327) */
char *sip_path_to_route(const char *path, su_home_t *home)
{
	if (!path || !path[0] || !home) {
		return NULL;
	}
	
	/* Path header is already in the correct format for Route header */
	/* Just need to duplicate it in the Sofia home memory */
	return su_strdup(home, path);
}

/* Helper function to get source IP from message */
static int get_source_ip(msg_t *msg, char *ip_addr, size_t ip_size)
{
	su_addrinfo_t *addrinfo;
	void *addr_ptr = NULL;
	
	if (!msg || !ip_addr || ip_size < INET6_ADDRSTRLEN) {
		return -1;
	}
	
	addrinfo = msg_addrinfo(msg);
	if (!addrinfo || !addrinfo->ai_addr) {
		return -1;
	}
	
	if (addrinfo->ai_addr->sa_family == AF_INET) {
		struct sockaddr_in *sin = (struct sockaddr_in *)addrinfo->ai_addr;
		addr_ptr = &sin->sin_addr;
	} else if (addrinfo->ai_addr->sa_family == AF_INET6) {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)addrinfo->ai_addr;
		addr_ptr = &sin6->sin6_addr;
	} else {
		return -1;
	}
	
	if (!inet_ntop(addrinfo->ai_addr->sa_family, addr_ptr, ip_addr, ip_size)) {
		return -1;
	}
	
	return 0;
}

/* Sofia event callback */
static void sofia_event_callback(nua_event_t event,
                                int status, char const *phrase,
                                nua_t *nua, void *nua_magic,
                                nua_handle_t *nh, void *nh_magic,
                                sip_t const *sip,
                                tagi_t tags[])
{
	struct sip_profile *profile = (struct sip_profile *)nua_magic;
	struct sofia_pvt *pvt = (struct sofia_pvt *)nh_magic;
	nua_saved_event_t saved[1];
	nua_event_data_t const *data;
	
	/* Save the event to get proper sip structure */
	nua_save_event(nua, saved);
	data = nua_event_data(saved);
	if (data && data->e_msg && !sip) {
		sip = sip_object(data->e_msg);
	}
	
	/* Check IP blacklist for incoming SIP requests - FAST O(1) check */
	if (profile && profile->blacklist_enabled && data && data->e_msg && sip && sip->sip_request) {
		char ip_addr[INET6_ADDRSTRLEN];
		if (get_source_ip(data->e_msg, ip_addr, sizeof(ip_addr)) == 0) {
			/* Fast O(1) blacklist check */
			if (sip_blacklist_check(ip_addr)) {
				ast_log(LOG_WARNING, "Dropping packet from blacklisted IP: %s\n", ip_addr);
				/* Silently drop the packet - no response */
				return;
			}
		}
	}
	
	/* Always log events to debug issues */
	ast_verbose("=== SOFIA EVENT: %s (%d) - %s ===\n", 
		nua_event_name(event), status, phrase ? phrase : "");
	ast_log(LOG_NOTICE, "<--- SIP Event: %s (%d) - %s (profile=%p, nh=%p) ---\n", 
		nua_event_name(event), status, phrase ? phrase : "", profile, nh);
	
	/* Log additional details for incoming messages */
	if (sip && sip->sip_request) {
		ast_verbose("    Method: %s, URI: %s\n", 
			sip->sip_request->rq_method_name,
			url_as_string(NULL, sip->sip_request->rq_url));
		ast_log(LOG_NOTICE, "    SIP Request: %s %s\n",
			sip->sip_request->rq_method_name,
			url_as_string(NULL, sip->sip_request->rq_url));
	}
	
	/* Ensure we have a profile */
	if (!profile) {
		ast_log(LOG_ERROR, "No profile in event callback!\n");
		return;
	}

	/* Events that should be queued for async processing */
	/* NOTE: REGISTER and INVITE are processed synchronously to avoid issues with message context */
	if (event == nua_i_options ||
	    event == nua_i_subscribe || event == nua_i_publish || event == nua_i_info ||
	    event == nua_i_cancel || event == nua_i_ack || event == nua_i_bye ||
	    event == nua_i_message || event == nua_i_update) {
		
		/* Queue event for async processing */
		if (sofia_queue) {
			ast_log(LOG_NOTICE, "Queueing %s event for async processing\n", nua_event_name(event));
			msg_t *msg = data ? data->e_msg : NULL;
			if (sofia_queue_event(profile, nh, event, status, phrase, nua, msg, sip, saved) == 0) {
				/* Event queued successfully */
				ast_log(LOG_DEBUG, "%s event queued successfully\n", nua_event_name(event));
				return;
			}
			/* Queue failed, fall through to direct processing */
			ast_log(LOG_ERROR, "Failed to queue %s event, processing directly\n", 
				nua_event_name(event));
		} else {
			ast_log(LOG_WARNING, "Event queue not initialized, processing %s directly\n", 
				nua_event_name(event));
		}
	}

	switch (event) {
	case nua_r_shutdown:
		if (profile && profile->nua) {
			su_root_break(sofia_root);
		}
		break;
		
	case nua_i_invite:
		/* Incoming call */
		ast_debug(1, "Incoming INVITE received\n");
		sofia_handle_invite(profile, nh, sip, nua, saved);
		break;
		
	case nua_i_register:
		/* Registration request */
		ast_log(LOG_NOTICE, "REGISTER received on profile %s\n", profile ? profile->name : "unknown");
		ast_verbose("DEBUG: nua_i_register - sip=%p, data=%p\n", sip, data);
		if (data && data->e_msg) {
			ast_verbose("DEBUG: data->e_msg=%p\n", data->e_msg);
		}
		/* Always process REGISTER - authentication is per endpoint */
		if (profile) {
			ast_log(LOG_NOTICE, "Processing REGISTER\n");
			msg_t *msg = data ? data->e_msg : NULL;
			sofia_handle_register(profile, nh, sip, nua, msg, tags, saved);
		} else {
			ast_log(LOG_ERROR, "No profile found for REGISTER\n");
			nua_respond(nh, SIP_500_INTERNAL_SERVER_ERROR, NUTAG_WITH_THIS(nua), TAG_END());
		}
		break;
		
	case nua_i_options:
		/* OPTIONS request */
		ast_debug(2, "OPTIONS received\n");
		handle_options_request(profile, nh, sip, nua, NULL, tags, saved);
		break;
		
	case nua_i_update:
		/* UPDATE method - RFC 3311 */
		ast_log(LOG_NOTICE, "Received UPDATE request\n");
		if (sip && sip->sip_payload && sip->sip_payload->pl_data) {
			/* Has SDP - handle media update */
			struct sofia_pvt *pvt = nua_handle_magic(nh);
			if (pvt) {
				ast_log(LOG_NOTICE, "UPDATE with SDP - parsing new media offer\n");
				
				/* Parse the new SDP offer */
				if (sofia_parse_sdp_offer(pvt, sip->sip_payload->pl_data, sip->sip_payload->pl_len) == 0) {
					/* Build SDP answer */
					struct ast_sockaddr rtp_addr;
					if (pvt->rtp) {
						ast_rtp_instance_get_local_address(pvt->rtp, &rtp_addr);
						if (sofia_build_sdp_answer(pvt, &rtp_addr) == 0) {
							/* Send 200 OK with SDP answer */
							nua_respond(nh, SIP_200_OK,
								NUTAG_WITH_THIS(nua),
								SOATAG_USER_SDP_STR(pvt->local_sdp),
								SOATAG_REUSE_REJECTED(1),
								SOATAG_RTP_SELECT(1),
								TAG_END());
							
							/* Update RTP destination if needed */
							if (pvt->remote_addr_set) {
								ast_log(LOG_NOTICE, "UPDATE: Setting new RTP remote address to %s\n", 
									ast_sockaddr_stringify(&pvt->remote_addr));
								ast_rtp_instance_set_remote_address(pvt->rtp, &pvt->remote_addr);
							}
						} else {
							ast_log(LOG_WARNING, "Failed to build SDP answer for UPDATE\n");
							nua_respond(nh, SIP_488_NOT_ACCEPTABLE, NUTAG_WITH_THIS(nua), TAG_END());
						}
					} else {
						ast_log(LOG_WARNING, "No RTP instance for UPDATE\n");
						nua_respond(nh, SIP_488_NOT_ACCEPTABLE, NUTAG_WITH_THIS(nua), TAG_END());
					}
				} else {
					ast_log(LOG_WARNING, "Failed to parse SDP in UPDATE\n");
					nua_respond(nh, SIP_488_NOT_ACCEPTABLE, NUTAG_WITH_THIS(nua), TAG_END());
				}
			} else {
				ast_log(LOG_WARNING, "No pvt for UPDATE\n");
				nua_respond(nh, SIP_481_NO_TRANSACTION, NUTAG_WITH_THIS(nua), TAG_END());
			}
		} else {
			/* UPDATE without SDP - just accept it */
			nua_respond(nh, SIP_200_OK, NUTAG_WITH_THIS(nua), TAG_END());
		}
		break;
		
	case nua_i_message:
		/* MESSAGE request */
		ast_debug(1, "MESSAGE received\n");
		if (profile->enable_messaging) {
			sofia_handle_message(profile, nh, sip, nua);
		} else {
			nua_respond(nh, SIP_501_NOT_IMPLEMENTED, NUTAG_WITH_THIS(nua), TAG_END());
		}
		break;
		
	case nua_i_subscribe:
		/* SUBSCRIBE request */
		ast_debug(1, "SUBSCRIBE received\n");
		if (profile->enable_presence) {
			/* Pass the saved event data for proper response handling */
			handle_subscribe_request(profile, nh, sip, nua, NULL, tags, saved);
		} else {
			nua_respond(nh, SIP_501_NOT_IMPLEMENTED, NUTAG_WITH_THIS(nua), TAG_END());
		}
		break;
		
	case nua_i_publish:
		/* PUBLISH request */
		ast_debug(1, "PUBLISH received\n");
		if (profile->enable_presence) {
			handle_publish_request(nh, profile, sip, tags, nua, saved);
		} else {
			/* Presence/publications disabled on this profile */
			nua_respond(nh, 403, "Forbidden - Presence Disabled", TAG_END());
		}
		break;
		
	case nua_i_bye:
		/* BYE request */
		handle_bye_request(nh, profile, sip, tags, data ? data->e_msg : NULL);
		break;
		
	case nua_i_cancel:
		/* CANCEL request */
		handle_cancel_request(nh, profile, sip, tags);
		break;
		
	case nua_i_ack:
		/* ACK received */
		handle_ack_request(nh, profile, sip, tags);
		break;
		
	case nua_i_info:
		/* INFO received */
		handle_info_request(nh, profile, sip, tags, data ? data->e_msg : NULL);
		break;
		
	case nua_r_invite:
		/* Response to our INVITE */
		ast_debug(1, "INVITE response: %d %s\n", status, phrase ? phrase : "");
		if (pvt && pvt->owner) {
			switch (status) {
			case 100:
				/* Trying - nothing to do */
				break;
			case 180:
			case 183:
				/* Ringing/Session Progress */
				ast_queue_control(pvt->owner, AST_CONTROL_RINGING);
				break;
			case 200:
				/* OK - Call answered */
				ast_queue_control(pvt->owner, AST_CONTROL_ANSWER);
				/* Send ACK manually since AUTOACK is disabled */
				sofia_send_ack(pvt, status);
				break;
			case 486:
				/* Busy */
				ast_queue_control(pvt->owner, AST_CONTROL_BUSY);
				ast_queue_hangup(pvt->owner);
				break;
			case 404:
			case 480:
			case 503:
				/* Not found, unavailable, service unavailable */
				ast_queue_control(pvt->owner, AST_CONTROL_CONGESTION);
				ast_queue_hangup(pvt->owner);
				break;
			default:
				if (status >= 400) {
					/* Other errors */
					ast_queue_hangup(pvt->owner);
				}
				break;
			}
		}
		break;
		
	case nua_r_bye:
		/* Response to our BYE */
		ast_debug(1, "BYE response: %d %s\n", status, phrase ? phrase : "");
		break;
		
	case nua_r_notify:
		/* Response to our NOTIFY */
		ast_debug(2, "NOTIFY response: %d %s\n", status, phrase ? phrase : "");
		if (status >= 200) {
			/* Final response received */
			if (status >= 300) {
				ast_log(LOG_WARNING, "NOTIFY failed: %d %s\n", status, phrase ? phrase : "");
			}
		}
		break;
		
	default:
		ast_debug(4, "Unhandled Sofia event: %s\n", nua_event_name(event));
		break;
	}
}

/* Sofia worker thread */
static void *sofia_worker(void *data)
{
	ast_debug(1, "Sofia worker thread started\n");
	
	/* Create root object in this thread (Sofia-SIP requirement) */
	ast_log(LOG_NOTICE, "Creating Sofia-SIP root...\n");
	
	sofia_root = su_root_create(NULL);
	if (!sofia_root) {
		ast_log(LOG_ERROR, "Failed to create Sofia-SIP root in worker thread\n");
		return NULL;
	}
	
	ast_log(LOG_NOTICE, "Sofia-SIP root created successfully\n");
	
	/* Load configuration now that we have root in correct thread */
	if (sip_config_load(0) < 0) {
		ast_log(LOG_ERROR, "Failed to load SIP configuration in worker thread\n");
		su_root_destroy(sofia_root);
		sofia_root = NULL;
		return NULL;
	}
	
	/* Initialize event queue after configuration is loaded */
	if (sofia_queue_init() < 0) {
		ast_log(LOG_ERROR, "Failed to initialize event queue\n");
		sip_config_destroy();
		su_root_destroy(sofia_root);
		sofia_root = NULL;
		return NULL;
	}
	
	/* Start profiles in this thread */
	ast_log(LOG_NOTICE, "Starting profiles in Sofia worker thread\n");
	AST_RWLIST_RDLOCK(&profiles);
	struct sip_profile *profile;
	int profile_count = 0;
	AST_RWLIST_TRAVERSE(&profiles, profile, list) {
		profile_count++;
		ast_log(LOG_NOTICE, "Found profile '%s' (enabled=%d)\n", profile->name, profile->enabled);
		if (profile->enabled) {
			char url[256];
			char urls[1024] = "";
			int url_count = 0;
			
			/* Build URL with transport parameter like FreeSwitch does */
			char bindurl[256];
			
			/* Determine transport parameter based on configuration */
			char *transport_param = "";
			if (strstr(profile->transport_protocol, "UDP") && strstr(profile->transport_protocol, "TCP")) {
				transport_param = ";transport=udp,tcp";
			} else if (strstr(profile->transport_protocol, "UDP")) {
				transport_param = ";transport=udp";
			} else if (strstr(profile->transport_protocol, "TCP")) {
				transport_param = ";transport=tcp";
			}
			
			/* Build bind URL */
			if (!strcmp(profile->bindip, "0.0.0.0")) {
				snprintf(bindurl, sizeof(bindurl), "sip:*:%d%s", profile->bindport, transport_param);
			} else {
				snprintf(bindurl, sizeof(bindurl), "sip:%s:%d%s", profile->bindip, profile->bindport, transport_param);
			}
			
			ast_log(LOG_NOTICE, "Creating NUA for profile '%s' with URL: %s\n", 
				profile->name, bindurl);
			
			profile->nua = nua_create(sofia_root,
				sofia_event_callback,
				profile,
				NUTAG_URL(bindurl),
				NUTAG_APPL_METHOD("REGISTER,OPTIONS,INVITE,SUBSCRIBE,NOTIFY,MESSAGE,PUBLISH"),
				NUTAG_AUTOACK(0),
				NUTAG_AUTOANSWER(0),
				NUTAG_ENABLEINVITE(1),
				NUTAG_ENABLEMESSAGE(1),
				NUTAG_ALLOW("INVITE, ACK, BYE, CANCEL, OPTIONS, MESSAGE, SUBSCRIBE, NOTIFY, REFER, UPDATE, REGISTER, PUBLISH"),
				SIPTAG_ALLOW_STR("INVITE, ACK, BYE, CANCEL, OPTIONS, MESSAGE, SUBSCRIBE, NOTIFY, REFER, UPDATE, REGISTER, PUBLISH"),
				SOATAG_AF(SOA_AF_IP4_ONLY),  /* Use IPv4 only for now */
				TAG_END());
			
			if (!profile->nua) {
				ast_log(LOG_ERROR, "Failed to create NUA for profile '%s'\n", profile->name);
			} else {
				/* Enable registrar and additional settings */
				nua_set_params(profile->nua,
					NUTAG_REGISTRAR(bindurl),
					NUTAG_ALLOW_EVENTS("presence,dialog,message-summary"),
					TAG_END());
				
				ast_log(LOG_NOTICE, "NUA created successfully for profile '%s' on %s:%d\n",
					profile->name, profile->bindip, profile->bindport);
				ast_verbose(">>> SOFIA: Profile '%s' listening on %s:%d (UDP/TCP) <<<\n",
					profile->name, profile->bindip, profile->bindport);
				
				/* Force initial event processing to ensure NUA is ready */
				su_root_step(sofia_root, 0);
				ast_log(LOG_NOTICE, "Initial su_root_step completed for profile '%s'\n", profile->name);
			}
		}
	}
	AST_RWLIST_UNLOCK(&profiles);
	
	ast_log(LOG_NOTICE, "Sofia worker thread entering main loop\n");
	
	/* Run the event loop with scheduler processing */
	time_t last_cleanup = time(NULL);
	while (sofia_running) {
		/* Process Sofia events */
		su_root_step(sofia_root, 20);
		
		/* Process schedulers for all profiles */
		AST_RWLIST_RDLOCK(&profiles);
		AST_RWLIST_TRAVERSE(&profiles, profile, list) {
			if (profile->sched) {
				ast_sched_runq(profile->sched);
			}
		}
		AST_RWLIST_UNLOCK(&profiles);
		
		/* Periodic cleanup tasks every 60 seconds */
		time_t now = time(NULL);
		if (now - last_cleanup >= 60) {
			/* Cleanup expired blacklist entries */
			sip_blacklist_cleanup();
			
			/* Cleanup expired auth cache entries */
			sip_auth_cache_cleanup();
			
			/* Cleanup expired subscriptions */
			sip_subscription_cleanup();
			
			/* Cleanup expired publications */
			sip_publish_cleanup();
			
			last_cleanup = now;
		}
	}
	
	ast_log(LOG_NOTICE, "Sofia worker thread exiting main loop\n");
	
	/* Cleanup in the same thread */
	if (sofia_root) {
		su_root_destroy(sofia_root);
		sofia_root = NULL;
	}
	
	ast_debug(1, "Sofia worker thread stopped\n");
	return NULL;
}

/* Helper to count active channels for a peer */
static int count_peer_channels(const char *peer_name)
{
       struct ast_channel_iterator *iter;
       struct ast_channel *chan;
       char prefix[256];
       int count = 0;

       snprintf(prefix, sizeof(prefix), "SIP/%s-", peer_name);
       iter = ast_channel_iterator_by_name_new(prefix, strlen(prefix));
       if (!iter) {
               return 0;
       }
       for (; (chan = ast_channel_iterator_next(iter)); ast_channel_unref(chan)) {
               count++;
       }
       ast_channel_iterator_destroy(iter);
       return count;
}

/* Device state implementation for BLF */
static int sofia_devicestate(const char *data)
{
       struct sip_endpoint *peer;
       char *device, *profile_name;
       struct sip_profile *profile = NULL;
       int res = AST_DEVICE_INVALID;
	
	device = ast_strdupa(data);
	profile_name = strchr(device, '@');
	if (profile_name) {
		*profile_name++ = '\0';
	}
	
	/* Find peer */
	if (profile_name) {
		profile = sip_profile_find(profile_name);
	}
	
	if (profile) {
		peer = sip_endpoint_find(profile, device);
	} else {
		/* Search all profiles */
		AST_RWLIST_RDLOCK(&profiles);
		AST_RWLIST_TRAVERSE(&profiles, profile, list) {
			peer = sip_endpoint_find(profile, device);
			if (peer) {
				break;
			}
		}
		AST_RWLIST_UNLOCK(&profiles);
	}
	
       if (peer) {
               if (peer->registration_count > 0) {
                       int active = count_peer_channels(peer->name);
                       res = active > 0 ? AST_DEVICE_INUSE : AST_DEVICE_NOT_INUSE;
               } else {
                       res = AST_DEVICE_UNAVAILABLE;
               }
               ao2_ref(peer, -1);  /* Release reference from sip_endpoint_find */
       }
	
	return res;
}

/* Device state provider callback */
static enum ast_device_state sofia_devicestate_cb(const char *data)
{
	return sofia_devicestate(data);
}

/* Update device state and notify watchers */
void sofia_update_peer_status(struct sip_endpoint *peer, int registered)
{
	char device[256];
	enum ast_device_state state;
	
	snprintf(device, sizeof(device), "SIP/%s", peer->name);
	
	if (registered) {
		state = AST_DEVICE_NOT_INUSE;
	} else {
		state = AST_DEVICE_UNAVAILABLE;
	}
	
	/* Update device state for BLF watchers */
	ast_devstate_changed(state, AST_DEVSTATE_CACHABLE, "SIP/%s", peer->name);
}

/* Channel technology implementation */
static struct ast_channel *sofia_request(const char *type, struct ast_format_cap *cap,
	const struct ast_assigned_ids *assignedids, const struct ast_channel *requestor,
	const char *addr, int *cause)
{
	struct ast_channel *chan = NULL;
	struct sofia_pvt *pvt;
	char *dest = ast_strdupa(addr);
	char *profile_name = NULL;
	char *destination = NULL;
	struct sip_profile *profile = NULL;
	
	/* Parse destination: SIP/profile/destination or SIP/destination */
	if (strchr(dest, '/')) {
		profile_name = strsep(&dest, "/");
		destination = dest;
	} else {
		profile_name = "default";
		destination = dest;
	}
	
	/* Find profile */
	AST_RWLIST_RDLOCK(&profiles);
	AST_RWLIST_TRAVERSE(&profiles, profile, list) {
		if (!strcasecmp(profile->name, profile_name)) {
			break;
		}
	}
	AST_RWLIST_UNLOCK(&profiles);
	
	if (!profile) {
		ast_log(LOG_ERROR, "Profile '%s' not found\n", profile_name);
		*cause = AST_CAUSE_CHANNEL_UNACCEPTABLE;
		return NULL;
	}
	
	/* Allocate private structure */
	pvt = ast_calloc(1, sizeof(*pvt));
	if (!pvt) {
		*cause = AST_CAUSE_SWITCH_CONGESTION;
		return NULL;
	}
	
	ast_mutex_init(&pvt->lock);
	pvt->profile = profile;
	ast_copy_string(pvt->exten, destination, sizeof(pvt->exten));
	ast_copy_string(pvt->context, profile->context, sizeof(pvt->context));
	
	/* Allocate capabilities */
	pvt->caps = ast_format_cap_alloc(AST_FORMAT_CAP_FLAG_DEFAULT);
	if (!pvt->caps) {
		ast_free(pvt);
		*cause = AST_CAUSE_SWITCH_CONGESTION;
		return NULL;
	}
	
	/* Add audio formats */
	ast_format_cap_append_by_type(pvt->caps, AST_MEDIA_TYPE_AUDIO);
	
	/* Create RTP instance */
	struct ast_sockaddr rtp_addr;
	ast_sockaddr_parse(&rtp_addr, profile->bindip, PARSE_PORT_FORBID);
	ast_sockaddr_set_port(&rtp_addr, 0); /* Let RTP engine pick port */
	
	pvt->rtp = ast_rtp_instance_new("gabpbx", NULL, &rtp_addr, NULL);
	if (!pvt->rtp) {
		ast_log(LOG_ERROR, "Failed to create RTP instance\n");
		ao2_cleanup(pvt->caps);
		ast_mutex_destroy(&pvt->lock);
		ast_free(pvt);
		*cause = AST_CAUSE_SWITCH_CONGESTION;
		return NULL;
	}
	
	/* Create channel */
	chan = ast_channel_alloc(1, AST_STATE_DOWN, NULL, NULL, NULL, NULL, NULL,
		assignedids, requestor, 0, "%s/%s-%08x", type, profile_name,
		(unsigned int)ast_random());
	
	if (!chan) {
		ast_rtp_instance_destroy(pvt->rtp);
		ao2_cleanup(pvt->caps);
		ast_mutex_destroy(&pvt->lock);
		ast_free(pvt);
		*cause = AST_CAUSE_SWITCH_CONGESTION;
		return NULL;
	}
	
	/* Set channel tech and pvt */
	ast_channel_tech_set(chan, &sip_tech);
	ast_channel_tech_pvt_set(chan, pvt);
	pvt->owner = chan;
	
	/* Set formats */
	ast_channel_nativeformats_set(chan, pvt->caps);
	
	/* Set initial format */
	ast_channel_set_writeformat(chan, ast_format_ulaw);
	ast_channel_set_rawwriteformat(chan, ast_format_ulaw);
	ast_channel_set_readformat(chan, ast_format_ulaw);
	ast_channel_set_rawreadformat(chan, ast_format_ulaw);
	
	ast_channel_context_set(chan, pvt->context);
	ast_channel_exten_set(chan, pvt->exten);
	
	*cause = 0;
	return chan;
}

static int sofia_call(struct ast_channel *ast, const char *dest, int timeout)
{
	struct sofia_pvt *pvt = ast_channel_tech_pvt(ast);
	char uri[256];
	char sdp[2048];
	struct ast_sockaddr rtp_addr;
	int rtp_port;
	
	if (!pvt) {
		return -1;
	}
	
	ast_mutex_lock(&pvt->lock);
	
	/* Build destination URI */
	snprintf(uri, sizeof(uri), "sip:%s@%s:%d", dest, 
		pvt->profile->bindip, pvt->profile->bindport);
	
	/* Create handle */
	pvt->nh = nua_handle(pvt->profile->nua, pvt,
		SIPTAG_TO_STR(uri),
		TAG_END());
	
	if (!pvt->nh) {
		ast_mutex_unlock(&pvt->lock);
		return -1;
	}
	
	/* Get RTP address and port */
	if (pvt->rtp) {
		ast_rtp_instance_get_local_address(pvt->rtp, &rtp_addr);
		rtp_port = ast_sockaddr_port(&rtp_addr);
		
		/* Build SDP offer */
		snprintf(sdp, sizeof(sdp),
			"v=0\r\n"
			"o=- %ld %ld IN IP4 %s\r\n"
			"s=GABpbx\r\n"
			"c=IN IP4 %s\r\n"
			"t=0 0\r\n"
			"m=audio %d RTP/AVP 0 8 3 101\r\n"
			"a=rtpmap:0 PCMU/8000\r\n"
			"a=rtpmap:8 PCMA/8000\r\n"
			"a=rtpmap:3 GSM/8000\r\n"
			"a=rtpmap:101 telephone-event/8000\r\n"
			"a=fmtp:101 0-16\r\n"
			"a=sendrecv\r\n",
			(long)time(NULL), (long)time(NULL),
			ast_sockaddr_stringify_host(&rtp_addr),
			ast_sockaddr_stringify_host(&rtp_addr),
			rtp_port);
		
		/* Send INVITE with SDP and session timer support */
		if (pvt->profile->session_timers_enabled) {
			char se_value[32];
			int session_expires = pvt->profile->session_default_se ? 
				pvt->profile->session_default_se : 1800;
			snprintf(se_value, sizeof(se_value), "%d", session_expires);
			
			nua_invite(pvt->nh,
				SIPTAG_SUPPORTED_STR("timer"),
				SIPTAG_SESSION_EXPIRES_STR(se_value),
				SIPTAG_CONTENT_TYPE_STR("application/sdp"),
				SIPTAG_PAYLOAD_STR(sdp),
				TAG_END());
			
			/* Initialize session timer state */
			pvt->session_interval = session_expires;
			pvt->session_timer_active = 1;
			pvt->refresher = REFRESHER_UAC;
			pvt->we_are_refresher = 1;
		} else {
			nua_invite(pvt->nh,
				SIPTAG_CONTENT_TYPE_STR("application/sdp"),
				SIPTAG_PAYLOAD_STR(sdp),
				TAG_END());
		}
	} else {
		/* Send INVITE without SDP */
		nua_invite(pvt->nh, TAG_END());
	}
	
	ast_setstate(ast, AST_STATE_RING);
	
	ast_mutex_unlock(&pvt->lock);
	return 0;
}

static int sofia_hangup(struct ast_channel *ast)
{
	struct sofia_pvt *pvt = ast_channel_tech_pvt(ast);
	int cause;
	
	if (!pvt) {
		return 0;
	}
	
	ast_mutex_lock(&pvt->lock);
	
	/* Get hangup cause */
	cause = ast_channel_hangupcause(ast);
	if (!cause) {
		cause = AST_CAUSE_NORMAL_CLEARING;
	}
	
	/* Stop any session timers */
	if (pvt->refresh_sched_id > -1 && pvt->profile && pvt->profile->sched) {
		AST_SCHED_DEL(pvt->profile->sched, pvt->refresh_sched_id);
	}
	
	/* Send CANCEL or BYE as appropriate */
	if (pvt->nh) {
		if (sofia_should_send_cancel(pvt)) {
			/* Early dialog - send CANCEL */
			sofia_send_cancel(pvt);
		} else if (sofia_should_send_bye(pvt)) {
			/* Confirmed dialog - send BYE */
			sofia_send_bye(pvt, cause);
		}
	}
	
	/* Clean up RTP */
	if (pvt->rtp) {
		ast_rtp_instance_stop(pvt->rtp);
		ast_rtp_instance_destroy(pvt->rtp);
		pvt->rtp = NULL;
	}
	
	/* Destroy NUA handle */
	if (pvt->nh) {
		nua_handle_destroy(pvt->nh);
		pvt->nh = NULL;
	}
	
	pvt->owner = NULL;
	ast_channel_tech_pvt_set(ast, NULL);
	
	ast_mutex_unlock(&pvt->lock);
	ast_mutex_destroy(&pvt->lock);
	
	ao2_cleanup(pvt->caps);
	ast_free(pvt);
	
	return 0;
}

/* Session refresh callback for session timers */
static int session_refresh_callback(const void *data)
{
	struct sofia_pvt *pvt = (struct sofia_pvt *)data;
	char sdp[2048];
	struct ast_sockaddr rtp_addr;
	int rtp_port;
	
	if (!pvt || !pvt->nh) {
		return -1;
	}
	
	ast_mutex_lock(&pvt->lock);
	
	/* Reset scheduled ID */
	pvt->refresh_sched_id = -1;
	
	/* Get current RTP info for re-INVITE */
	if (pvt->rtp) {
		ast_rtp_instance_get_local_address(pvt->rtp, &rtp_addr);
		rtp_port = ast_sockaddr_port(&rtp_addr);
		
		/* Build SDP for re-INVITE */
		snprintf(sdp, sizeof(sdp),
			"v=0\r\n"
			"o=- %ld %ld IN IP4 %s\r\n"
			"s=GABpbx Session Refresh\r\n"
			"c=IN IP4 %s\r\n"
			"t=0 0\r\n"
			"m=audio %d RTP/AVP 0 8 3 101\r\n"
			"a=rtpmap:0 PCMU/8000\r\n"
			"a=rtpmap:8 PCMA/8000\r\n"
			"a=rtpmap:3 GSM/8000\r\n"
			"a=rtpmap:101 telephone-event/8000\r\n"
			"a=fmtp:101 0-16\r\n"
			"a=sendrecv\r\n",
			(long)time(NULL), (long)time(NULL),
			pvt->profile->bindip,
			pvt->profile->bindip,
			rtp_port);
		
		/* Send re-INVITE for session refresh */
		char se_header[64];
		snprintf(se_header, sizeof(se_header), "%d;refresher=%s", 
			pvt->session_interval, pvt->we_are_refresher ? "uas" : "uac");
		
		nua_invite(pvt->nh,
			SIPTAG_SUPPORTED_STR("timer"),
			SIPTAG_SESSION_EXPIRES_STR(se_header),
			SIPTAG_CONTENT_TYPE_STR("application/sdp"),
			SIPTAG_PAYLOAD_STR(sdp),
			TAG_END());
		
		/* Update last refresh time */
		pvt->last_refresh = time(NULL);
		
		ast_log(LOG_DEBUG, "Sent session refresh re-INVITE\n");
	}
	
	ast_mutex_unlock(&pvt->lock);
	
	return 0;  /* Don't reschedule - will be rescheduled on response */
}

static int sofia_answer(struct ast_channel *ast)
{
	struct sofia_pvt *pvt = ast_channel_tech_pvt(ast);
	char sdp[2048];
	struct ast_sockaddr rtp_addr;
	
	if (!pvt || !pvt->nh) {
		return -1;
	}
	
	ast_mutex_lock(&pvt->lock);
	
	/* Get RTP address and port */
	if (pvt->rtp) {
		ast_rtp_instance_get_local_address(pvt->rtp, &rtp_addr);
		
		/* Build SDP answer based on negotiated codecs */
		if (sofia_build_sdp_answer(pvt, &rtp_addr) < 0) {
			ast_log(LOG_ERROR, "Failed to build SDP answer\n");
			ast_mutex_unlock(&pvt->lock);
			return -1;
		}
		
		/* Use the generated SDP */
		ast_copy_string(sdp, pvt->local_sdp, sizeof(sdp));
		
		/* Add session timer support in 200 OK */
		if (pvt->session_timer_active && pvt->profile->session_timers_enabled) {
			char se_header[64];
			const char *refresher = pvt->we_are_refresher ? "uas" : "uac";
			snprintf(se_header, sizeof(se_header), "%d;refresher=%s", 
				pvt->session_interval, refresher);
			
			nua_respond(pvt->nh, SIP_200_OK,
				NUTAG_WITH_SAVED(pvt->saved),
				SOATAG_USER_SDP_STR(sdp),
				SOATAG_REUSE_REJECTED(1),
				SOATAG_RTP_SELECT(1),
				SOATAG_AUDIO_AUX("cn telephone-event"),
				SIPTAG_SUPPORTED_STR("timer"),
				SIPTAG_SESSION_EXPIRES_STR(se_header),
				TAG_END());
			
			/* Schedule session refresh if we're the refresher */
			if (pvt->we_are_refresher && pvt->profile->sched) {
				int refresh_time = pvt->session_interval / 2;  /* Refresh at half time */
				pvt->refresh_sched_id = ast_sched_add(pvt->profile->sched, 
					refresh_time * 1000, session_refresh_callback, pvt);
			}
		} else {
			nua_respond(pvt->nh, SIP_200_OK,
				NUTAG_WITH_SAVED(pvt->saved),
				SOATAG_USER_SDP_STR(sdp),
				SOATAG_REUSE_REJECTED(1),
				SOATAG_RTP_SELECT(1),
				SOATAG_AUDIO_AUX("cn telephone-event"),
				TAG_END());
		}
		
		/* Set media state to answered and activate RTP */
		pvt->media_state = MEDIA_STATE_ANSWERED;
		if (sofia_activate_rtp(pvt) < 0) {
			ast_log(LOG_WARNING, "Failed to activate RTP\n");
		}
	} else {
		/* No RTP - send without SDP */
		nua_respond(pvt->nh, SIP_200_OK,
			NUTAG_WITH_SAVED(pvt->saved),
			TAG_END());
	}
	
	ast_mutex_unlock(&pvt->lock);
	
	return 0;
}

static struct ast_frame *sofia_read(struct ast_channel *ast)
{
	struct sofia_pvt *pvt = ast_channel_tech_pvt(ast);
	struct ast_frame *f;
	
	if (!pvt) {
		return &ast_null_frame;
	}
	
	ast_mutex_lock(&pvt->lock);
	
	if (pvt->rtp) {
		f = ast_rtp_instance_read(pvt->rtp, 0);
	} else {
		f = &ast_null_frame;
	}
	
	ast_mutex_unlock(&pvt->lock);
	
	return f;
}

static int sofia_write(struct ast_channel *ast, struct ast_frame *frame)
{
	struct sofia_pvt *pvt = ast_channel_tech_pvt(ast);
	int res = 0;
	
	if (!pvt) {
		return -1;
	}
	
	ast_mutex_lock(&pvt->lock);
	
	if (pvt->rtp && frame->frametype == AST_FRAME_VOICE) {
		res = ast_rtp_instance_write(pvt->rtp, frame);
	}
	
	ast_mutex_unlock(&pvt->lock);
	
	return res;
}

static int sofia_indicate(struct ast_channel *ast, int condition, const void *data, size_t datalen)
{
	struct sofia_pvt *pvt = ast_channel_tech_pvt(ast);
	char sdp[2048];
	struct ast_sockaddr rtp_addr;
	int rtp_port;
	
	if (!pvt || !pvt->nh) {
		return -1;
	}
	
	switch (condition) {
       case AST_CONTROL_RINGING:
               /* Send 180 Ringing - optionally with SDP for early media */
               if (pvt->rtp) {
			/* Get RTP address and port for early media */
			ast_rtp_instance_get_local_address(pvt->rtp, &rtp_addr);
			rtp_port = ast_sockaddr_port(&rtp_addr);
			
			/* Build SDP for early media */
			snprintf(sdp, sizeof(sdp),
				"v=0\r\n"
				"o=- %ld %ld IN IP4 %s\r\n"
				"s=GABpbx\r\n"
				"c=IN IP4 %s\r\n"
				"t=0 0\r\n"
				"m=audio %d RTP/AVP 0 8 3 101\r\n"
				"a=rtpmap:0 PCMU/8000\r\n"
				"a=rtpmap:8 PCMA/8000\r\n"
				"a=rtpmap:3 GSM/8000\r\n"
				"a=rtpmap:101 telephone-event/8000\r\n"
				"a=fmtp:101 0-16\r\n"
				"a=sendrecv\r\n",
				(long)time(NULL), (long)time(NULL),
				pvt->profile->bindip,
				pvt->profile->bindip,
				rtp_port);
			
			nua_respond(pvt->nh, SIP_180_RINGING,
				SIPTAG_CONTENT_TYPE_STR("application/sdp"),
				SIPTAG_PAYLOAD_STR(sdp),
				TAG_END());
		} else {
			/* Regular 180 without SDP */
			nua_respond(pvt->nh, SIP_180_RINGING, TAG_END());
		}
		break;
	case AST_CONTROL_PROGRESS:
		/* Send 183 Session Progress with SDP */
		if (pvt->rtp) {
			ast_rtp_instance_get_local_address(pvt->rtp, &rtp_addr);
			rtp_port = ast_sockaddr_port(&rtp_addr);
			
			snprintf(sdp, sizeof(sdp),
				"v=0\r\n"
				"o=- %ld %ld IN IP4 %s\r\n"
				"s=GABpbx\r\n"
				"c=IN IP4 %s\r\n"
				"t=0 0\r\n"
				"m=audio %d RTP/AVP 0 8 3 101\r\n"
				"a=rtpmap:0 PCMU/8000\r\n"
				"a=rtpmap:8 PCMA/8000\r\n"
				"a=rtpmap:3 GSM/8000\r\n"
				"a=rtpmap:101 telephone-event/8000\r\n"
				"a=fmtp:101 0-16\r\n"
				"a=sendrecv\r\n",
				(long)time(NULL), (long)time(NULL),
				pvt->profile->bindip,
				pvt->profile->bindip,
				rtp_port);
			
			nua_respond(pvt->nh, SIP_183_SESSION_PROGRESS,
				SIPTAG_CONTENT_TYPE_STR("application/sdp"),
				SIPTAG_PAYLOAD_STR(sdp),
				TAG_END());
		}
		break;
	case AST_CONTROL_BUSY:
		nua_respond(pvt->nh, SIP_486_BUSY_HERE, TAG_END());
		break;
	case AST_CONTROL_CONGESTION:
		nua_respond(pvt->nh, SIP_503_SERVICE_UNAVAILABLE, TAG_END());
		break;
	default:
		return -1;
	}
	
	return 0;
}

static int sofia_fixup(struct ast_channel *oldchan, struct ast_channel *newchan)
{
	struct sofia_pvt *pvt = ast_channel_tech_pvt(newchan);
	
	if (!pvt) {
		return -1;
	}
	
	ast_mutex_lock(&pvt->lock);
	
	if (pvt->owner != oldchan) {
		ast_mutex_unlock(&pvt->lock);
		return -1;
	}
	
	pvt->owner = newchan;
	
	ast_mutex_unlock(&pvt->lock);
	
	return 0;
}

static int sofia_sendtext(struct ast_channel *ast, const char *text)
{
	struct sofia_pvt *pvt = ast_channel_tech_pvt(ast);
	
	if (!pvt || !pvt->nh || !pvt->profile->enable_messaging) {
		return -1;
	}
	
	/* Send SIP MESSAGE */
	nua_message(pvt->nh,
		SIPTAG_CONTENT_TYPE_STR("text/plain"),
		SIPTAG_PAYLOAD_STR(text),
		TAG_END());
	
	return 0;
}

static int sofia_senddigit_begin(struct ast_channel *ast, char digit)
{
	struct sofia_pvt *pvt = ast_channel_tech_pvt(ast);
	
	if (!pvt || !pvt->endpoint) {
	return -1;
	}
	
	if (!strcasecmp(pvt->endpoint->dtmfmode, "rfc2833") && pvt->rtp) {
	return ast_rtp_instance_dtmf_begin(pvt->rtp, digit);
	} else if (!strcasecmp(pvt->endpoint->dtmfmode, "inband")) {
	struct ast_frame f = {
	.frametype = AST_FRAME_DTMF_BEGIN,
	.subclass.integer = digit,
	};
	ast_queue_frame(ast, &f);
	return 0;
	}
	
	/* INFO mode does not use begin packets */
	return 0;
	}

	static int sofia_senddigit_end(struct ast_channel *ast, char digit, unsigned int duration)
	{
	struct sofia_pvt *pvt = ast_channel_tech_pvt(ast);
	
	if (!pvt || !pvt->endpoint) {
	return -1;
	}
	
	if (!strcasecmp(pvt->endpoint->dtmfmode, "rfc2833") && pvt->rtp) {
	return ast_rtp_instance_dtmf_end_with_duration(pvt->rtp, digit, duration);
	} else if (!strcasecmp(pvt->endpoint->dtmfmode, "inband")) {
	struct ast_frame f = {
	.frametype = AST_FRAME_DTMF_END,
	.subclass.integer = digit,
	.len = duration,
	};
	ast_queue_frame(ast, &f);
	return 0;
	} else if (pvt->nh && pvt->dialog_state == DIALOG_STATE_CONFIRMED) {
	return sofia_send_dtmf_info(pvt, digit, duration);
	}
	
	return -1;
	}
	
	/* CLI commands */
	static char *sofia_show_status(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a);
	static char *sofia_show_profiles(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a);
	
	static char *sofia_show_endpoints(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a);
	static char *sofia_show_peer(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a);
static char *sofia_show_peer_contacts(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a);
static char *sofia_show_registrations(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a);
static char *sofia_show_subscriptions(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a);
static char *sip_set_debug(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a);
static char *sip_show_blacklist(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a);
static char *sip_blacklist_add(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a);
static char *sip_blacklist_del(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a);
static char *sip_show_authcache(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a);
static char *sip_authcache_clear(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a);

static struct ast_cli_entry sofia_cli[] = {
	AST_CLI_DEFINE(sofia_show_status, "Show Sofia status"),
	AST_CLI_DEFINE(sofia_show_profiles, "Show Sofia profiles"),
	AST_CLI_DEFINE(sofia_show_endpoints, "Show Sofia endpoints/peers"),
	AST_CLI_DEFINE(sofia_show_peer, "Show details of a specific peer"),
	AST_CLI_DEFINE(sofia_show_peer_contacts, "Show all contacts for a peer"),
	AST_CLI_DEFINE(sofia_show_registrations, "Show active registrations"),
	AST_CLI_DEFINE(sofia_show_subscriptions, "Show active event subscriptions"),
	AST_CLI_DEFINE(sip_set_debug, "Enable/disable SIP debugging"),
	AST_CLI_DEFINE(sip_show_blacklist, "Show IP blacklist"),
	AST_CLI_DEFINE(sip_blacklist_add, "Add IP to blacklist"),
	AST_CLI_DEFINE(sip_blacklist_del, "Remove IP from blacklist"),
	AST_CLI_DEFINE(sip_show_authcache, "Show authentication cache"),
	AST_CLI_DEFINE(sip_authcache_clear, "Clear authentication cache"),
};

static char *sofia_show_status(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
{
	switch (cmd) {
	case CLI_INIT:
		e->command = "sip show settings";
		e->usage =
			"Usage: sip show settings\n"
			"       Display overall SIP channel driver settings.\n";
		return NULL;
	case CLI_GENERATE:
		return NULL;
	}

	if (a->argc != 3) {
		return CLI_SHOWUSAGE;
	}

	ast_cli(a->fd, "\nSIP Channel Driver Status\n");
	ast_cli(a->fd, "========================\n");
	ast_cli(a->fd, "Module Status    : Loaded\n");
	ast_cli(a->fd, "Sofia-SIP        : Available\n");
	ast_cli(a->fd, "Technology Name  : SIP\n");
	ast_cli(a->fd, "Replaces         : chan_sip (deprecated)\n");
	ast_cli(a->fd, "Worker Thread    : %s\n", 
		sofia_thread != AST_PTHREADT_NULL ? "Active" : "Inactive");
	ast_cli(a->fd, "\n");

	return CLI_SUCCESS;
}

static char *sofia_show_profiles(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
{
	struct sip_profile *profile;
	int count = 0;

	switch (cmd) {
	case CLI_INIT:
		e->command = "sip show profiles";
		e->usage =
			"Usage: sip show profiles\n"
			"       List all configured SIP profiles.\n";
		return NULL;
	case CLI_GENERATE:
		return NULL;
	}

	if (a->argc != 3) {
		return CLI_SHOWUSAGE;
	}

	ast_cli(a->fd, "\nSIP Profiles\n");
	ast_cli(a->fd, "============\n");
	ast_cli(a->fd, "%-15s %-15s %-6s %-10s %-15s %s\n",
		"Profile", "Bind IP", "Port", "Context", "Transport", "Features");
	ast_cli(a->fd, "%-15s %-15s %-6s %-10s %-15s %s\n",
		"-------", "-------", "----", "-------", "---------", "--------");

	AST_RWLIST_RDLOCK(&profiles);
	AST_RWLIST_TRAVERSE(&profiles, profile, list) {
		char features[128] = "";
		
		if (profile->enable_options) strcat(features, "OPTIONS ");
		if (profile->enable_messaging) strcat(features, "MESSAGE ");
		if (profile->enable_presence) strcat(features, "PRESENCE ");
		
		ast_cli(a->fd, "%-15s %-15s %-6d %-10s %-15s %s\n",
			profile->name,
			profile->bindip,
			profile->bindport,
			profile->context,
			profile->transport_protocol,
			features);
		count++;
	}
	AST_RWLIST_UNLOCK(&profiles);

	ast_cli(a->fd, "\nTotal profiles: %d\n\n", count);

	return CLI_SUCCESS;
}

static char *sofia_show_endpoints(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
{
	struct sip_endpoint *endpoint;
	int count = 0;

	switch (cmd) {
	case CLI_INIT:
		e->command = "sip show peers";
		e->usage =
			"Usage: sip show peers\n"
			"       List all configured SIP peers.\n";
		return NULL;
	case CLI_GENERATE:
		return NULL;
	}

	if (a->argc != 3) {
		return CLI_SHOWUSAGE;
	}

	time_t now = time(NULL);
	
	ast_cli(a->fd, "\nSIP Peers\n");
	ast_cli(a->fd, "=========\n");
	ast_cli(a->fd, "%-15s %-15s %-15s %-20s %-15s %s\n",
		"Name", "Username", "Profile", "Status", "Expires", "Address");
	ast_cli(a->fd, "%-15s %-15s %-15s %-20s %-15s %s\n",
		"----", "--------", "-------", "------", "-------", "-------");

	/* Iterate through endpoints hash table */
	struct ao2_iterator endpoint_iter;
	endpoint_iter = ao2_iterator_init(endpoints, 0);
	while ((endpoint = ao2_iterator_next(&endpoint_iter))) {
		/* Find registration for this endpoint */
		struct sip_registration *reg = NULL;
		char status[32] = "Not Registered";
		char expires[32] = "N/A";
		char address[64] = "N/A";
		
		/* Find registration for this endpoint */
		struct ao2_iterator iter;
		iter = ao2_iterator_init(registrations, 0);
		while ((reg = ao2_iterator_next(&iter))) {
			if (reg->endpoint == endpoint) {
				if (reg->expires > 0 && reg->expires > now) {
					int remaining = reg->expires - now;
					snprintf(status, sizeof(status), "Registered");
					snprintf(expires, sizeof(expires), "%d sec", remaining);
					char addr_str[INET_ADDRSTRLEN];
					inet_ntop(AF_INET, &reg->addr.sin_addr, addr_str, sizeof(addr_str));
					snprintf(address, sizeof(address), "%s:%d", addr_str, ntohs(reg->addr.sin_port));
				} else if (reg->expires == -1) {
					snprintf(status, sizeof(status), "Expired");
					snprintf(expires, sizeof(expires), "Expired");
					char addr_str[INET_ADDRSTRLEN];
					inet_ntop(AF_INET, &reg->addr.sin_addr, addr_str, sizeof(addr_str));
					snprintf(address, sizeof(address), "%s:%d", addr_str, ntohs(reg->addr.sin_port));
				}
				ao2_ref(reg, -1);
				break;
			}
			ao2_ref(reg, -1);
		}
		ao2_iterator_destroy(&iter);
		
		ast_cli(a->fd, "%-15s %-15s %-15s %-20s %-15s %s\n",
			endpoint->name,
			endpoint->username,
			endpoint->profile ? endpoint->profile->name : "none",
			status,
			expires,
			address);
		count++;
		ao2_ref(endpoint, -1);
	}
	ao2_iterator_destroy(&endpoint_iter);

	ast_cli(a->fd, "\nTotal endpoints: %d\n\n", count);

	return CLI_SUCCESS;
}

static char *sofia_show_peer(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
{
	struct sip_endpoint *peer;
	const char *peer_name;
	
	switch (cmd) {
	case CLI_INIT:
		e->command = "sip show peer";
		e->usage =
			"Usage: sip show peer <peername>\n"
			"       Show details of a specific SIP peer.\n";
		return NULL;
	case CLI_GENERATE:
		return NULL;
	}

	if (a->argc != 4) {
		return CLI_SHOWUSAGE;
	}

	peer_name = a->argv[3];
	
	/* Find the peer across all profiles */
	struct sip_profile *profile;
	peer = NULL;
	AST_RWLIST_RDLOCK(&profiles);
	AST_RWLIST_TRAVERSE(&profiles, profile, list) {
		peer = sip_endpoint_find(profile, peer_name);
		if (peer) {
			break;
		}
	}
	AST_RWLIST_UNLOCK(&profiles);
	
	if (!peer) {
		ast_cli(a->fd, "Peer '%s' not found.\n", peer_name);
		return CLI_SUCCESS;
	}
	
	/* Display peer information */
	ast_cli(a->fd, "\n");
	ast_cli(a->fd, "  * Name       : %s\n", peer->name);
	ast_cli(a->fd, "  * Username   : %s\n", peer->username);
	ast_cli(a->fd, "  * Secret     : %s\n", ast_strlen_zero(peer->secret) ? "<Not set>" : "<Set>");
	ast_cli(a->fd, "  * Context    : %s\n", peer->context);
	ast_cli(a->fd, "  * Profile    : %s\n", peer->profile ? peer->profile->name : "none");
	ast_cli(a->fd, "  * Max Contacts: %d\n", peer->max_contacts > 0 ? peer->max_contacts : 
		(peer->profile && peer->profile->max_contacts_global > 0 ? peer->profile->max_contacts_global : 3));
	ast_cli(a->fd, "  * Reg Count  : %d\n", peer->registration_count);
	ast_cli(a->fd, "  * Ring Mode  : %s\n", 
		peer->ring_all_except_inuse ? "All except in-use" : 
		(peer->profile && peer->profile->ring_all_except_inuse_global ? "All except in-use (profile)" : "All devices"));
	
	/* User-Agent authentication info */
	if (peer->require_useragent && peer->num_useragents > 0) {
		int i;
		ast_cli(a->fd, "  * UA Auth    : Required\n");
		for (i = 0; i < peer->num_useragents; i++) {
			ast_cli(a->fd, "  * UA Pattern %d: %s\n", i + 1, peer->allowed_useragents[i]);
		}
	} else {
		ast_cli(a->fd, "  * UA Auth    : Not required\n");
	}
	
ast_cli(a->fd, "\n");
{
struct ast_str *codec_buf = ast_str_alloca(AST_FORMAT_CAP_NAMES_LEN);
const char *names = peer->caps ? ast_format_cap_get_names(peer->caps, &codec_buf) : "(none)";
ast_cli(a->fd, "  Codecs       : %s\n", names);
}
	/* Display registration status summary */
	int active_count = count_active_registrations(peer);
	int total_count = 0;
	struct ao2_iterator iter;
	struct sip_registration *reg;
	
	/* Count total including expired */
	iter = ao2_iterator_init(registrations, 0);
	while ((reg = ao2_iterator_next(&iter))) {
		if (reg->endpoint == peer) {
			total_count++;
		}
		ao2_ref(reg, -1);
	}
	ao2_iterator_destroy(&iter);
	
	ast_cli(a->fd, "  Status       : ");
	if (active_count > 0) {
		ast_cli(a->fd, "%d active registration%s", active_count, active_count > 1 ? "s" : "");
		if (total_count > active_count) {
			ast_cli(a->fd, " (%d expired)", total_count - active_count);
		}
		ast_cli(a->fd, "\n");
		ast_cli(a->fd, "                 Use 'sip show peer contacts %s' to see all contacts\n", peer->name);
	} else if (total_count > 0) {
		ast_cli(a->fd, "OK (all %d registration%s expired)\n", total_count, total_count > 1 ? "s" : "");
		ast_cli(a->fd, "                 Use 'sip show peer contacts %s' to see details\n", peer->name);
	} else {
		ast_cli(a->fd, "Not Registered\n");
	}
	ast_cli(a->fd, "  Useragent    : ");
	
	/* Show most recent user agent */
	time_t latest_time = 0;
	char latest_ua[256] = "N/A";
	iter = ao2_iterator_init(registrations, 0);
	while ((reg = ao2_iterator_next(&iter))) {
		if (reg->endpoint == peer && reg->registered > latest_time) {
			latest_time = reg->registered;
			ast_copy_string(latest_ua, reg->user_agent, sizeof(latest_ua));
		}
		ao2_ref(reg, -1);
	}
	ao2_iterator_destroy(&iter);
	ast_cli(a->fd, "%s\n", latest_ua);
	
	ast_cli(a->fd, "  Qualify Freq : 60000 ms\n");
	ast_cli(a->fd, "  Mailbox      : %s\n", "1001@default"); /* TODO: Mailbox config */
	ast_cli(a->fd, "\n");
	
	/* Device state for BLF */
	ast_cli(a->fd, "  Device State : %s\n", "Not in use"); /* TODO: Real device state */
	ast_cli(a->fd, "  Subscriptions: 0\n"); /* TODO: Track subscriptions */
	ast_cli(a->fd, "  BLF Capable  : Yes\n");
	ast_cli(a->fd, "\n");
	
	ao2_ref(peer, -1);  /* Release reference from sip_endpoint_find */
	return CLI_SUCCESS;
}

static char *sofia_show_peer_contacts(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
{
	struct sip_endpoint *peer;
	struct sip_registration *reg;
	struct ao2_iterator iter;
	time_t now = time(NULL);
	int count = 0;
	
	switch (cmd) {
	case CLI_INIT:
		e->command = "sip show peer contacts";
		e->usage =
			"Usage: sip show peer contacts <peername>\n"
			"       Show all contact registrations for a specific peer.\n";
		return NULL;
	case CLI_GENERATE:
		return NULL;
	}
	
	if (a->argc != 5) {
		return CLI_SHOWUSAGE;
	}
	
	peer = sip_endpoint_find(NULL, a->argv[4]);
	if (!peer) {
		ast_cli(a->fd, "Peer '%s' not found.\n", a->argv[4]);
		return CLI_SUCCESS;
	}
	
	ast_cli(a->fd, "\nContacts for peer %s:\n", peer->name);
	ast_cli(a->fd, "==================================================================================================================\n");
	ast_cli(a->fd, "%-50s %-20s %-15s %-30s\n", "Contact URI", "IP Address", "Expires", "User-Agent");
	ast_cli(a->fd, "%-50s %-20s %-15s %-30s\n",
		"--------------------------------------------------",
		"--------------------", 
		"---------------",
		"------------------------------");
	ast_cli(a->fd, "Path: <path header values if present>\n");
	ast_cli(a->fd, "------------------------------------------------------------------------------------------------------------------\n");
	
	iter = ao2_iterator_init(registrations, 0);
	while ((reg = ao2_iterator_next(&iter))) {
		if (reg->endpoint == peer) {
			char addr_str[INET_ADDRSTRLEN + 6];
			char expires_str[32];
			char contact_short[51];
			
			inet_ntop(AF_INET, &reg->addr.sin_addr, addr_str, sizeof(addr_str));
			int len = strlen(addr_str);
			snprintf(addr_str + len, sizeof(addr_str) - len, ":%d", ntohs(reg->addr.sin_port));
			
			if (reg->expires == -1) {
				strcpy(expires_str, "Expired");
			} else if (reg->expires > now) {
				int remaining = reg->expires - now;
				snprintf(expires_str, sizeof(expires_str), "%d sec", remaining);
			} else {
				strcpy(expires_str, "Expired");
			}
			
			/* Truncate contact if too long */
			ast_copy_string(contact_short, reg->contact, sizeof(contact_short));
			if (strlen(reg->contact) > 50) {
				contact_short[47] = '.';
				contact_short[48] = '.';
				contact_short[49] = '.';
				contact_short[50] = '\0';
			}
			
			ast_cli(a->fd, "%-50s %-20s %-15s %.30s\n",
				contact_short,
				addr_str,
				expires_str,
				reg->user_agent);
			
			/* Show Path header if present */
			if (reg->path[0]) {
				ast_cli(a->fd, "  Path: %s\n", reg->path);
			}
			count++;
		}
		ao2_ref(reg, -1);
	}
	ao2_iterator_destroy(&iter);
	
	if (count == 0) {
		ast_cli(a->fd, "\nNo contacts registered.\n");
	} else {
		int active = count_active_registrations(peer);
		int max_contacts = peer->max_contacts > 0 ? peer->max_contacts :
			(peer->profile && peer->profile->max_contacts_global > 0 ? 
			 peer->profile->max_contacts_global : 3);
		ast_cli(a->fd, "\nTotal: %d contact%s (%d active, %d expired) - Max allowed: %d\n", 
			count, count != 1 ? "s" : "", active, count - active, max_contacts);
	}
	
	ao2_ref(peer, -1);  /* Release reference from sip_endpoint_find */
	return CLI_SUCCESS;
}

static char *sofia_show_registrations(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
{
	int count = 0;

	switch (cmd) {
	case CLI_INIT:
		e->command = "sip show registry";
		e->usage =
			"Usage: sip show registry\n"
			"       List all active SIP registrations.\n";
		return NULL;
	case CLI_GENERATE:
		return NULL;
	}

	if (a->argc != 3) {
		return CLI_SHOWUSAGE;
	}

	
	ast_cli(a->fd, "\nActive Registrations\n");
	ast_cli(a->fd, "====================================================================================================\n");
	ast_cli(a->fd, "%-15s %-20s %-40s %-20s %-10s %s\n",
		"Peer", "AOR", "Contact", "IP Address", "Expires", "User-Agent");
	ast_cli(a->fd, "%-15s %-20s %-40s %-20s %-10s %s\n",
		"----", "---", "-------", "----------", "-------", "----------");

	struct sip_registration *reg;
	time_t now = time(NULL);
	int active_count = 0;
	int expired_count = 0;
	
	/* Iterate through all registrations */
	struct ao2_iterator iter;
	iter = ao2_iterator_init(registrations, 0);
	while ((reg = ao2_iterator_next(&iter))) {
		char time_str[32];
		
		if (reg->expires == -1 || reg->expires <= now) {
			snprintf(time_str, sizeof(time_str), "expired");
			expired_count++;
		} else {
			int remaining = reg->expires - now;
			snprintf(time_str, sizeof(time_str), "%d sec", remaining);
			active_count++;
		}
		
		char addr_str[INET_ADDRSTRLEN + 6]; /* IP:port */
		inet_ntop(AF_INET, &reg->addr.sin_addr, addr_str, sizeof(addr_str));
		int len = strlen(addr_str);
		snprintf(addr_str + len, sizeof(addr_str) - len, ":%d", ntohs(reg->addr.sin_port));
		
		/* Truncate contact if too long to fit in column */
		char contact_short[41];
		ast_copy_string(contact_short, reg->contact, sizeof(contact_short));
		if (strlen(reg->contact) > 40) {
			contact_short[37] = '.';
			contact_short[38] = '.';
			contact_short[39] = '.';
			contact_short[40] = '\0';
		}
		
		ast_cli(a->fd, "%-15.15s %-20.20s %-40s %-20s %-10s %s\n",
			reg->endpoint ? reg->endpoint->name : "Unknown",
			reg->aor,
			contact_short,
			addr_str,
			time_str,
			reg->user_agent);
		count++;
		ao2_ref(reg, -1);
	}
	ao2_iterator_destroy(&iter);
	
	if (count == 0) {
		ast_cli(a->fd, "\nNo registrations found\n");
	} else {
		ast_cli(a->fd, "\nTotal: %d registration%s (%d active, %d expired)\n", 
			count, count != 1 ? "s" : "", active_count, expired_count);
		
		/* Show peer summary */
		ast_cli(a->fd, "\nPeer Summary:\n");
		struct sip_endpoint *peer;
		struct ao2_iterator peer_iter;
		peer_iter = ao2_iterator_init(endpoints, 0);
		while ((peer = ao2_iterator_next(&peer_iter))) {
			int peer_active = count_active_registrations(peer);
			if (peer_active > 0 || peer->registration_count > 0) {
				ast_cli(a->fd, "  %-15s: %d active contact%s\n", 
					peer->name, peer_active, peer_active != 1 ? "s" : "");
			}
			ao2_ref(peer, -1);
		}
		ao2_iterator_destroy(&peer_iter);
	}
	ast_cli(a->fd, "\n");

	return CLI_SUCCESS;
}

static char *sofia_show_subscriptions(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
{
	switch (cmd) {
	case CLI_INIT:
		e->command = "sip show subscriptions";
		e->usage =
			"Usage: sip show subscriptions\n"
			"       List all active SIP event subscriptions (SUBSCRIBE/NOTIFY).\n";
		return NULL;
	case CLI_GENERATE:
		return NULL;
	}

	if (a->argc != 3) {
		return CLI_SHOWUSAGE;
	}

	/* Show the subscriptions */
	sip_subscription_show_cli(a->fd);
	
	/* Also show statistics */
	int total, active, pending, terminated;
	sip_subscription_get_stats(&total, &active, &pending, &terminated);
	
	if (total > 0) {
		ast_cli(a->fd, "\nSubscription Statistics:\n");
		ast_cli(a->fd, "  Active:     %d\n", active);
		ast_cli(a->fd, "  Pending:    %d\n", pending); 
		ast_cli(a->fd, "  Terminated: %d\n", terminated);
	}
	
	return CLI_SUCCESS;
}

static char *sip_set_debug(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
{
	switch (cmd) {
	case CLI_INIT:
		e->command = "sip set debug {on|off}";
		e->usage =
			"Usage: sip set debug {on|off}\n"
			"       Enable/disable SIP message debugging\n";
		return NULL;
	case CLI_GENERATE:
		return NULL;
	}

	if (a->argc != 4) {
		return CLI_SHOWUSAGE;
	}

	if (!strcasecmp(a->argv[3], "on")) {
		sip_debug = 1;
		ast_cli(a->fd, "SIP Debugging enabled\n");
	} else if (!strcasecmp(a->argv[3], "off")) {
		sip_debug = 0;
		ast_cli(a->fd, "SIP Debugging disabled\n");
	} else {
		return CLI_SHOWUSAGE;
	}

	return CLI_SUCCESS;
}

static char *sip_show_blacklist(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
{
	struct ao2_iterator iter;
	struct sip_blacklist_entry *entry;
	time_t now = time(NULL);
	int count = 0;
	
	switch (cmd) {
	case CLI_INIT:
		e->command = "sip show blacklist";
		e->usage =
			"Usage: sip show blacklist\n"
			"       Show all IPs in the blacklist with their status.\n";
		return NULL;
	case CLI_GENERATE:
		return NULL;
	}
	
	if (a->argc != 3) {
		return CLI_SHOWUSAGE;
	}
	
	ast_cli(a->fd, "\nIP Blacklist\n");
	ast_cli(a->fd, "============\n");
	ast_cli(a->fd, "%-20s %-10s %-15s %-20s %-30s %s\n", 
		"IP Address", "Failures", "Status", "Ban Expires", "Last User", "Reason");
	ast_cli(a->fd, "%-20s %-10s %-15s %-20s %-30s %s\n",
		"--------------------", "----------", "---------------", "--------------------", 
		"------------------------------", "------");
	
	if (!blacklist) {
		ast_cli(a->fd, "Blacklist not initialized\n");
		return CLI_SUCCESS;
	}
	
	iter = ao2_iterator_init(blacklist, 0);
	while ((entry = ao2_iterator_next(&iter))) {
		char status[16];
		char expires[32];
		
		if (entry->is_banned) {
			if (entry->banned_until == 0) {
				strcpy(status, "PERMANENT");
				strcpy(expires, "NEVER");
			} else if (entry->banned_until > now) {
				strcpy(status, "BANNED");
				struct tm *tm = localtime(&entry->banned_until);
				strftime(expires, sizeof(expires), "%Y-%m-%d %H:%M:%S", tm);
			} else {
				/* Ban expired but flag not yet cleared */
				strcpy(status, "EXPIRED");
				strcpy(expires, "Clearing...");
			}
		} else {
			/* Not banned, just tracking failures */
			strcpy(status, "Tracking");
			strcpy(expires, "N/A");
		}
		
		ast_cli(a->fd, "%-20s %-10d %-15s %-20s %-30s %s\n",
			entry->ip_addr,
			entry->fail_count,
			status,
			expires,
			entry->last_user,
			entry->reason);
		count++;
		ao2_ref(entry, -1);
	}
	ao2_iterator_destroy(&iter);
	
	ast_cli(a->fd, "\nTotal: %d entries\n\n", count);
	
	/* Show blacklist configuration */
	struct sip_profile *profile;
	AST_RWLIST_RDLOCK(&profiles);
	AST_RWLIST_TRAVERSE(&profiles, profile, list) {
		if (profile->blacklist_enabled) {
			ast_cli(a->fd, "Profile '%s' blacklist: enabled (threshold=%d, duration=%d sec)\n",
				profile->name, profile->blacklist_threshold, profile->blacklist_duration);
		}
	}
	AST_RWLIST_UNLOCK(&profiles);
	
	return CLI_SUCCESS;
}

static char *sip_blacklist_add(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
{
	const char *ip_addr;
	int duration = SOFIA_DEFAULT_BAN_TIME;
	
	switch (cmd) {
	case CLI_INIT:
		e->command = "sip blacklist add";
		e->usage =
			"Usage: sip blacklist add <IP> [duration]\n"
			"       Manually add an IP to the blacklist.\n"
			"       Duration is in seconds (default: 3600).\n"
			"       Use duration=0 for permanent ban.\n";
		return NULL;
	case CLI_GENERATE:
		return NULL;
	}
	
	if (a->argc < 4 || a->argc > 5) {
		return CLI_SHOWUSAGE;
	}
	
	ip_addr = a->argv[3];
	
	/* Validate IP address */
	struct sockaddr_in sa;
	struct sockaddr_in6 sa6;
	if (inet_pton(AF_INET, ip_addr, &(sa.sin_addr)) != 1 &&
	    inet_pton(AF_INET6, ip_addr, &(sa6.sin6_addr)) != 1) {
		ast_cli(a->fd, "Invalid IP address: %s\n", ip_addr);
		return CLI_SUCCESS;
	}
	
	if (a->argc == 5) {
		duration = atoi(a->argv[4]);
		if (duration < 0) {
			ast_cli(a->fd, "Invalid duration: %s\n", a->argv[4]);
			return CLI_SUCCESS;
		}
	}
	
	sip_blacklist_ban(ip_addr, duration, "Manual ban via CLI");
	if (duration == 0) {
		ast_cli(a->fd, "IP %s permanently added to blacklist\n", ip_addr);
	} else {
		ast_cli(a->fd, "IP %s added to blacklist for %d seconds\n", ip_addr, duration);
	}
	
	return CLI_SUCCESS;
}

static char *sip_blacklist_del(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
{
	const char *ip_addr;
	
	switch (cmd) {
	case CLI_INIT:
		e->command = "sip blacklist del";
		e->usage =
			"Usage: sip blacklist del <IP>|all\n"
			"       Remove an IP from the blacklist.\n"
			"       Use 'all' to clear the entire blacklist.\n";
		return NULL;
	case CLI_GENERATE:
		return NULL;
	}
	
	if (a->argc != 4) {
		return CLI_SHOWUSAGE;
	}
	
	ip_addr = a->argv[3];
	
	if (!strcasecmp(ip_addr, "all")) {
		/* Clear entire blacklist */
		if (blacklist) {
			struct ao2_iterator iter;
			struct sip_blacklist_entry *entry;
			int count = 0;
			
			iter = ao2_iterator_init(blacklist, 0);
			while ((entry = ao2_iterator_next(&iter))) {
				ao2_unlink(blacklist, entry);
				ao2_ref(entry, -1);
				count++;
			}
			ao2_iterator_destroy(&iter);
			
			ast_cli(a->fd, "Cleared %d entries from blacklist\n", count);
		} else {
			ast_cli(a->fd, "Blacklist not initialized\n");
		}
	} else {
		/* Remove specific IP */
		/* Validate IP address */
		struct sockaddr_in sa;
		struct sockaddr_in6 sa6;
		if (inet_pton(AF_INET, ip_addr, &(sa.sin_addr)) != 1 &&
		    inet_pton(AF_INET6, ip_addr, &(sa6.sin6_addr)) != 1) {
			ast_cli(a->fd, "Invalid IP address: %s\n", ip_addr);
			return CLI_SUCCESS;
		}
		
		sip_blacklist_unban(ip_addr);
		ast_cli(a->fd, "IP %s removed from blacklist\n", ip_addr);
	}
	
	return CLI_SUCCESS;
}

static char *sip_show_authcache(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
{
	switch (cmd) {
	case CLI_INIT:
		e->command = "sip show authcache";
		e->usage =
			"Usage: sip show authcache\n"
			"       Display authentication cache entries.\n";
		return NULL;
	case CLI_GENERATE:
		return NULL;
	}
	
	if (a->argc != 3) {
		return CLI_SHOWUSAGE;
	}
	
	if (!auth_cache) {
		ast_cli(a->fd, "Authentication cache not initialized\n");
		return CLI_SUCCESS;
	}
	
	struct ao2_iterator iter;
	struct sip_auth_cache_entry *entry;
	int count = 0;
	time_t now = time(NULL);
	
	ast_cli(a->fd, "\nAuthentication Cache\n");
	ast_cli(a->fd, "====================\n");
	ast_cli(a->fd, "%-40s %-15s %-10s %s\n", "Key (user:realm:nonce:uri)", "IP Address", "TTL", "Response");
	ast_cli(a->fd, "---------------------------------------------------------------------------\n");
	
	iter = ao2_iterator_init(auth_cache, 0);
	while ((entry = ao2_iterator_next(&iter))) {
		int ttl = (entry->expires > now) ? (entry->expires - now) : 0;
		
		/* Truncate key for display */
		char display_key[41];
		ast_copy_string(display_key, entry->key, sizeof(display_key));
		if (strlen(entry->key) > 40) {
			strcpy(display_key + 37, "...");
		}
		
		ast_cli(a->fd, "%-40s %-15s %-10d %s\n",
			display_key,
			entry->ip_addr[0] ? entry->ip_addr : "any",
			ttl,
			entry->response);
		
		count++;
		ao2_ref(entry, -1);
	}
	ao2_iterator_destroy(&iter);
	
	ast_cli(a->fd, "\nTotal entries: %d\n", count);
	
	return CLI_SUCCESS;
}

static char *sip_authcache_clear(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
{
	switch (cmd) {
	case CLI_INIT:
		e->command = "sip authcache clear";
		e->usage =
			"Usage: sip authcache clear\n"
			"       Clear all entries from the authentication cache.\n";
		return NULL;
	case CLI_GENERATE:
		return NULL;
	}
	
	if (a->argc != 3) {
		return CLI_SHOWUSAGE;
	}
	
	if (!auth_cache) {
		ast_cli(a->fd, "Authentication cache not initialized\n");
		return CLI_SUCCESS;
	}
	
	struct ao2_iterator iter;
	struct sip_auth_cache_entry *entry;
	int count = 0;
	
	iter = ao2_iterator_init(auth_cache, 0);
	while ((entry = ao2_iterator_next(&iter))) {
		ao2_unlink(auth_cache, entry);
		ao2_ref(entry, -1);
		count++;
	}
	ao2_iterator_destroy(&iter);
	
	ast_cli(a->fd, "Cleared %d entries from authentication cache\n", count);
	
	return CLI_SUCCESS;
}

/* Module load/unload */
static int load_module(void)
{
	ast_log(LOG_NOTICE, "Loading Sofia-SIP Channel Driver\n");

	/* Initialize Sofia-SIP */
	su_init();
	
	/* Create registrations hash table with 65536 buckets */
	registrations = ao2_container_alloc_hash(AO2_ALLOC_OPT_LOCK_MUTEX, 0,
		65536, registration_hash_fn, NULL, registration_cmp_fn);
	if (!registrations) {
		ast_log(LOG_ERROR, "Failed to create registrations container\n");
		return AST_MODULE_LOAD_FAILURE;
	}
	
	/* Initialize IP blacklist */
	if (sip_blacklist_init() < 0) {
		ast_log(LOG_ERROR, "Failed to initialize IP blacklist\n");
		ao2_ref(registrations, -1);
		return AST_MODULE_LOAD_FAILURE;
	}
	
	/* Initialize auth cache */
	if (sip_auth_cache_init() < 0) {
		ast_log(LOG_ERROR, "Failed to initialize auth cache\n");
		sip_blacklist_destroy();
		ao2_ref(registrations, -1);
		return AST_MODULE_LOAD_FAILURE;
	}
	
	/* Initialize subscription subsystem */
	if (sip_subscription_init() < 0) {
		ast_log(LOG_ERROR, "Failed to initialize subscription subsystem\n");
		sip_auth_cache_destroy();
		sip_blacklist_destroy();
		ao2_ref(registrations, -1);
		return AST_MODULE_LOAD_FAILURE;
	}
	
	/* Initialize publish subsystem */
	if (sip_publish_init() < 0) {
		ast_log(LOG_ERROR, "Failed to initialize publish subsystem\n");
		sip_subscription_destroy();
		sip_auth_cache_destroy();
		sip_blacklist_destroy();
		ao2_ref(registrations, -1);
		return AST_MODULE_LOAD_FAILURE;
	}
	
	/* Note: sofia_root will be created in the worker thread */
	
	/* Start worker thread - profiles will be started there */
	sofia_running = 1;
	if (ast_pthread_create_background(&sofia_thread, NULL, sofia_worker, NULL) < 0) {
		ast_log(LOG_ERROR, "Unable to create Sofia worker thread\n");
		su_deinit();
		return AST_MODULE_LOAD_FAILURE;
	}
	
	/* Wait a bit for the worker thread to initialize */
	usleep(500000); /* 500ms */


	/* Create format capabilities */
	if (!(sip_tech.capabilities = ast_format_cap_alloc(AST_FORMAT_CAP_FLAG_DEFAULT))) {
		return AST_MODULE_LOAD_FAILURE;
	}
	
	/* Add audio formats */
	ast_format_cap_append_by_type(sip_tech.capabilities, AST_MEDIA_TYPE_AUDIO);

	/* Register SIP channel technology */
	if (ast_channel_register(&sip_tech)) {
		ast_log(LOG_ERROR, "Unable to register SIP channel technology\n");
		ao2_ref(sip_tech.capabilities, -1);
		return AST_MODULE_LOAD_FAILURE;
	}

	/* Register CLI commands */
	ast_cli_register_multiple(sofia_cli, ARRAY_LEN(sofia_cli));
	
	/* Register PUBLISH CLI commands */
	sip_publish_register_cli();

	/* Register device state provider for BLF */
	if (ast_devstate_prov_add("SIP", sofia_devicestate_cb)) {
		ast_log(LOG_WARNING, "Unable to register SIP device state provider\n");
	}

	sofia_loaded = 1;
	
	ast_log(LOG_NOTICE, "Sofia-SIP Channel Driver loaded successfully\n");
	ast_log(LOG_NOTICE, "  Registered as: SIP\n");
	ast_log(LOG_NOTICE, "  Use Dial(SIP/...)\n");
	
	return AST_MODULE_LOAD_SUCCESS;
}

static int unload_module(void)
{
	struct sip_profile *profile;
	
	if (!sofia_loaded) {
		return 0;
	}

	ast_log(LOG_NOTICE, "Unloading Sofia-SIP Channel Driver\n");

	/* Unregister CLI commands */
	ast_cli_unregister_multiple(sofia_cli, ARRAY_LEN(sofia_cli));
	
	/* Unregister PUBLISH CLI commands */
	sip_publish_unregister_cli();

	/* Unregister device state provider */
	ast_devstate_prov_del("SIP");

	/* Unregister channel technology */
	ast_channel_unregister(&sip_tech);

	/* Shutdown NUAs before stopping thread */
	AST_RWLIST_RDLOCK(&profiles);
	AST_RWLIST_TRAVERSE(&profiles, profile, list) {
		if (profile->nua) {
			ast_log(LOG_NOTICE, "Shutting down profile %s\n", profile->name);
			nua_shutdown(profile->nua);
		}
	}
	AST_RWLIST_UNLOCK(&profiles);
	
	/* Stop worker thread */
	sofia_running = 0;
	if (sofia_root) {
		su_root_break(sofia_root);
	}
	if (sofia_thread != AST_PTHREADT_NULL) {
		pthread_join(sofia_thread, NULL);
		sofia_thread = AST_PTHREADT_NULL;
	}

	/* Destroy profiles */
	AST_RWLIST_WRLOCK(&profiles);
	while ((profile = AST_RWLIST_REMOVE_HEAD(&profiles, list))) {
		if (profile->nua) {
			nua_shutdown(profile->nua);
		}
		ast_mutex_destroy(&profile->lock);
		ast_free(profile);
	}
	AST_RWLIST_UNLOCK(&profiles);

	/* Destroy root */
	if (sofia_root) {
		su_root_destroy(sofia_root);
		sofia_root = NULL;
	}

	/* Deinitialize Sofia-SIP */
	su_deinit();

	/* Cleanup format capabilities */
	ao2_cleanup(sip_tech.capabilities);
	
	/* Cleanup registrations container */
	if (registrations) {
		ao2_ref(registrations, -1);
		registrations = NULL;
	}
	
	/* Cleanup blacklist */
	sip_blacklist_destroy();
	
	/* Cleanup auth cache */
	sip_auth_cache_destroy();
	
	/* Cleanup subscription subsystem */
	sip_subscription_destroy();
	
	/* Cleanup publish subsystem */
	sip_publish_destroy();
	
	/* Cleanup event queue */
	sofia_queue_destroy();

	sofia_loaded = 0;
	
	ast_log(LOG_NOTICE, "Sofia-SIP Channel Driver unloaded\n");
	return 0;
}

static int reload_module(void)
{
	ast_log(LOG_NOTICE, "Reloading Sofia-SIP Channel Driver configuration\n");
	
	/* Reload configuration */
	if (sip_config_load(1) < 0) {
		ast_log(LOG_ERROR, "Failed to reload SIP configuration\n");
		return AST_MODULE_LOAD_FAILURE;
	}
	
	ast_log(LOG_NOTICE, "Sofia-SIP Channel Driver configuration reloaded successfully\n");
	return AST_MODULE_LOAD_SUCCESS;
}

/* Handler function implementations */

/* Helper function to find existing registration by contact */
struct sip_registration *find_registration_by_contact(const char *aor, const char *contact)
{
	struct sip_registration tmp;
	struct sip_registration *reg;
	
	/* Create a temporary object for searching */
	ast_copy_string(tmp.aor, aor, sizeof(tmp.aor));
	ast_copy_string(tmp.contact, contact, sizeof(tmp.contact));
	
	/* Find by object - this will match both aor and contact */
	reg = ao2_find(registrations, &tmp, OBJ_SEARCH_OBJECT);
	
	return reg; /* Caller must ao2_ref(reg, -1) when done */
}

/* Helper function to count active registrations for an endpoint */

/* Helper function to find active registration for endpoint */
struct sip_registration *find_active_registration(struct sip_endpoint *endpoint)
{
	struct ao2_iterator iter;
	struct sip_registration *reg, *active = NULL;
	time_t now = time(NULL);
	
	if (!endpoint) {
		return NULL;
	}
	
	iter = ao2_iterator_init(registrations, 0);
	while ((reg = ao2_iterator_next(&iter))) {
		if (reg->endpoint == endpoint && reg->expires > now) {
			/* Found active registration */
			active = reg;
			/* Keep the reference */
			break;
		}
		ao2_ref(reg, -1);
	}
	ao2_iterator_destroy(&iter);
	
	return active; /* Caller must release reference */
}


/* Helper function to get all active registrations for an endpoint
 * This function will be used by the INVITE handler to implement ring_all_except_inuse functionality
 */
static struct ao2_container *get_endpoint_registrations(struct sip_endpoint *endpoint)
{
	struct ao2_container *regs;
	struct ao2_iterator iter;
	struct sip_registration *reg;
	time_t now = time(NULL);
	
	/* Create a container to hold the results */
	regs = ao2_container_alloc_list(AO2_ALLOC_OPT_LOCK_MUTEX, 0, NULL, NULL);
	if (!regs) {
		return NULL;
	}
	
	iter = ao2_iterator_init(registrations, 0);
	while ((reg = ao2_iterator_next(&iter))) {
		if (reg->endpoint == endpoint && reg->expires > 0 && reg->expires > now) {
			ao2_link(regs, reg);
		}
		ao2_ref(reg, -1);
	}
	ao2_iterator_destroy(&iter);
	
	return regs;
}

/* Helper function to schedule registration refresh */
void schedule_registration_refresh(struct sip_registration *reg)
{
	struct sip_profile *profile;
	int expires_seconds;
	int refresh_seconds;
	int refresh_percent;
	
	if (!reg || !reg->endpoint || !reg->endpoint->profile) {
		return;
	}
	
	profile = reg->endpoint->profile;
	if (!profile->sched) {
		ast_log(LOG_WARNING, "No scheduler context for profile %s\n", profile->name);
		return;
	}
	
	/* Cancel any existing refresh */
	if (reg->refresh_sched_id > -1) {
		AST_SCHED_DEL(profile->sched, reg->refresh_sched_id);
	}
	
	/* Calculate when to refresh */
	expires_seconds = reg->expires - time(NULL);
	if (expires_seconds <= 0) {
		return; /* Already expired */
	}
	
	/* Default to 90% if not configured */
	refresh_percent = profile->registration_refresh_percent > 0 ? 
		profile->registration_refresh_percent : 90;
	
	/* Schedule refresh at X% of expiry time */
	refresh_seconds = (expires_seconds * refresh_percent) / 100;
	
	/* Minimum 30 seconds */
	if (refresh_seconds < 30) {
		refresh_seconds = 30;
	}
	
	/* Don't refresh if we're already past the refresh point */
	if (refresh_seconds >= expires_seconds) {
		return;
	}
	
	/* Schedule the refresh - add reference for scheduler */
	ao2_ref(reg, +1);
	reg->refresh_sched_id = ast_sched_add(profile->sched, refresh_seconds * 1000, 
		registration_refresh_callback, reg);
	
	if (reg->refresh_sched_id < 0) {
		ast_log(LOG_ERROR, "Failed to schedule registration refresh for %s\n", reg->aor);
		ao2_ref(reg, -1); /* Release the reference we just added */
	} else {
		ast_log(LOG_DEBUG, "Scheduled registration refresh for %s in %d seconds (expires in %d)\n",
			reg->aor, refresh_seconds, expires_seconds);
	}
}

/* Helper function to check if User-Agent matches any allowed pattern */
int useragent_matches_allowed(const char *user_agent, struct sip_endpoint *endpoint)
{
	int i;
	
	if (!user_agent || !endpoint) {
		return 0;
	}
	
	/* If no useragent patterns configured, it's allowed */
	if (endpoint->num_useragents == 0 || !endpoint->require_useragent) {
		return 1;
	}
	
	/* Check each configured pattern (up to 3) */
	for (i = 0; i < endpoint->num_useragents && i < 3; i++) {
		if (endpoint->allowed_useragents[i][0]) {
			/* Handle USERAGENT placeholder */
			if (!strcmp(endpoint->allowed_useragents[i], "USERAGENT")) {
				/* If it's still a placeholder, we need to capture it */
				ast_copy_string(endpoint->allowed_useragents[i], user_agent, 
					sizeof(endpoint->allowed_useragents[i]));
				ast_log(LOG_NOTICE, "Captured User-Agent '%s' in slot %d for endpoint %s\n", 
					user_agent, i + 1, endpoint->name);
				return 1; /* Allow this registration since we're capturing */
			} else {
				/* Check if User-Agent starts with this pattern (case-sensitive) */
				if (!strncmp(user_agent, endpoint->allowed_useragents[i], 
						strlen(endpoint->allowed_useragents[i]))) {
					ast_log(LOG_DEBUG, "User-Agent '%s' matches allowed pattern '%s'\n", 
						user_agent, endpoint->allowed_useragents[i]);
					return 1;
				}
			}
		}
	}
	
	return 0;
}

/* Registration refresh callback - sends outbound REGISTER before expiry */
static int registration_refresh_callback(const void *data)
{
	struct sip_registration *reg = (struct sip_registration *)data;
	struct sip_profile *profile;
	time_t now = time(NULL);
	int remaining;
	
	if (!reg || !reg->endpoint) {
		return 0; /* Don't reschedule */
	}
	
	/* Check if registration is still valid */
	if (reg->expires <= 0 || reg->expires <= now) {
		ast_log(LOG_DEBUG, "Registration refresh skipped - already expired for %s\n", reg->aor);
		reg->refresh_sched_id = -1;
		ao2_ref(reg, -1); /* Release scheduler reference */
		return 0; /* Don't reschedule */
	}
	
	profile = reg->endpoint->profile;
	if (!profile || !profile->nua) {
		ast_log(LOG_WARNING, "No profile/nua for registration refresh of %s\n", reg->aor);
		reg->refresh_sched_id = -1;
		ao2_ref(reg, -1); /* Release scheduler reference */
		return 0;
	}
	
       remaining = reg->expires - now;
       ast_log(LOG_NOTICE, "Sending registration refresh for %s (expires in %d seconds)\n",
               reg->aor, remaining);

       /* Send REGISTER refresh */
       {
               nua_handle_t *nh;

               nh = nua_handle(profile->nua, NULL, TAG_END());
               if (nh) {
                       nua_register(nh,
                               SIPTAG_TO_STR(reg->aor),
                               SIPTAG_CONTACT_STR(reg->contact),
                               TAG_END());
                       nua_handle_destroy(nh);
               } else {
                       ast_log(LOG_WARNING, "Failed to create NUA handle for registration refresh of %s\n", reg->aor);
               }
       }
	
	/* Don't reschedule - we'll schedule a new refresh when we get the response */
	reg->refresh_sched_id = -1;
	ao2_ref(reg, -1); /* Release scheduler reference */
	return 0;
}

/* Helper function to mark expired registrations */

#if 0
/* OLD IMPLEMENTATION - Replaced by sip_register.c */
static void sofia_handle_register_old(struct sip_profile *profile, nua_handle_t *nh, sip_t const *sip, nua_t *nua, msg_t *msg, tagi_t tags[], nua_saved_event_t *saved)
{
	const char *to_user = NULL;
	char aor[256] = "";
	char contact_uri[512] = "";
	int expires = 3600;
	
	ast_verbose("=== SOFIA_HANDLE_REGISTER CALLED ===\n");
	
	struct sip_endpoint *endpoint;
	struct sip_registration *reg = NULL;
	char call_id[256] = "";
	uint32_t cseq = 0;
	const char *user_agent = "Unknown";
	struct sockaddr_in addr;
	time_t now = time(NULL);
	nua_event_data_t const *event_data = NULL;
	msg_t *response_msg = NULL;
	
	/* Get event data for proper response association */
	if (saved) {
		event_data = nua_event_data(saved);
		if (event_data && event_data->e_msg) {
			response_msg = event_data->e_msg;
		}
	}
	
/* Macro to send response with proper message association */
#define SEND_RESPONSE(...) do { \
	if (response_msg) { \
		nua_respond(nh, __VA_ARGS__, NUTAG_WITH_THIS_MSG(response_msg), TAG_END()); \
	} else { \
		nua_respond(nh, __VA_ARGS__, NUTAG_WITH_THIS(nua), TAG_END()); \
	} \
} while(0)

	ast_log(LOG_NOTICE, "Processing REGISTER request\n");
	
	/* RFC 3261 Section 10.3 Step 1-2: Basic validation */
	if (!sip || !sip->sip_from || !sip->sip_to || !sip->sip_call_id || !sip->sip_cseq) {
		ast_log(LOG_ERROR, "Invalid REGISTER - missing required headers\n");
		SEND_RESPONSE(SIP_400_BAD_REQUEST);
		return;
	}
	
	/* Extract Address of Record from To header (RFC 3261 Section 10.3 Step 5) */
	to_user = sip->sip_to->a_url->url_user;
	snprintf(aor, sizeof(aor), "%s@%s", 
		to_user ? to_user : "unknown",
		sip->sip_to->a_url->url_host ? sip->sip_to->a_url->url_host : profile->name);
	
	/* Get Call-ID and CSeq */
	ast_copy_string(call_id, sip->sip_call_id->i_id, sizeof(call_id));
	cseq = sip->sip_cseq->cs_seq;
	
	/* Get User-Agent if present */
	if (sip->sip_user_agent && sip->sip_user_agent->g_string) {
		user_agent = sip->sip_user_agent->g_string;
	}
	
	/* Get Path header if present (RFC 3327) */
	char path_header[2048] = "";
	if (sip->sip_path) {
		/* Path header uses same structure as Route header */
		sip_route_t *path = (sip_route_t *)sip->sip_path;
		char *path_ptr = path_header;
		size_t path_remaining = sizeof(path_header);
		su_home_t path_home[1] = { SU_HOME_INIT(path_home) };
		
		/* Concatenate all Path header values */
		while (path && path_remaining > 1) {
			const char *path_url = url_as_string(path_home, path->r_url);
			if (path_url) {
				int written = snprintf(path_ptr, path_remaining, "%s%s", 
					path_ptr == path_header ? "" : ",", path_url);
				if (written > 0 && written < path_remaining) {
					path_ptr += written;
					path_remaining -= written;
				}
			}
			path = path->r_next;
		}
		su_home_deinit(path_home);
		
		if (path_header[0]) {
			ast_log(LOG_DEBUG, "Path header found: %s\n", path_header);
		}
	}
	
	/* Get source address */
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	if (sip->sip_via) {
		if (sip->sip_via->v_host) {
			inet_pton(AF_INET, sip->sip_via->v_host, &addr.sin_addr);
		}
		if (sip->sip_via->v_port) {
			addr.sin_port = htons(atoi(sip->sip_via->v_port));
		} else {
			addr.sin_port = htons(profile->bindport);
		}
	}
	
	/* RFC 3261 Section 10.3 Step 6: Process Contact header */
	if (!sip->sip_contact) {
		/* Query for bindings */
		ast_log(LOG_DEBUG, "REGISTER query for %s\n", aor);
		/* TODO: Return current bindings */
		if (saved) {
			nua_event_data_t const *data = nua_event_data(saved);
			if (data && data->e_msg) {
				nua_respond(nh, SIP_200_OK,
					NUTAG_WITH_THIS_MSG(data->e_msg),
					TAG_END());
				return;
			}
		}
		nua_respond(nh, SIP_200_OK,
			NUTAG_WITH_THIS(nua),
			TAG_END());
		return;
	}
	
	/* Check for de-registration (Contact: *) */
	if (sip->sip_contact->m_url->url_user && 
	    !strcmp(sip->sip_contact->m_url->url_user, "*")) {
		/* Remove all bindings for this AOR */
		ast_log(LOG_NOTICE, "De-registration request for %s\n", aor);
		/* TODO: Remove bindings */
		if (saved) {
			nua_event_data_t const *data = nua_event_data(saved);
			if (data && data->e_msg) {
				nua_respond(nh, SIP_200_OK,
					NUTAG_WITH_THIS_MSG(data->e_msg),
					TAG_END());
				return;
			}
		}
		nua_respond(nh, SIP_200_OK,
			NUTAG_WITH_THIS(nua),
			TAG_END());
		return;
	}
	
	/* Build full contact URI */
	const url_t *url = sip->sip_contact->m_url;
	char port_str[16];
	snprintf(port_str, sizeof(port_str), "%d", profile->bindport);
	snprintf(contact_uri, sizeof(contact_uri), "sip:%s@%s:%s",
		url->url_user ? url->url_user : to_user,
		url->url_host ? url->url_host : "unknown",
		url->url_port ? url->url_port : port_str);
	
	/* RFC 3261 Section 10.3 Step 7: Get expiration time */
	if (sip->sip_contact->m_expires) {
		expires = atoi(sip->sip_contact->m_expires);
	} else if (sip->sip_expires) {
		expires = sip->sip_expires->ex_delta;
	}
	
	/* Enforce minimum expiration (RFC 3261 Section 10.3 Step 7) */
	if (expires > 0 && expires < 60) {
		ast_log(LOG_WARNING, "Registration interval too brief: %d\n", expires);
		if (saved) {
			nua_event_data_t const *data = nua_event_data(saved);
			if (data && data->e_msg) {
				nua_respond(nh, SIP_423_INTERVAL_TOO_BRIEF,
					NUTAG_WITH_THIS_MSG(data->e_msg),
					SIPTAG_MIN_EXPIRES_STR("60"),
					TAG_END());
				return;
			}
		}
		nua_respond(nh, SIP_423_INTERVAL_TOO_BRIEF,
			NUTAG_WITH_THIS(nua),
			SIPTAG_MIN_EXPIRES_STR("60"),
			TAG_END());
		return;
	}
	
	ast_log(LOG_NOTICE, "REGISTER request - AOR: %s, Contact: %s, Expires: %d, Call-ID: %s, CSeq: %u\n",
		aor, contact_uri, expires, call_id, cseq);
	
	/* Clean up expired registrations */
	cleanup_expired_registrations();
	
	/* Debug: Try to access authorization directly from unknown headers */
	if (sip->sip_unknown) {
		msg_unknown_t *u;
		for (u = sip->sip_unknown; u; u = u->un_next) {
			if (u->un_name) {
				ast_log(LOG_DEBUG, "Unknown header: %s: %s\n", u->un_name, u->un_value ? u->un_value : "");
				if (!strcasecmp(u->un_name, "Authorization")) {
					ast_log(LOG_NOTICE, "Found Authorization as unknown header: %s\n", u->un_value);
				}
			}
		}
	}
	
	/* Debug all headers */
	if (sip_debug) {
		ast_log(LOG_NOTICE, "Headers: From=%s, To=%s, Call-ID=%s, CSeq=%d %s\n",
			sip->sip_from ? sip->sip_from->a_url->url_user : "none",
			sip->sip_to ? sip->sip_to->a_url->url_user : "none",
			sip->sip_call_id ? sip->sip_call_id->i_id : "none",
			sip->sip_cseq ? (int)sip->sip_cseq->cs_seq : 0,
			sip->sip_cseq ? sip->sip_cseq->cs_method_name : "none");
	}
	
	/* Find the endpoint - use to_user for AOR matching */
	endpoint = sip_endpoint_find(profile, to_user);
	if (!endpoint) {
		ast_log(LOG_WARNING, "Unknown endpoint '%s' trying to register\n", to_user);
		
		/* Track auth failure for unknown endpoint */
		/* BLACKLIST DISABLED FOR TESTING - DO NOT ENABLE */
		#if 0
		char ip_addr[INET6_ADDRSTRLEN];
		#endif
		/* BLACKLIST DISABLED FOR TESTING - DO NOT ENABLE */
		#if 0
		if (msg && get_source_ip(msg, ip_addr, sizeof(ip_addr)) == 0) {
			sip_blacklist_add_failure(ip_addr, to_user, "Unknown endpoint");
		}
		#endif
		
		nua_respond(nh, SIP_404_NOT_FOUND,
			NUTAG_WITH_THIS(nua),
			TAG_END());
		return;
	}
	
	/* Check existing registration by contact */
	reg = find_registration_by_contact(aor, contact_uri);
	
	/* Check if this is an authenticated request - also check unknown headers */
	sip_authorization_t const *auth = sip->sip_authorization ? sip->sip_authorization : sip->sip_proxy_authorization;
	char *auth_header_value = NULL;
	
	/* If not found in parsed headers, check unknown headers */
	if (!auth && sip->sip_unknown) {
		msg_unknown_t *u;
		for (u = sip->sip_unknown; u; u = u->un_next) {
			if (u->un_name && !strcasecmp(u->un_name, "Authorization")) {
				auth_header_value = ast_strdupa(u->un_value);
				ast_log(LOG_DEBUG, "Found Authorization in unknown headers: %s\n", auth_header_value);
				break;
			}
		}
	}
	
	/* If still not found and we have a message, try to parse it from there */
	if (!auth && !auth_header_value && msg) {
		sip_t *full_sip = sip_object(msg);
		if (full_sip && full_sip->sip_authorization) {
			auth = full_sip->sip_authorization;
			ast_log(LOG_DEBUG, "Found Authorization in full message\n");
		}
	}
	
	/* Check if request has authorization - if not, always challenge */
	ast_verbose(">>> REGISTER AUTH CHECK: auth=%p, auth_header_value=%p\n", auth, auth_header_value);
	if (!auth && !auth_header_value) {
		/* No authorization present - send 401 challenge */
		char realm[256];
		char nonce[256];
		char auth_header[1024];
		time_t current_time = time(NULL);
		int nonce_valid_time = profile->nonce_ttl > 0 ? profile->nonce_ttl : 30;
		
		snprintf(realm, sizeof(realm), "%s", profile->name);
		
		/* Lock profile for nonce access */
		ast_mutex_lock(&profile->lock);
		
		/* Check if we should reuse the cached nonce */
		if (profile->cached_nonce[0] && 
		    (current_time - profile->nonce_generated) < nonce_valid_time) {
			/* Reuse existing nonce */
			ast_copy_string(nonce, profile->cached_nonce, sizeof(nonce));
			ast_log(LOG_DEBUG, "Reusing cached nonce for profile %s: %s (age: %ld seconds)\n", 
				profile->name, nonce, current_time - profile->nonce_generated);
		} else {
			/* Generate new nonce */
			snprintf(nonce, sizeof(nonce), "%08x", (unsigned int)current_time);
			ast_copy_string(profile->cached_nonce, nonce, sizeof(profile->cached_nonce));
			profile->nonce_generated = current_time;
			ast_log(LOG_DEBUG, "Generated new nonce for profile %s: %s\n", 
				profile->name, nonce);
		}
		
		ast_mutex_unlock(&profile->lock);
		
		snprintf(auth_header, sizeof(auth_header), 
			"Digest realm=\"%s\", nonce=\"%s\", algorithm=MD5",
			realm, nonce);
		
		ast_log(LOG_DEBUG, "Sending 401 Unauthorized challenge\n");
		SEND_RESPONSE(SIP_401_UNAUTHORIZED,
			SIPTAG_WWW_AUTHENTICATE_STR(auth_header));
		return;
	}
	
	/* Validate the authorization response */
	ast_verbose(">>> VALIDATING AUTH: auth=%p, auth->au_params=%p\n", auth, auth ? auth->au_params : NULL);
	if (auth && auth->au_params) {
		const char *auth_user = NULL;
		const char *auth_realm = NULL;
		const char *auth_nonce = NULL;
		const char *auth_uri = NULL;
		const char *auth_response = NULL;
		int i;
		
		/* Parse auth parameters */
		for (i = 0; auth->au_params[i]; i++) {
			const char *param = auth->au_params[i];
			const char *val;
			
			if ((val = extract_auth_param(param, "username"))) {
				auth_user = ast_strdupa(val);
				char *p = strchr(auth_user, '"');
				if (p) *p = '\0';
			} else if ((val = extract_auth_param(param, "realm"))) {
				auth_realm = ast_strdupa(val);
				char *p = strchr(auth_realm, '"');
				if (p) *p = '\0';
			} else if ((val = extract_auth_param(param, "nonce"))) {
				auth_nonce = ast_strdupa(val);
				char *p = strchr(auth_nonce, '"');
				if (p) *p = '\0';
			} else if ((val = extract_auth_param(param, "uri"))) {
				auth_uri = ast_strdupa(val);
				char *p = strchr(auth_uri, '"');
				if (p) *p = '\0';
			} else if ((val = extract_auth_param(param, "response"))) {
				auth_response = ast_strdupa(val);
				char *p = strchr(auth_response, '"');
				if (p) *p = '\0';
			}
		}
		
		ast_log(LOG_DEBUG, "Auth params - user: %s, realm: %s, nonce: %s, uri: %s, response: %s\n",
			auth_user ? auth_user : "none",
			auth_realm ? auth_realm : "none",
			auth_nonce ? auth_nonce : "none",
			auth_uri ? auth_uri : "none",
			auth_response ? auth_response : "none");
		
		/* Calculate expected response */
		if (auth_user && auth_realm && auth_nonce && auth_uri && auth_response) {
			char ip_addr[INET6_ADDRSTRLEN] = "";
			int auth_valid = 0;
			
			/* Get source IP for cache validation */
			if (msg) {
				get_source_ip(msg, ip_addr, sizeof(ip_addr));
			}
			
			/* Check auth cache first if enabled */
			if (profile->auth_cache_enabled) {
				if (sip_auth_cache_check(auth_user, auth_realm, auth_nonce, 
						auth_uri, auth_response, ip_addr)) {
					ast_log(LOG_DEBUG, "Auth cache hit for %s - skipping MD5 calculation\n", auth_user);
					auth_valid = 1;
				}
			}
			
			/* If not in cache, calculate MD5 */
			if (!auth_valid) {
				char a1_input[256];
				char a2_input[256];
				char final_input[512];
				su_md5_t md5_ctx;
				unsigned char a1_hash[SU_MD5_DIGEST_SIZE], a2_hash[SU_MD5_DIGEST_SIZE], final_hash[SU_MD5_DIGEST_SIZE];
				char a1_hex[33], a2_hex[33], final_hex[33];
				
				/* A1 = MD5(username:realm:password) */
			snprintf(a1_input, sizeof(a1_input), "%s:%s:%s", auth_user, auth_realm, endpoint->secret);
			su_md5_init(&md5_ctx);
			su_md5_update(&md5_ctx, a1_input, strlen(a1_input));
			su_md5_digest(&md5_ctx, a1_hash);
			for (i = 0; i < SU_MD5_DIGEST_SIZE; i++) {
				sprintf(a1_hex + i*2, "%02x", a1_hash[i]);
			}
			a1_hex[32] = '\0';
			
			/* A2 = MD5(method:uri) */
			snprintf(a2_input, sizeof(a2_input), "REGISTER:%s", auth_uri);
			su_md5_init(&md5_ctx);
			su_md5_update(&md5_ctx, a2_input, strlen(a2_input));
			su_md5_digest(&md5_ctx, a2_hash);
			for (i = 0; i < SU_MD5_DIGEST_SIZE; i++) {
				sprintf(a2_hex + i*2, "%02x", a2_hash[i]);
			}
			a2_hex[32] = '\0';
			
			/* Response = MD5(A1:nonce:A2) */
			snprintf(final_input, sizeof(final_input), "%s:%s:%s", a1_hex, auth_nonce, a2_hex);
			su_md5_init(&md5_ctx);
			su_md5_update(&md5_ctx, final_input, strlen(final_input));
			su_md5_digest(&md5_ctx, final_hash);
			for (i = 0; i < SU_MD5_DIGEST_SIZE; i++) {
				sprintf(final_hex + i*2, "%02x", final_hash[i]);
			}
			final_hex[32] = '\0';
			
			ast_log(LOG_DEBUG, "Calculated digest: %s, received: %s\n", final_hex, auth_response);
			
			if (strcasecmp(final_hex, auth_response) != 0) {
				ast_log(LOG_WARNING, "Authentication failed for user '%s'\n", auth_user);
				
				/* Track auth failure in blacklist */
				/* BLACKLIST DISABLED FOR TESTING - DO NOT ENABLE */
				#if 0
				char ip_addr[INET6_ADDRSTRLEN];
				#endif
				/* BLACKLIST DISABLED FOR TESTING - DO NOT ENABLE */
				#if 0
				if (msg && get_source_ip(msg, ip_addr, sizeof(ip_addr)) == 0) {
					sip_blacklist_add_failure(ip_addr, auth_user, "Invalid credentials");
				}
				#endif
				
				nua_respond(nh, SIP_403_FORBIDDEN,
					NUTAG_WITH_THIS(nua),
					TAG_END());
				return;
			}
			
			ast_log(LOG_DEBUG, "Authentication successful for user '%s'\n", auth_user);
			
			/* Store successful auth in cache */
			if (profile->auth_cache_enabled) {
				ast_verbose(">>> STORING AUTH IN CACHE: user=%s realm=%s nonce=%s uri=%s ttl=%d\n",
					auth_user, auth_realm, auth_nonce, auth_uri, profile->auth_cache_ttl);
				sip_auth_cache_store(auth_user, auth_realm, auth_nonce,
					auth_uri, auth_response, ip_addr, profile->auth_cache_ttl);
			} else {
				ast_log(LOG_WARNING, "AUTH CACHE DISABLED for profile %s\n", profile->name);
			}
			
			/* Check User-Agent requirement if configured */
			if (endpoint->require_useragent && endpoint->num_useragents > 0) {
				if (!user_agent || !useragent_matches_allowed(user_agent, endpoint)) {
					ast_log(LOG_WARNING, "User-Agent mismatch for %s - received: %s\n",
						auth_user, user_agent ? user_agent : "none");
					
					/* Track auth failure for wrong User-Agent in blacklist */
					char ip_addr[INET6_ADDRSTRLEN];
					if (msg && get_source_ip(msg, ip_addr, sizeof(ip_addr)) == 0) {
						sip_blacklist_add_failure(ip_addr, auth_user, "Invalid User-Agent");
					}
					
					nua_respond(nh, SIP_403_FORBIDDEN,
						NUTAG_WITH_THIS(nua),
						TAG_END());
					return;
				}
				ast_log(LOG_DEBUG, "User-Agent validation passed for %s\n", auth_user);
			}
			
			/* Reset blacklist failure counter on successful auth */
			/* BLACKLIST DISABLED FOR TESTING - DO NOT ENABLE */
			#if 0
			char ip_addr[INET6_ADDRSTRLEN];
			#endif
			/* BLACKLIST DISABLED FOR TESTING - DO NOT ENABLE */
			#if 0
			if (msg && get_source_ip(msg, ip_addr, sizeof(ip_addr)) == 0) {
				sip_blacklist_reset_failures(ip_addr);
			}
			#endif
		} else {
			ast_log(LOG_WARNING, "Missing auth parameters\n");
			nua_respond(nh, SIP_400_BAD_REQUEST,
				NUTAG_WITH_THIS(nua),
				TAG_END());
			return;
		}
		}
	} else if (auth_header_value) {
		/* Manual parsing of Authorization header from unknown headers */
		const char *auth_user = NULL;
		const char *auth_realm = NULL;
		const char *auth_nonce = NULL;
		const char *auth_uri = NULL;
		const char *auth_response = NULL;
		char *p, *token, *saveptr;
		char *auth_copy = ast_strdupa(auth_header_value);
		
		/* Skip "Digest " prefix */
		if (strncasecmp(auth_copy, "Digest ", 7) == 0) {
			auth_copy += 7;
		}
		
		/* Parse comma-separated parameters */
		for (token = strtok_r(auth_copy, ",", &saveptr); token; token = strtok_r(NULL, ",", &saveptr)) {
			while (*token == ' ') token++; /* Skip leading spaces */
			
			if (!strncmp(token, "username=", 9)) {
				auth_user = token + 9;
				if (*auth_user == '"') {
					auth_user++;
					p = strchr(auth_user, '"');
					if (p) *p = '\0';
				}
				auth_user = ast_strdupa(auth_user);
			} else if (!strncmp(token, "realm=", 6)) {
				auth_realm = token + 6;
				if (*auth_realm == '"') {
					auth_realm++;
					p = strchr(auth_realm, '"');
					if (p) *p = '\0';
				}
				auth_realm = ast_strdupa(auth_realm);
			} else if (!strncmp(token, "nonce=", 6)) {
				auth_nonce = token + 6;
				if (*auth_nonce == '"') {
					auth_nonce++;
					p = strchr(auth_nonce, '"');
					if (p) *p = '\0';
				}
				auth_nonce = ast_strdupa(auth_nonce);
			} else if (!strncmp(token, "uri=", 4)) {
				auth_uri = token + 4;
				if (*auth_uri == '"') {
					auth_uri++;
					p = strchr(auth_uri, '"');
					if (p) *p = '\0';
				}
				auth_uri = ast_strdupa(auth_uri);
			} else if (!strncmp(token, "response=", 9)) {
				auth_response = token + 9;
				if (*auth_response == '"') {
					auth_response++;
					p = strchr(auth_response, '"');
					if (p) *p = '\0';
				}
				auth_response = ast_strdupa(auth_response);
			}
		}
		
		ast_log(LOG_DEBUG, "Manual parse - user: %s, realm: %s, nonce: %s, uri: %s, response: %s\n",
			auth_user ? auth_user : "none",
			auth_realm ? auth_realm : "none",
			auth_nonce ? auth_nonce : "none",
			auth_uri ? auth_uri : "none",
			auth_response ? auth_response : "none");
		
		/* Validate the parsed values */
		if (auth_user && auth_realm && auth_nonce && auth_uri && auth_response) {
			char ip_addr[INET6_ADDRSTRLEN] = "";
			int auth_valid = 0;
			
			/* Get source IP for cache validation */
			if (msg) {
				get_source_ip(msg, ip_addr, sizeof(ip_addr));
			}
			
			/* Remove @ from username if present */
			char *auth_user_clean = ast_strdupa(auth_user);
			char *at = strchr(auth_user_clean, '@');
			if (at) *at = '\0';
			
			/* Check auth cache first if enabled */
			if (profile->auth_cache_enabled) {
				auth_valid = sip_auth_cache_check(auth_user_clean, auth_realm, auth_nonce, 
					auth_uri, auth_response, ip_addr);
				if (auth_valid) {
					ast_log(LOG_DEBUG, "Auth cache hit for user '%s' - skipping MD5 calculation\n", auth_user_clean);
				}
			}
			
			/* If not in cache, calculate MD5 */
			if (!auth_valid) {
				char a1_input[256];
				char a2_input[256];
				char final_input[512];
				su_md5_t md5_ctx;
				unsigned char a1_hash[SU_MD5_DIGEST_SIZE], a2_hash[SU_MD5_DIGEST_SIZE], final_hash[SU_MD5_DIGEST_SIZE];
				char a1_hex[33], a2_hex[33], final_hex[33];
				int i;
				
				/* A1 = MD5(username:realm:password) */
				snprintf(a1_input, sizeof(a1_input), "%s:%s:%s", auth_user_clean, auth_realm, endpoint->secret);
				su_md5_init(&md5_ctx);
				su_md5_update(&md5_ctx, a1_input, strlen(a1_input));
				su_md5_digest(&md5_ctx, a1_hash);
				for (i = 0; i < SU_MD5_DIGEST_SIZE; i++) {
					sprintf(a1_hex + i*2, "%02x", a1_hash[i]);
				}
				a1_hex[32] = '\0';
				
				/* A2 = MD5(method:uri) */
				snprintf(a2_input, sizeof(a2_input), "REGISTER:%s", auth_uri);
				su_md5_init(&md5_ctx);
				su_md5_update(&md5_ctx, a2_input, strlen(a2_input));
				su_md5_digest(&md5_ctx, a2_hash);
				for (i = 0; i < SU_MD5_DIGEST_SIZE; i++) {
					sprintf(a2_hex + i*2, "%02x", a2_hash[i]);
				}
				a2_hex[32] = '\0';
				
				/* Response = MD5(A1:nonce:A2) */
				snprintf(final_input, sizeof(final_input), "%s:%s:%s", a1_hex, auth_nonce, a2_hex);
				su_md5_init(&md5_ctx);
				su_md5_update(&md5_ctx, final_input, strlen(final_input));
				su_md5_digest(&md5_ctx, final_hash);
				for (i = 0; i < SU_MD5_DIGEST_SIZE; i++) {
					sprintf(final_hex + i*2, "%02x", final_hash[i]);
				}
				final_hex[32] = '\0';
				
				ast_log(LOG_DEBUG, "Calculated digest: %s, received: %s\n", final_hex, auth_response);
				
				if (strcasecmp(final_hex, auth_response) == 0) {
					auth_valid = 1;
					/* Store successful auth in cache */
					if (profile->auth_cache_enabled) {
						ast_verbose(">>> STORING AUTH IN CACHE (PATH2): user=%s realm=%s nonce=%s uri=%s ttl=%d\n",
							auth_user_clean, auth_realm, auth_nonce, auth_uri, profile->auth_cache_ttl);
						sip_auth_cache_store(auth_user_clean, auth_realm, auth_nonce,
							auth_uri, auth_response, ip_addr, profile->auth_cache_ttl);
					}
				}
			}
			
			if (!auth_valid) {
				ast_log(LOG_WARNING, "Authentication failed for user '%s'\n", auth_user_clean);
				
				/* Track auth failure in blacklist */
				/* BLACKLIST DISABLED FOR TESTING - DO NOT ENABLE */
				#if 0
				if (ip_addr[0]) {
					sip_blacklist_add_failure(ip_addr, auth_user_clean, "Invalid credentials");
				}
				#endif
				
				nua_respond(nh, SIP_403_FORBIDDEN,
					NUTAG_WITH_THIS(nua),
					TAG_END());
				return;
			}
			
			ast_log(LOG_DEBUG, "Authentication successful for user '%s'\n", auth_user_clean);
			
			/* Check User-Agent requirement if configured */
			if (endpoint->require_useragent && endpoint->num_useragents > 0) {
				if (!user_agent || !useragent_matches_allowed(user_agent, endpoint)) {
					ast_log(LOG_WARNING, "User-Agent mismatch for %s - received: %s\n",
						auth_user_clean, user_agent ? user_agent : "none");
					
					/* Track auth failure for wrong User-Agent in blacklist */
					if (ip_addr[0]) {
						sip_blacklist_add_failure(ip_addr, auth_user_clean, "Invalid User-Agent");
					}
					
					nua_respond(nh, SIP_403_FORBIDDEN,
						NUTAG_WITH_THIS(nua),
						TAG_END());
					return;
				}
				ast_log(LOG_DEBUG, "User-Agent validation passed for %s\n", auth_user_clean);
			}
			
			/* Reset blacklist failure counter on successful auth */
			/* BLACKLIST DISABLED FOR TESTING - DO NOT ENABLE */
			#if 0
			if (ip_addr[0]) {
				sip_blacklist_reset_failures(ip_addr);
			}
			#endif
		} else {
			ast_log(LOG_WARNING, "Missing auth parameters in manual parse\n");
			nua_respond(nh, SIP_400_BAD_REQUEST,
				NUTAG_WITH_THIS(nua),
				TAG_END());
			return;
		}
	} else {
		ast_log(LOG_WARNING, "Invalid authorization header\n");
		nua_respond(nh, SIP_400_BAD_REQUEST,
			NUTAG_WITH_THIS(nua),
			TAG_END());
		return;
	}
	
	/* RFC 3261 Section 10.3 Step 7: Update or create registration binding */
	if (expires > 0) {
		/* Register or update */
		if (reg) {
			/* RFC 3261: If Call-ID is different, it's a new registration (e.g. phone restart).
			 * The old entry should be replaced. CSeq check doesn't apply. */
			if (strcmp(reg->call_id, call_id) != 0) {
				ast_log(LOG_NOTICE, "New Call-ID detected for existing Contact. Replacing registration for %s.\n", aor);
				/* The 'reg' entry is now obsolete. We'll treat it as a new creation below. */
				ao2_unlink(registrations, reg); /* Remove old entry from container */
				ao2_ref(reg, -1);                /* Release find reference */
				reg = NULL;                      /* Set to NULL to force new entry creation */
			} else {
				/* If Call-ID is the same, it's a refresh. Check CSeq. */
				if (cseq <= reg->cseq) {
					ast_log(LOG_WARNING, "Out of order REGISTER - CSeq %u <= %u\n", cseq, reg->cseq);
					ao2_ref(reg, -1); /* Release find reference */
					nua_respond(nh, SIP_400_BAD_REQUEST,
						NUTAG_WITH_THIS(nua),
						TAG_END());
					return;
				}
				/* Update existing registration */
				ao2_lock(reg);
				ast_copy_string(reg->contact, contact_uri, sizeof(reg->contact));
				ast_copy_string(reg->user_agent, user_agent, sizeof(reg->user_agent));
				ast_copy_string(reg->path, path_header, sizeof(reg->path));
				reg->cseq = cseq;
				reg->registered = now;
				reg->expires = now + expires;
				memcpy(&reg->addr, &addr, sizeof(addr));
				ao2_unlock(reg);
				ast_log(LOG_NOTICE, "Updated registration for %s (expires in %d seconds)%s\n", 
					aor, expires, path_header[0] ? " with Path" : "");
				
				/* Schedule refresh if enabled */
				schedule_registration_refresh(reg);
				
				ao2_ref(reg, -1); /* Release find reference */
			}
		}
		
		/* If reg is NULL (because it didn't exist or we set it to NULL above), create new entry */
		if (!reg) {
			/* Check max_contacts limit before creating new registration */
			int max_contacts = endpoint->max_contacts > 0 ? endpoint->max_contacts :
				(profile->max_contacts_global > 0 ? profile->max_contacts_global : 3);
			int active_count = count_active_registrations(endpoint);
			
			if (active_count >= max_contacts) {
				/* Remove oldest registration to make room */
				ast_log(LOG_NOTICE, "Max contacts limit (%d) reached for %s, removing oldest\n",
					max_contacts, endpoint->name);
				remove_oldest_registration(endpoint);
			}
			
			/* Create new registration */
			reg = ao2_alloc(sizeof(*reg), registration_destructor);
			if (!reg) {
				ast_log(LOG_ERROR, "Failed to allocate registration record\n");
				nua_respond(nh, SIP_500_INTERNAL_SERVER_ERROR,
					NUTAG_WITH_THIS(nua),
					TAG_END());
				return;
			}
			reg->endpoint = endpoint;
			ast_copy_string(reg->aor, aor, sizeof(reg->aor));
			ast_copy_string(reg->contact, contact_uri, sizeof(reg->contact));
			ast_copy_string(reg->call_id, call_id, sizeof(reg->call_id));
			reg->cseq = cseq;
			ast_copy_string(reg->user_agent, user_agent, sizeof(reg->user_agent));
			ast_copy_string(reg->path, path_header, sizeof(reg->path));
			reg->registered = now;
			reg->expires = now + expires;
			memcpy(&reg->addr, &addr, sizeof(addr));
			reg->refresh_sched_id = -1; /* Initialize scheduler ID */
			
			ao2_link(registrations, reg);
			endpoint->registration_count = count_active_registrations(endpoint);
			
			char addr_str[INET_ADDRSTRLEN];
			inet_ntop(AF_INET, &addr.sin_addr, addr_str, sizeof(addr_str));
			ast_log(LOG_NOTICE, "New registration for %s from %s:%d (expires in %d seconds)%s - Total: %d/%d\n", 
				aor, addr_str, ntohs(addr.sin_port), expires, 
				path_header[0] ? " with Path" : "",
				endpoint->registration_count, max_contacts);
			
			/* Schedule refresh if enabled */
			schedule_registration_refresh(reg);
		}
		sofia_update_peer_status(endpoint, 1);
	} else {
		/* Unregister - expires = 0 */
		if (reg) {
			/* Mark as expired but keep the registration like chan_sip */
			ao2_lock(reg);
			reg->expires = -1;
			ao2_unlock(reg);
			ao2_ref(reg, -1); /* Release find reference */
			ast_log(LOG_NOTICE, "Registration expired for %s (unregistered)\n", aor);
		}
		sofia_update_peer_status(endpoint, 0);
	}
	
	/* RFC 3261 Section 10.3 Step 8: Send 200 OK with all current bindings */
	char date_buf[64];
	struct tm tm;
	time_t date_time = time(NULL);
	gmtime_r(&date_time, &tm);
	strftime(date_buf, sizeof(date_buf), "%a, %d %b %Y %H:%M:%S GMT", &tm);
	
	/* Build Contact headers for all current bindings for this AOR */
	sip_contact_t *contact_list = NULL;
	sip_contact_t **contact_tail = &contact_list;
	struct sip_registration *binding;
	int binding_count = 0;
	su_home_t home[1] = { SU_HOME_INIT(home) };
	
	/* Build contact list for all bindings with this AOR */
	struct ao2_iterator iter;
	iter = ao2_iterator_init(registrations, 0);
	while ((binding = ao2_iterator_next(&iter))) {
		if (!strcasecmp(binding->aor, aor) && binding->expires > 0) {
			int remaining = binding->expires - now;
			if (remaining > 0) {
				char contact_str[1024];
				snprintf(contact_str, sizeof(contact_str), "<%s>;expires=%d", 
					binding->contact, remaining);
				*contact_tail = sip_contact_make(home, contact_str);
				if (*contact_tail) {
					contact_tail = &(*contact_tail)->m_next;
					binding_count++;
				}
			}
		}
		ao2_ref(binding, -1);
	}
	ao2_iterator_destroy(&iter);
	
	ast_log(LOG_DEBUG, "Sending 200 OK with %d contact bindings\n", binding_count);
	
	if (saved) {
		nua_event_data_t const *data = nua_event_data(saved);
		if (data && data->e_msg) {
			nua_respond(nh, SIP_200_OK,
				NUTAG_WITH_THIS_MSG(data->e_msg),
				SIPTAG_DATE_STR(date_buf),
				TAG_IF(contact_list, SIPTAG_CONTACT(contact_list)),
				TAG_END());
		} else {
			nua_respond(nh, SIP_200_OK,
				NUTAG_WITH_THIS(nua),
				SIPTAG_DATE_STR(date_buf),
				TAG_IF(contact_list, SIPTAG_CONTACT(contact_list)),
				TAG_END());
		}
	} else {
		nua_respond(nh, SIP_200_OK,
			NUTAG_WITH_THIS(nua),
			SIPTAG_DATE_STR(date_buf),
			TAG_IF(contact_list, SIPTAG_CONTACT(contact_list)),
			TAG_END());
	}
	
	/* Clean up home allocation */
	su_home_deinit(home);
	
	/* Release endpoint reference */
	if (endpoint) {
		ao2_ref(endpoint, -1);
	}
}
#endif /* OLD IMPLEMENTATION */

/* New implementation - wrapper to call handle_register_request from sip_register.c */
static void sofia_handle_register(struct sip_profile *profile, nua_handle_t *nh, sip_t const *sip, nua_t *nua, msg_t *msg, tagi_t tags[], nua_saved_event_t *saved)
{
	handle_register_request(profile, nh, sip, nua, msg, tags, saved);
}

static void sofia_handle_message(struct sip_profile *profile, nua_handle_t *nh, sip_t const *sip, nua_t *nua)
{
	/* TODO: Implement MESSAGE handling */
	nua_respond(nh, SIP_200_OK, NUTAG_WITH_THIS(nua), TAG_END());
}


AST_MODULE_INFO(GABPBX_GPL_KEY, AST_MODFLAG_LOAD_ORDER, "Sofia-SIP Channel Driver",
	.support_level = AST_MODULE_SUPPORT_EXTENDED,
	.load = load_module,
	.unload = unload_module,
	.reload = reload_module,
	.load_pri = AST_MODPRI_CHANNEL_DRIVER,
	.requires = "res_rtp_gabpbx",
);
