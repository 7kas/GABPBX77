/*
 * GABpbx -- An open source telephony toolkit.
 *
 * Copyright (C) 2025, 7kas servicios de internet SL
 *
 * Germán Aracil Boned <garacilb@gmail.com>
 *
 * INVITE Method Implementation for chan_sofia
 *
 * This file contains all INVITE-related functionality extracted from chan_sofia.c
 * to improve code organization and maintainability.
 * 
 * GABpbx is a fork of Asterisk 22
 */

/* Handler function for incoming INVITE requests */
void sofia_handle_invite(struct sip_profile *profile, nua_handle_t *nh, sip_t const *sip, nua_t *nua, nua_saved_event_t *saved)
{
	/* NOTE: This function is now called from worker threads, not Sofia event thread */
#if 1  /* Re-enable INVITE processing */
	const char *from_user = NULL;
	const char *from_host = NULL;
	const char *from_tag = NULL;
	const char *to_user = NULL;
	const char *to_host = NULL;
	const char *to_tag = NULL;
	const char *call_id = NULL;
	const char *cseq_method = NULL;
	const char *contact_uri = NULL;
	const char *user_agent = NULL;
	const char *content_type = NULL;
	const char *supported = NULL;
	const char *require = NULL;
	const char *allow = NULL;
	const char *accept = NULL;
	uint32_t cseq_number = 0;
	int max_forwards = 70;
	int se_value = 0;
	int minse_value = 0;
	const char *refresher_param = NULL;
	struct sofia_pvt *pvt;
	char source_ip[INET6_ADDRSTRLEN] = "";
	int source_port = 0;
	/* struct ast_channel *chan; */
	
	/* RFC3261: INVITE must contain To, From, Call-ID, CSeq, Contact, Via headers */
	if (!sip || !sip->sip_from || !sip->sip_to || !sip->sip_call_id || 
	    !sip->sip_cseq || !sip->sip_contact || !sip->sip_via) {
		ast_log(LOG_WARNING, "INVITE missing required headers\n");
		nua_respond(nh, SIP_400_BAD_REQUEST, 
			SIPTAG_WARNING_STR("399 " SIP_USER_AGENT " \"Missing required headers\""),
			TAG_END());
		return;
	}
	
	/* Extract From header information */
	from_user = sip->sip_from->a_url->url_user;
	from_host = sip->sip_from->a_url->url_host;
	from_tag = sip->sip_from->a_tag;
	
	/* Extract To header information */
	to_user = sip->sip_to->a_url->url_user;
	to_host = sip->sip_to->a_url->url_host;
	to_tag = sip->sip_to->a_tag;
	
	/* Extract Call-ID */
	call_id = sip->sip_call_id->i_id;
	
	/* Extract CSeq */
	cseq_number = sip->sip_cseq->cs_seq;
	cseq_method = sip->sip_cseq->cs_method_name;
	
	/* RFC 3261 Section 8.2.1: Validate required headers */
	
	/* From header MUST have a tag */
	if (ast_strlen_zero(from_tag)) {
		ast_log(LOG_WARNING, "INVITE From header missing tag parameter\n");
		nua_respond(nh, SIP_400_BAD_REQUEST,
			SIPTAG_WARNING_STR("399 " SIP_USER_AGENT " \"From header missing tag\""),
			TAG_END());
		return;
	}
	
	/* Validate From URI */
	if (ast_strlen_zero(from_host)) {
		ast_log(LOG_WARNING, "INVITE From header has invalid URI\n");
		nua_respond(nh, SIP_400_BAD_REQUEST,
			SIPTAG_WARNING_STR("399 " SIP_USER_AGENT " \"From header invalid URI\""),
			TAG_END());
		return;
	}
	
	/* Validate To URI */
	if (ast_strlen_zero(to_host)) {
		ast_log(LOG_WARNING, "INVITE To header has invalid URI\n");
		nua_respond(nh, SIP_400_BAD_REQUEST,
			SIPTAG_WARNING_STR("399 " SIP_USER_AGENT " \"To header invalid URI\""),
			TAG_END());
		return;
	}
	
	/* To header MUST NOT have a tag for initial INVITE */
	if (!ast_strlen_zero(to_tag)) {
		ast_log(LOG_WARNING, "Initial INVITE should not have To tag\n");
		/* This might be a re-INVITE, handle later */
	}
	
	/* Validate Call-ID */
	if (ast_strlen_zero(call_id)) {
		ast_log(LOG_WARNING, "INVITE Call-ID header empty\n");
		nua_respond(nh, SIP_400_BAD_REQUEST,
			SIPTAG_WARNING_STR("399 " SIP_USER_AGENT " \"Call-ID header empty\""),
			TAG_END());
		return;
	}
	
	/* Validate CSeq number */
	if (cseq_number == 0) {
		ast_log(LOG_WARNING, "INVITE CSeq number is 0\n");
		nua_respond(nh, SIP_400_BAD_REQUEST,
			SIPTAG_WARNING_STR("399 " SIP_USER_AGENT " \"Invalid CSeq number\""),
			TAG_END());
		return;
	}
	
	/* Validate Contact header */
	if (!sip->sip_contact->m_url->url_host) {
		ast_log(LOG_WARNING, "INVITE Contact header has invalid URI\n");
		nua_respond(nh, SIP_400_BAD_REQUEST,
			SIPTAG_WARNING_STR("399 " SIP_USER_AGENT " \"Contact header invalid URI\""),
			TAG_END());
		return;
	}
	
	/* Validate Via header */
	if (!sip->sip_via->v_protocol || strncasecmp(sip->sip_via->v_protocol, "SIP/2.0/", 8) != 0) {
		ast_log(LOG_WARNING, "INVITE Via header has invalid protocol: %s\n", 
			sip->sip_via->v_protocol ? sip->sip_via->v_protocol : "NULL");
		nua_respond(nh, SIP_400_BAD_REQUEST,
			SIPTAG_WARNING_STR("399 " SIP_USER_AGENT " \"Via header invalid protocol\""),
			TAG_END());
		return;
	}
	
	if (!sip->sip_via->v_branch || strncmp(sip->sip_via->v_branch, "z9hG4bK", 7) != 0) {
		ast_log(LOG_WARNING, "INVITE Via branch parameter invalid or missing\n");
		nua_respond(nh, SIP_400_BAD_REQUEST,
			SIPTAG_WARNING_STR("399 " SIP_USER_AGENT " \"Via branch parameter invalid\""),
			TAG_END());
		return;
	}
	
	/* Validate CSeq method matches INVITE */
	if (ast_strlen_zero(cseq_method) || strcasecmp(cseq_method, "INVITE") != 0) {
		ast_log(LOG_WARNING, "CSeq method '%s' does not match INVITE\n", 
			cseq_method ? cseq_method : "NULL");
		nua_respond(nh, SIP_400_BAD_REQUEST,
			SIPTAG_WARNING_STR("399 " SIP_USER_AGENT " \"CSeq method mismatch\""),
			TAG_END());
		return;
	}
	
	/* Extract Contact */
	if (sip->sip_contact) {
		su_home_t home[1] = { SU_HOME_INIT(home) };
		contact_uri = url_as_string(home, sip->sip_contact->m_url);
		su_home_deinit(home);
	}
	
	/* Extract Max-Forwards if present */
	if (sip->sip_max_forwards) {
		max_forwards = sip->sip_max_forwards->mf_count;
		if (max_forwards <= 0) {
			ast_log(LOG_WARNING, "Max-Forwards reached 0\n");
			nua_respond(nh, SIP_483_TOO_MANY_HOPS, TAG_END());
			return;
		}
	}
	
	/* Extract optional headers */
	if (sip->sip_user_agent) {
		user_agent = sip->sip_user_agent->g_string;
	}
	
	if (sip->sip_content_type) {
		content_type = sip->sip_content_type->c_type;
	}
	
	/* Use temporary home for string operations */
	su_home_t home2[1] = { SU_HOME_INIT(home2) };
	
	if (sip->sip_supported) {
		supported = sip_header_as_string(home2, (sip_header_t *)sip->sip_supported);
	}
	
	if (sip->sip_require) {
		require = sip_header_as_string(home2, (sip_header_t *)sip->sip_require);
	}
	
	if (sip->sip_allow) {
		allow = sip_header_as_string(home2, (sip_header_t *)sip->sip_allow);
	}
	
	if (sip->sip_accept) {
		accept = sip_header_as_string(home2, (sip_header_t *)sip->sip_accept);
	}
	
	/* Log detailed INVITE information */
	ast_log(LOG_NOTICE, "INVITE parsed successfully:\n");
	ast_log(LOG_NOTICE, "  From: %s@%s (tag=%s)\n", 
		from_user ? from_user : "anonymous",
		from_host ? from_host : "unknown",
		from_tag ? from_tag : "none");
	ast_log(LOG_NOTICE, "  To: %s@%s (tag=%s)\n",
		to_user ? to_user : "unknown",
		to_host ? to_host : "unknown", 
		to_tag ? to_tag : "none");
	ast_log(LOG_NOTICE, "  Call-ID: %s\n", call_id);
	ast_log(LOG_NOTICE, "  CSeq: %u %s\n", cseq_number, cseq_method);
	ast_log(LOG_NOTICE, "  Contact: %s\n", contact_uri ? contact_uri : "none");
	ast_log(LOG_NOTICE, "  Max-Forwards: %d\n", max_forwards);
	
	if (user_agent) {
		ast_log(LOG_NOTICE, "  User-Agent: %s\n", user_agent);
	}
	
	if (supported) {
		ast_log(LOG_NOTICE, "  Supported: %s\n", supported);
	}
	
	if (require) {
		ast_log(LOG_NOTICE, "  Require: %s\n", require);
		/* TODO: Check if we support required extensions */
		/* For now, reject if Require header is present */
		ast_log(LOG_WARNING, "Require header not supported yet\n");
		nua_respond(nh, SIP_420_BAD_EXTENSION,
			SIPTAG_UNSUPPORTED_STR(require),
			TAG_END());
		su_home_deinit(home2);
		return;
	}
	
	if (allow) {
		ast_log(LOG_NOTICE, "  Allow: %s\n", allow);
	}
	
	if (accept) {
		ast_log(LOG_NOTICE, "  Accept: %s\n", accept);
	}
	
	if (content_type) {
		ast_log(LOG_NOTICE, "  Content-Type: %s\n", content_type);
	}
	
	/* Parse Session Timer headers (RFC 4028) */
	if (sip->sip_session_expires) {
		se_value = sip->sip_session_expires->x_delta;
		refresher_param = sip->sip_session_expires->x_refresher;
		ast_log(LOG_NOTICE, "  Session-Expires: %d%s%s\n", se_value,
			refresher_param ? ";refresher=" : "",
			refresher_param ? refresher_param : "");
	}
	
	if (sip->sip_min_se) {
		minse_value = sip->sip_min_se->min_delta;
		ast_log(LOG_NOTICE, "  Min-SE: %d\n", minse_value);
	}
	
	/* Check if supported contains timer */
	int supports_timer = 0;
	if (supported && strstr(supported, "timer")) {
		supports_timer = 1;
		ast_log(LOG_DEBUG, "Remote supports session timers\n");
	}
	
	/* Clean up temporary home */
	su_home_deinit(home2);
	
	/* Create private structure */
	pvt = ast_calloc(1, sizeof(*pvt));
	if (!pvt) {
		nua_respond(nh, SIP_500_INTERNAL_SERVER_ERROR, TAG_END());
		return;
	}
	
	ast_mutex_init(&pvt->lock);
	pvt->profile = profile;
	pvt->nh = nh;
	ast_copy_string(pvt->exten, to_user ? to_user : "s", sizeof(pvt->exten));
	ast_copy_string(pvt->context, profile->context, sizeof(pvt->context));
	
	/* Initialize session timer values */
	pvt->min_se = minse_value ? minse_value : 90;  /* RFC 4028 minimum */
	pvt->session_interval = se_value;
	pvt->refresher = REFRESHER_AUTO;
	pvt->refresh_sched_id = -1;
	
	/* Save the event for later responses */
	if (saved) {
		memcpy(pvt->saved, saved, sizeof(pvt->saved));
	}
	
	/* NAT Detection - Get source IP from the message */
	if (saved) {
		nua_event_data_t const *data = nua_event_data(saved);
		if (data && data->e_msg && get_source_ip(data->e_msg, source_ip, sizeof(source_ip)) == 0) {
			/* Parse source address with port */
			char *port_sep = strrchr(source_ip, ':');
			if (port_sep && strchr(port_sep, '.') == NULL) { /* IPv4 with port */
				*port_sep = '\0';
				source_port = atoi(port_sep + 1);
				ast_sockaddr_parse(&pvt->source_addr, source_ip, PARSE_PORT_FORBID);
				ast_sockaddr_set_port(&pvt->source_addr, source_port);
			} else {
				ast_sockaddr_parse(&pvt->source_addr, source_ip, PARSE_PORT_FORBID);
				source_port = ast_sockaddr_port(&pvt->source_addr);
			}
			pvt->source_addr_set = 1;
			
			/* Check if source IP differs from Contact header IP or if NAT mode is forced */
			if (profile->nat_mode) {
				/* NAT mode forced by configuration */
				pvt->nat_detected = 1;
				ast_log(LOG_NOTICE, "NAT mode enabled by configuration - Source: %s\n", source_ip);
			} else if (contact_uri) {
				su_home_t home3[1] = { SU_HOME_INIT(home3) };
				url_t *contact_url = url_make(home3, contact_uri);
				if (contact_url && contact_url->url_host) {
					/* Compare source IP with Contact IP */
					if (strcmp(source_ip, contact_url->url_host) != 0) {
						pvt->nat_detected = 1;
						ast_log(LOG_NOTICE, "NAT detected - Source: %s, Contact: %s\n",
							source_ip, contact_url->url_host);
					}
				}
				su_home_deinit(home3);
			}
		}
	}
	
	/* Check if remote supports timers but didn't specify SE */
	if (supports_timer && profile->session_timers_enabled && se_value == 0) {
		/* Remote supports timers but didn't specify SE, use our default */
		se_value = profile->session_default_se ? profile->session_default_se : 1800;
		pvt->session_interval = se_value;
	}
	
	/* Validate session timer if requested or if we're using them */
	if (se_value > 0 || (supports_timer && profile->session_timers_enabled)) {
		/* Check configured minimum (default 1800 seconds as recommended) */
		int our_min_se = profile->session_min_se ? profile->session_min_se : 1800;
		if (our_min_se < 90) {
			our_min_se = 90; /* RFC 4028 absolute minimum */
		}
		
		/* If requested SE is less than our minimum, reject with 422 */
		if (se_value > 0 && se_value < our_min_se) {
			char min_se_str[32];
			snprintf(min_se_str, sizeof(min_se_str), "%d", our_min_se);
			
			ast_log(LOG_WARNING, "Session-Expires %d too small, our minimum is %d\n",
				se_value, our_min_se);
			
			nua_respond(nh, 422, "Session Interval Too Small",
				SIPTAG_MIN_SE_STR(min_se_str),
				TAG_END());
			
			ast_mutex_destroy(&pvt->lock);
			ast_free(pvt);
			return;
		}
		
		/* Store the negotiated values */
		if (se_value == 0) {
			se_value = our_min_se > 1800 ? our_min_se : 1800;
		}
		pvt->session_interval = se_value;
		pvt->min_se = our_min_se > pvt->min_se ? our_min_se : pvt->min_se;
		pvt->session_timer_active = 1;
		
		/* Determine refresher */
		if (refresher_param) {
			if (!strcasecmp(refresher_param, "uac")) {
				pvt->refresher = REFRESHER_UAC;
				pvt->we_are_refresher = 0;
			} else if (!strcasecmp(refresher_param, "uas")) {
				pvt->refresher = REFRESHER_UAS;
				pvt->we_are_refresher = 1;
			}
		} else {
			/* Default: we refresh as UAS */
			pvt->refresher = REFRESHER_UAS;
			pvt->we_are_refresher = 1;
		}
	}
	
	/* Store pvt in handle magic */
	nua_handle_bind(nh, pvt);
	
	/* Send 100 Trying immediately and save message for later responses */
	nua_respond(nh, SIP_100_TRYING, NUTAG_WITH_SAVED(saved), TAG_END());
	
	/* Check authorization based on calling endpoint */
	struct sip_endpoint *calling_endpoint = NULL;
	int is_authorized = 0;
	
	if (from_user) {
		/* Look up the calling endpoint */
		calling_endpoint = sip_endpoint_find(profile, from_user);
		if (calling_endpoint) {
			/* Check auth type for this endpoint */
			if (calling_endpoint->auth_type == AUTH_TYPE_IP) {
				/* Trunk mode - validate by IP/port */
				if (calling_endpoint->host[0]) {
					/* Check if source IP matches configured host */
					if (!strcmp(source_ip, calling_endpoint->host)) {
						/* IP matches, check port if specified */
						if (calling_endpoint->port == 0 || source_port == calling_endpoint->port) {
							is_authorized = 1;
							ast_log(LOG_NOTICE, "INVITE from trunk %s@%s:%d authorized (IP match)\n",
								from_user, source_ip, source_port);
						} else {
							ast_log(LOG_WARNING, "INVITE from %s@%s:%d rejected (port mismatch, expected %d)\n",
								from_user, source_ip, source_port, calling_endpoint->port);
						}
					} else {
						ast_log(LOG_WARNING, "INVITE from %s@%s rejected (IP mismatch, expected %s)\n",
							from_user, source_ip, calling_endpoint->host);
					}
				} else {
					ast_log(LOG_WARNING, "Endpoint %s has auth_type=ip but no host configured\n", from_user);
				}
			} else {
				/* Register mode - check if endpoint is registered */
				struct ao2_container *caller_regs = get_endpoint_registrations(calling_endpoint);
				if (caller_regs && ao2_container_count(caller_regs) > 0) {
					/* Endpoint is registered - authorize the call */
					is_authorized = 1;
					ast_log(LOG_NOTICE, "INVITE from %s@%s authorized (endpoint is registered)\n",
						from_user, source_ip);
					
					/* Log registration details for debugging */
					struct ao2_iterator iter = ao2_iterator_init(caller_regs, 0);
					struct sip_registration *reg;
					while ((reg = ao2_iterator_next(&iter))) {
						ast_log(LOG_DEBUG, "  Registration contact: %s\n", reg->contact);
						ao2_ref(reg, -1);
					}
					ao2_iterator_destroy(&iter);
				} else {
					ast_log(LOG_WARNING, "INVITE from %s@%s rejected (not registered)\n",
						from_user, source_ip);
				}
				if (caller_regs) {
					ao2_ref(caller_regs, -1);
				}
			}
			
			/* Check User-Agent if configured */
			if (is_authorized && calling_endpoint->num_useragents > 0) {
				if (!user_agent || !useragent_matches_allowed(user_agent, calling_endpoint)) {
					ast_log(LOG_WARNING, "INVITE from %s@%s rejected (User-Agent mismatch: '%s')\n",
						from_user, source_ip, user_agent ? user_agent : "none");
					is_authorized = 0;
				}
			}
			
			ao2_ref(calling_endpoint, -1);
		} else {
			ast_log(LOG_WARNING, "Unknown endpoint '%s' trying to make call\n", from_user);
		}
	} else {
		ast_log(LOG_WARNING, "INVITE with no From user\n");
	}
	
	if (!is_authorized) {
		/* Not authorized - add failure to blacklist if enabled */
		if (profile->blacklist_enabled && source_ip[0]) {
			sip_blacklist_add_failure(source_ip, from_user, "Unauthorized INVITE");
		}
		
		/* Clean up */
		ast_mutex_destroy(&pvt->lock);
		ast_free(pvt);
		
		/* Send 403 Forbidden */
		nua_respond(nh, SIP_403_FORBIDDEN,
			SIPTAG_WARNING_STR("399 " SIP_USER_AGENT " \"Not authorized\""),
			TAG_END());
		return;
	} else {
		/* Authorized - reset blacklist failures */
		if (source_ip[0]) {
			sip_blacklist_reset_failures(source_ip);
		}
	}
	
	/* Find the called endpoint */
	struct sip_endpoint *called_endpoint = NULL;
	struct ao2_container *registrations = NULL;
	
	if (to_user) {
		called_endpoint = sip_endpoint_find(profile, to_user);
		if (called_endpoint) {
			/* Get all active registrations for this endpoint */
			registrations = get_endpoint_registrations(called_endpoint);
			if (registrations) {
				int reg_count = ao2_container_count(registrations);
				ast_log(LOG_NOTICE, "Found %d active registration(s) for endpoint %s\n", 
					reg_count, to_user);
				
				if (reg_count > 1 && called_endpoint->ring_all_except_inuse) {
					ast_log(LOG_NOTICE, "Will implement ring all except in-use for %s\n", to_user);
					/* TODO: Implement forking to multiple contacts */
				}
				
				/* For now, just log the registrations */
				struct ao2_iterator iter = ao2_iterator_init(registrations, 0);
				struct sip_registration *reg;
				while ((reg = ao2_iterator_next(&iter))) {
					ast_log(LOG_DEBUG, "  Registration: %s (expires: %ld)\n", 
						reg->contact, reg->expires);
					ao2_ref(reg, -1);
				}
				ao2_iterator_destroy(&iter);
				
				ao2_ref(registrations, -1);
			} else {
				ast_log(LOG_WARNING, "Endpoint %s has no active registrations\n", to_user);
			}
			ao2_ref(called_endpoint, -1);
		} else {
			ast_log(LOG_WARNING, "Endpoint %s not found\n", to_user ? to_user : "unknown");
		}
	}
	
	/* Parse SDP if present */
	if (sip->sip_payload && sip->sip_payload->pl_data) {
		ast_debug(1, "SDP received:\n%s\n", sip->sip_payload->pl_data);
		
		/* Parse SDP offer */
		if (sofia_parse_sdp_offer(pvt, sip->sip_payload->pl_data, sip->sip_payload->pl_len) < 0) {
			ast_log(LOG_WARNING, "Failed to parse SDP offer\n");
			ast_mutex_destroy(&pvt->lock);
			ast_free(pvt);
			nua_respond(nh, SIP_400_BAD_REQUEST, TAG_END());
			return;
		}
		
		/* Negotiate media */
		if (sofia_negotiate_media(pvt) < 0) {
			ast_log(LOG_WARNING, "No compatible codecs\n");
			ast_mutex_destroy(&pvt->lock);
			ast_free(pvt);
			nua_respond(nh, SIP_488_NOT_ACCEPTABLE, TAG_END());
			return;
		}
	} else {
		/* No SDP in INVITE - delayed offer */
		/* Allocate default capabilities */
		pvt->caps = ast_format_cap_alloc(AST_FORMAT_CAP_FLAG_DEFAULT);
		if (!pvt->caps) {
			ast_mutex_destroy(&pvt->lock);
			ast_free(pvt);
			nua_respond(nh, SIP_500_INTERNAL_SERVER_ERROR, TAG_END());
			return;
		}
		
		/* Add our supported codecs */
		ast_format_cap_append(pvt->caps, ast_format_ulaw, 0);
		ast_format_cap_append(pvt->caps, ast_format_alaw, 0);
		ast_format_cap_append(pvt->caps, ast_format_gsm, 0);
		ast_format_cap_append(pvt->caps, ast_format_g722, 0);
	}
	
	/* Create RTP instance */
	struct ast_sockaddr addr;
	ast_sockaddr_parse(&addr, profile->bindip, PARSE_PORT_FORBID);
	ast_sockaddr_set_port(&addr, 0); /* Let RTP engine pick port */
	
	pvt->rtp = ast_rtp_instance_new("gabpbx", NULL, &addr, NULL);
	if (!pvt->rtp) {
		ast_log(LOG_ERROR, "Failed to create RTP instance\n");
		ao2_cleanup(pvt->caps);
		ast_mutex_destroy(&pvt->lock);
		ast_free(pvt);
		nua_respond(nh, SIP_500_INTERNAL_SERVER_ERROR, TAG_END());
		return;
	}
	
	/* Set remote RTP address if we have it from SDP */
	if (pvt->remote_addr_set) {
		ast_rtp_instance_set_remote_address(pvt->rtp, &pvt->remote_addr);
	}
	
	/* Create GABpbx channel */
	struct ast_channel *chan;
	chan = ast_channel_alloc(1, AST_STATE_RING, from_user, from_user, "", 
		to_user, profile->context, NULL, NULL, 0, 
		"SIP/%s-%08lx", from_user ? from_user : "unknown", ast_random());
	
	if (!chan) {
		ast_log(LOG_ERROR, "Failed to allocate channel\n");
		ast_rtp_instance_destroy(pvt->rtp);
		ao2_cleanup(pvt->caps);
		ast_mutex_destroy(&pvt->lock);
		ast_free(pvt);
		nua_respond(nh, SIP_503_SERVICE_UNAVAILABLE, TAG_END());
		return;
	}
	
	/* Set channel tech and pvt */
	ast_channel_tech_set(chan, &sip_tech);
	ast_channel_tech_pvt_set(chan, pvt);
	pvt->owner = chan;
	
	/* Set formats */
	ast_channel_nativeformats_set(chan, pvt->caps);
	ast_channel_set_writeformat(chan, ast_format_ulaw);
	ast_channel_set_rawwriteformat(chan, ast_format_ulaw);
	ast_channel_set_readformat(chan, ast_format_ulaw);
	ast_channel_set_rawreadformat(chan, ast_format_ulaw);
	
	/* Set context and extension */
	ast_channel_context_set(chan, pvt->context);
	ast_channel_exten_set(chan, pvt->exten);
	ast_channel_priority_set(chan, 1);
	
	/* Set caller ID */
	if (from_user) {
		ast_set_callerid(chan, from_user, from_user, from_user);
	}
	
	ast_channel_unlock(chan);
	
	/* Start PBX */
	if (ast_pbx_start(chan)) {
		ast_log(LOG_ERROR, "Failed to start PBX on %s\n", ast_channel_name(chan));
		ast_hangup(chan);
		nua_respond(nh, SIP_503_SERVICE_UNAVAILABLE, TAG_END());
		return;
	}
	
	ast_log(LOG_NOTICE, "Channel %s created and PBX started for %s@%s\n", 
		ast_channel_name(chan), pvt->exten, pvt->context);
#endif /* 1 - End of re-enabled INVITE processing */
}