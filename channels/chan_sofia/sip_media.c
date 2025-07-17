/*
 * Asterisk -- An open source telephony toolkit.
 *
 * Copyright (C) 2024, Germán Aracil Boned <garacilb@gmail.com>
 * Copyright (C) 2024, 7kas Servicios de Internet SL
 *
 * See http://www.asterisk.org for more information about
 * the Asterisk project. Please do not directly contact
 * any of the maintainers of this project for assistance;
 * the project provides a web site, mailing lists and IRC
 * channels for your use.
 *
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 */

/*!
 * \file
 * \brief Chan_sofia media handling - SDP and RTP management
 *
 * \author Germán Aracil Boned <garacilb@gmail.com>
 *
 * \ingroup channel_drivers
 */

/*** DOCUMENTATION
 * Media handling implementation following RFC 3264 (Offer/Answer Model)
 * and best practices from FreeSwitch mod_sofia
 ***/

/* Note: This file is included within chan_sofia.c and uses struct sofia_pvt */
/* Media state machine is defined in sip_sofia.h */

/* Codec mapping structure */
struct sofia_codec_map {
	int rtp_pt;                    /* RTP payload type */
	const char *encoding_name;     /* SDP encoding name */
	int clock_rate;                /* Clock rate */
	struct ast_format *ast_format; /* Asterisk format */
};

/* Standard codec mappings */
static struct sofia_codec_map codec_map[] = {
	{ 0,   "PCMU",            8000,  NULL }, /* Will set ast_format_ulaw */
	{ 3,   "GSM",             8000,  NULL }, /* Will set ast_format_gsm */
	{ 4,   "G723",            8000,  NULL }, /* Will set ast_format_g723 */
	{ 8,   "PCMA",            8000,  NULL }, /* Will set ast_format_alaw */
	{ 9,   "G722",            8000,  NULL }, /* Will set ast_format_g722 */
	{ 18,  "G729",            8000,  NULL }, /* Will set ast_format_g729 */
	{ 101, "telephone-event", 8000,  NULL }, /* DTMF events */
	{ -1,  NULL,              0,     NULL }
};

/* Initialize codec map with Asterisk formats */
static void init_codec_map(void)
{
	codec_map[0].ast_format = ast_format_ulaw;
	codec_map[1].ast_format = ast_format_gsm;
	codec_map[2].ast_format = ast_format_g723;
	codec_map[3].ast_format = ast_format_alaw;
	codec_map[4].ast_format = ast_format_g722;
	codec_map[5].ast_format = ast_format_g729;
}

/*!
 * \brief Find Asterisk format from SDP rtpmap
 * \param rm SDP rtpmap entry
 * \return ast_format or NULL if not supported
 */
static struct ast_format *sdp_to_ast_format(sdp_rtpmap_t *rm)
{
	int i;
	
	if (!rm || !rm->rm_encoding) {
		return NULL;
	}
	
	/* Look up in codec map */
	for (i = 0; codec_map[i].encoding_name; i++) {
		if (!strcasecmp(rm->rm_encoding, codec_map[i].encoding_name) &&
		    rm->rm_rate == codec_map[i].clock_rate) {
			return codec_map[i].ast_format;
		}
	}
	
	return NULL;
}

/*!
 * \brief Parse SDP and extract media information
 * \param pvt Private structure
 * \param sdp_str SDP string
 * \param sdp_len SDP length
 * \return 0 on success, -1 on failure
 */
int sofia_parse_sdp_offer(struct sofia_pvt *pvt, const char *sdp_str, size_t sdp_len)
{
	su_home_t home[1] = { SU_HOME_INIT(home) };
	sdp_parser_t *parser = NULL;
	sdp_session_t *sdp = NULL;
	sdp_media_t *m;
	int result = -1;
	
	if (!pvt || !sdp_str) {
		return -1;
	}
	
	/* Initialize codec map if needed */
	static int codec_map_initialized = 0;
	if (!codec_map_initialized) {
		init_codec_map();
		codec_map_initialized = 1;
	}
	
	/* Store remote SDP */
	ast_copy_string(pvt->remote_sdp, sdp_str, sizeof(pvt->remote_sdp));
	
	/* Parse SDP */
	parser = sdp_parse(home, sdp_str, sdp_len, sdp_f_config);
	if (!parser) {
		ast_log(LOG_ERROR, "Failed to parse SDP\n");
		goto cleanup;
	}
	
	sdp = sdp_session(parser);
	if (!sdp) {
		ast_log(LOG_ERROR, "Failed to get SDP session\n");
		goto cleanup;
	}
	
	/* Process each media stream */
	for (m = sdp->sdp_media; m; m = m->m_next) {
		/* Only handle audio for now */
		if (m->m_type != sdp_media_audio) {
			continue;
		}
		
		/* Skip disabled streams (port 0) */
		if (m->m_port == 0) {
			ast_debug(1, "Skipping disabled audio stream\n");
			continue;
		}
		
		/* Extract connection information */
		const char *remote_ip = NULL;
		if (m->m_connections) {
			remote_ip = m->m_connections->c_address;
		} else if (sdp->sdp_connection) {
			remote_ip = sdp->sdp_connection->c_address;
		}
		
		if (!remote_ip) {
			ast_log(LOG_ERROR, "No connection address in SDP\n");
			goto cleanup;
		}
		
		/* Save remote RTP address */
		ast_sockaddr_parse(&pvt->remote_addr, remote_ip, PARSE_PORT_FORBID);
		ast_sockaddr_set_port(&pvt->remote_addr, m->m_port);
		pvt->remote_addr_set = 1;
		
		ast_log(LOG_NOTICE, "Parsed SDP - Remote RTP address: %s:%lu\n", remote_ip, m->m_port);
		ast_debug(1, "Remote RTP address: %s:%lu\n", remote_ip, m->m_port);
		
		/* Parse offered codecs */
		if (!pvt->offered_caps) {
			pvt->offered_caps = ast_format_cap_alloc(AST_FORMAT_CAP_FLAG_DEFAULT);
			if (!pvt->offered_caps) {
				ast_log(LOG_ERROR, "Failed to allocate offered capabilities\n");
				goto cleanup;
			}
		}
		
		/* Check static payload types first */
		sdp_rtpmap_t *rm;
		for (rm = m->m_rtpmaps; rm; rm = rm->rm_next) {
			struct ast_format *fmt = sdp_to_ast_format(rm);
			if (fmt) {
				ast_format_cap_append(pvt->offered_caps, fmt, rm->rm_pt);
				ast_debug(1, "Remote offers codec: %s/%lu (pt=%u)\n",
					rm->rm_encoding, rm->rm_rate, rm->rm_pt);
			}
			
			/* Check for DTMF */
			if (!strcasecmp(rm->rm_encoding, "telephone-event")) {
				pvt->rtp_dtmf = 1;
				pvt->rtp_dtmf_pt = rm->rm_pt;
				ast_debug(1, "Remote supports RFC 2833 DTMF (pt=%u)\n", rm->rm_pt);
			}
		}
		
		/* Also check format list for static types without rtpmap */
		sdp_list_t *fmt_item;
		for (fmt_item = m->m_format; fmt_item; fmt_item = fmt_item->l_next) {
			if (fmt_item->l_text) {
				int pt = atoi(fmt_item->l_text);
				
				/* Check if we already processed this PT */
				int found = 0;
				for (rm = m->m_rtpmaps; rm; rm = rm->rm_next) {
					if (rm->rm_pt == pt) {
						found = 1;
						break;
					}
				}
				
				if (!found) {
					/* Check static payload types */
					switch (pt) {
					case 0: /* PCMU */
						ast_format_cap_append(pvt->offered_caps, ast_format_ulaw, pt);
						ast_debug(1, "Remote offers PCMU (static pt=0)\n");
						break;
					case 3: /* GSM */
						ast_format_cap_append(pvt->offered_caps, ast_format_gsm, pt);
						ast_debug(1, "Remote offers GSM (static pt=3)\n");
						break;
					case 8: /* PCMA */
						ast_format_cap_append(pvt->offered_caps, ast_format_alaw, pt);
						ast_debug(1, "Remote offers PCMA (static pt=8)\n");
						break;
					}
				}
			}
		}
		
		/* We only process first audio stream */
		result = 0;
		break;
	}
	
	/* Check if we have any compatible codecs */
	if (pvt->offered_caps && ast_format_cap_count(pvt->offered_caps) == 0) {
		ast_log(LOG_WARNING, "No codecs offered in SDP\n");
		result = -1;
	}

cleanup:
	if (parser) {
		sdp_parser_free(parser);
	}
	su_home_deinit(home);
	
	return result;
}

/*!
 * \brief Negotiate codecs between offered and local capabilities
 * \param pvt Private structure
 * \return 0 on success, -1 on failure
 */
int sofia_negotiate_media(struct sofia_pvt *pvt)
{
	struct ast_format_cap *joint_caps;
	
	if (!pvt || !pvt->offered_caps) {
		return -1;
	}
	
	/* Get our capabilities */
	if (!pvt->caps) {
		pvt->caps = ast_format_cap_alloc(AST_FORMAT_CAP_FLAG_DEFAULT);
		if (!pvt->caps) {
			return -1;
		}
		
		/* Add our supported codecs */
		ast_format_cap_append(pvt->caps, ast_format_ulaw, 0);
		ast_format_cap_append(pvt->caps, ast_format_alaw, 0);
		ast_format_cap_append(pvt->caps, ast_format_gsm, 0);
		ast_format_cap_append(pvt->caps, ast_format_g722, 0);
	}
	
	/* Find common codecs */
	joint_caps = ast_format_cap_alloc(AST_FORMAT_CAP_FLAG_DEFAULT);
	if (!joint_caps) {
		return -1;
	}
	
	ast_format_cap_get_compatible(pvt->caps, pvt->offered_caps, joint_caps);
	
	if (ast_format_cap_count(joint_caps) == 0) {
		ast_log(LOG_WARNING, "No compatible codecs with remote\n");
		ao2_ref(joint_caps, -1);
		return -1;
	}
	
	/* Use joint capabilities */
	ao2_ref(pvt->caps, -1);
	pvt->caps = joint_caps;
	
	ast_debug(1, "Negotiated %zu compatible codecs\n", ast_format_cap_count(joint_caps));
	
	pvt->media_state = MEDIA_STATE_OFFERED;
	
	return 0;
}

/*!
 * \brief Build SDP answer based on negotiated codecs
 * \param pvt Private structure
 * \param local_addr Local RTP address
 * \return 0 on success, -1 on failure
 */
int sofia_build_sdp_answer(struct sofia_pvt *pvt, struct ast_sockaddr *local_addr)
{
	char sdp_buf[2048];
	char codec_buf[512] = "";
	char attr_buf[1024] = "";
	int codec_count = 0;
	struct ast_format *fmt;
	int i, x;
	
	if (!pvt || !pvt->caps || !local_addr) {
		return -1;
	}
	
	/* Build codec list and attributes */
	for (x = 0; x < ast_format_cap_count(pvt->caps); x++) {
		fmt = ast_format_cap_get_format(pvt->caps, x);
		
		/* Find payload type */
		int pt = -1;
		for (i = 0; codec_map[i].encoding_name; i++) {
			if (ast_format_cmp(fmt, codec_map[i].ast_format) == AST_FORMAT_CMP_EQUAL) {
				pt = codec_map[i].rtp_pt;
				
				/* Add to format list */
				if (codec_count > 0) {
					strcat(codec_buf, " ");
				}
				sprintf(codec_buf + strlen(codec_buf), "%d", pt);
				
				/* Add rtpmap */
				sprintf(attr_buf + strlen(attr_buf),
					"a=rtpmap:%d %s/%d\r\n",
					pt, codec_map[i].encoding_name, codec_map[i].clock_rate);
				
				codec_count++;
				break;
			}
		}
		
		ao2_ref(fmt, -1);
	}
	
	/* Add DTMF if supported */
	if (pvt->rtp_dtmf) {
		if (codec_count > 0) {
			strcat(codec_buf, " ");
		}
		strcat(codec_buf, "101");
		strcat(attr_buf, "a=rtpmap:101 telephone-event/8000\r\n");
		strcat(attr_buf, "a=fmtp:101 0-16\r\n");
	}
	
	/* Build complete SDP */
	snprintf(sdp_buf, sizeof(sdp_buf),
		"v=0\r\n"
		"o=- %ld %ld IN IP4 %s\r\n"
		"s=GABpbx\r\n"
		"c=IN IP4 %s\r\n"
		"t=0 0\r\n"
		"m=audio %d RTP/AVP %s\r\n"
		"%s"
		"a=sendrecv\r\n",
		(long)time(NULL), (long)time(NULL) + 1,
		ast_sockaddr_stringify_addr(local_addr),
		ast_sockaddr_stringify_addr(local_addr),
		ast_sockaddr_port(local_addr),
		codec_buf,
		attr_buf);
	
	ast_copy_string(pvt->local_sdp, sdp_buf, sizeof(pvt->local_sdp));
	
	pvt->media_state = MEDIA_STATE_ANSWERED;
	
	ast_debug(1, "Built SDP answer with %d codecs\n", codec_count);
	
	return 0;
}

/*!
 * \brief Activate RTP based on negotiated media
 * \param pvt Private structure
 * \return 0 on success, -1 on failure
 */
int sofia_activate_rtp(struct sofia_pvt *pvt)
{
	if (!pvt || !pvt->rtp) {
		return -1;
	}
	
	/* Only activate if we have negotiated media and remote address */
	if (pvt->media_state != MEDIA_STATE_ANSWERED || !pvt->remote_addr_set) {
		ast_debug(1, "Not ready to activate RTP (state=%d, remote_set=%d)\n",
			pvt->media_state, pvt->remote_addr_set);
		return -1;
	}
	
	/* Set remote address - use source address if NAT detected */
	if (pvt->nat_detected && pvt->source_addr_set) {
		/* Use the source IP but with the RTP port from SDP */
		struct ast_sockaddr nat_addr = pvt->source_addr;
		ast_sockaddr_set_port(&nat_addr, ast_sockaddr_port(&pvt->remote_addr));
		
		ast_log(LOG_NOTICE, "NAT detected - Setting RTP remote address to source IP %s (was %s)\n", 
			ast_sockaddr_stringify(&nat_addr), ast_sockaddr_stringify(&pvt->remote_addr));
		ast_rtp_instance_set_remote_address(pvt->rtp, &nat_addr);
		
		pvt->media_state = MEDIA_STATE_ACTIVE;
		ast_log(LOG_NOTICE, "RTP activated to %s (NAT mode)\n", ast_sockaddr_stringify(&nat_addr));
	} else {
		/* No NAT - use address from SDP */
		ast_log(LOG_NOTICE, "Setting RTP remote address to %s\n", ast_sockaddr_stringify(&pvt->remote_addr));
		ast_rtp_instance_set_remote_address(pvt->rtp, &pvt->remote_addr);
		
		pvt->media_state = MEDIA_STATE_ACTIVE;
		ast_log(LOG_NOTICE, "RTP activated to %s\n", ast_sockaddr_stringify(&pvt->remote_addr));
	}
	
	return 0;
}

/*!
 * \brief Put media on hold
 * \param pvt Private structure
 * \return 0 on success, -1 on failure
 */
int sofia_media_hold(struct sofia_pvt *pvt)
{
	if (!pvt || pvt->media_state != MEDIA_STATE_ACTIVE) {
		return -1;
	}
	
	/* TODO: Send re-INVITE with sendonly */
	pvt->media_state = MEDIA_STATE_HOLD;
	
	return 0;
}

/*!
 * \brief Take media off hold
 * \param pvt Private structure
 * \return 0 on success, -1 on failure
 */
int sofia_media_unhold(struct sofia_pvt *pvt)
{
	if (!pvt || pvt->media_state != MEDIA_STATE_HOLD) {
		return -1;
	}
	
	/* TODO: Send re-INVITE with sendrecv */
	pvt->media_state = MEDIA_STATE_ACTIVE;
	
	return 0;
}