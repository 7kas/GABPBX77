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
 * \brief Chan_sofia ACK method implementation
 *
 * \author Germán Aracil Boned <garacilb@gmail.com>
 *
 * \ingroup channel_drivers
 */

/*** DOCUMENTATION
 * ACK Method Implementation per RFC 3261 Section 17.1.1.3
 * 
 * ACK is used to acknowledge final responses to INVITE requests.
 * 
 * Key rules:
 * 1. ACK for 2xx responses creates a new transaction
 * 2. ACK for non-2xx responses is part of the INVITE transaction
 * 3. ACK must match the Call-ID, From tag, and To tag of the response
 * 4. CSeq number must match the INVITE, method must be ACK
 * 5. ACK is never retransmitted by the UAC
 * 6. Proxies do not generate ACK for 2xx responses
 ***/

/*!
 * \brief Parse and validate ACK request
 * \param sip SIP message structure
 * \param profile Sofia profile
 * \return 0 on success, -1 on failure
 */
static int validate_ack_request(sip_t const *sip, struct sip_profile *profile)
{
	/* ACK is special - no response should be sent */
	
	/* Validate required headers */
	if (!sip->sip_request || !sip->sip_request->rq_method_name) {
		ast_log(LOG_ERROR, "ACK: Missing request line\n");
		return -1;
	}
	
	if (!sip->sip_call_id) {
		ast_log(LOG_ERROR, "ACK: Missing Call-ID header\n");
		return -1;
	}
	
	if (!sip->sip_from || !sip->sip_from->a_tag) {
		ast_log(LOG_ERROR, "ACK: Missing From header or tag\n");
		return -1;
	}
	
	if (!sip->sip_to || !sip->sip_to->a_tag) {
		ast_log(LOG_ERROR, "ACK: Missing To header or tag\n");
		return -1;
	}
	
	if (!sip->sip_cseq) {
		ast_log(LOG_ERROR, "ACK: Missing CSeq header\n");
		return -1;
	}
	
	/* Verify CSeq method is ACK */
	if (strcasecmp(sip->sip_cseq->cs_method_name, "ACK") != 0) {
		ast_log(LOG_ERROR, "ACK: CSeq method mismatch: %s\n", 
			sip->sip_cseq->cs_method_name);
		return -1;
	}
	
	ast_debug(3, "ACK validated - Call-ID: %s, From: %s (tag=%s), To: %s (tag=%s)\n",
		sip->sip_call_id->i_id,
		sip->sip_from->a_url->url_user, sip->sip_from->a_tag,
		sip->sip_to->a_url->url_user, sip->sip_to->a_tag);
	
	return 0;
}

/*!
 * \brief Handle ACK request
 * \param nh NUA handle
 * \param profile Sofia profile
 * \param sip SIP message
 * \param tags Sofia tags
 * 
 * ACK handling follows RFC 3261:
 * - For 2xx responses: ACK is end-to-end, creates new transaction
 * - For non-2xx: ACK is hop-by-hop, part of INVITE transaction
 * - No response is sent to ACK
 */
void handle_ack_request(nua_handle_t *nh, struct sip_profile *profile, 
	sip_t const *sip, tagi_t tags[])
{
	struct sofia_pvt *pvt = NULL;
	char call_id[256];
	char from_tag[128];
	char to_tag[128];
	
	if (!nh || !sip) {
		ast_log(LOG_ERROR, "ACK: Invalid parameters\n");
		return;
	}
	
	/* Get private data from handle */
	pvt = nua_handle_magic(nh);
	
	/* Validate ACK request */
	if (validate_ack_request(sip, profile) != 0) {
		ast_log(LOG_WARNING, "ACK: Validation failed\n");
		return;
	}
	
	/* Extract dialog identifiers */
	ast_copy_string(call_id, sip->sip_call_id->i_id, sizeof(call_id));
	ast_copy_string(from_tag, sip->sip_from->a_tag, sizeof(from_tag));
	ast_copy_string(to_tag, sip->sip_to->a_tag, sizeof(to_tag));
	
	ast_debug(1, "ACK received for dialog: Call-ID=%s, From-tag=%s, To-tag=%s\n",
		call_id, from_tag, to_tag);
	
	/* Handle based on context */
	if (pvt && pvt->owner) {
		/* ACK for established dialog */
		ast_debug(2, "ACK for established dialog on channel %s\n", 
			ast_channel_name(pvt->owner));
		
		/* Update channel state if needed */
		if (ast_channel_state(pvt->owner) != AST_STATE_UP) {
			ast_debug(1, "Setting channel %s to UP state after ACK\n",
				ast_channel_name(pvt->owner));
			ast_setstate(pvt->owner, AST_STATE_UP);
		}
		
		/* Mark that we received ACK */
		pvt->ack_received = 1;
		
		/* RFC 3261: ACK may contain SDP answer in some cases */
		if (sip->sip_payload && sip->sip_content_type &&
		    strstr(sip->sip_content_type->c_type, "application/sdp")) {
			ast_debug(2, "ACK contains SDP - processing answer\n");
			/* TODO: Process SDP if needed for late offer/answer */
		}
		
		/* Update dialog state */
		pvt->dialog_state = DIALOG_STATE_CONFIRMED;
		
		/* Activate RTP now that we have ACK */
		if (pvt->media_state == MEDIA_STATE_ANSWERED) {
			if (sofia_activate_rtp(pvt) == 0) {
				ast_debug(1, "RTP activated after ACK\n");
			}
		}
		
	} else if (pvt) {
		/* ACK without owner - might be for failed INVITE */
		ast_debug(2, "ACK received for dialog without owner\n");
		
		/* This could be ACK for non-2xx response */
		/* Sofia-SIP handles transaction layer, we just log */
		
	} else {
		/* ACK without context - stray ACK */
		ast_debug(1, "Stray ACK received - no associated dialog\n");
		/* Sofia-SIP will handle transaction matching */
	}
	
	/* Log for debugging */
	ast_debug(3, "=== ACK Processed ===\n");
	ast_debug(3, "Call-ID: %s\n", call_id);
	ast_debug(3, "From: %s (tag=%s)\n", 
		sip->sip_from->a_url->url_user, from_tag);
	ast_debug(3, "To: %s (tag=%s)\n", 
		sip->sip_to->a_url->url_user, to_tag);
	ast_debug(3, "CSeq: %u %s\n", 
		sip->sip_cseq->cs_seq, sip->sip_cseq->cs_method_name);
	ast_debug(3, "====================\n");
	
	/* No response sent for ACK per RFC 3261 */
}

/*!
 * \brief Generate ACK for 2xx response
 * \param pvt Private structure
 * \param response_code Response code that triggered ACK
 * \return 0 on success, -1 on failure
 * 
 * Used when we receive 200 OK for our INVITE
 */
int sofia_send_ack(struct sofia_pvt *pvt, int response_code)
{
	if (!pvt || !pvt->nh) {
		ast_log(LOG_ERROR, "Cannot send ACK - invalid private structure\n");
		return -1;
	}
	
	ast_debug(2, "Sending ACK for %d response on channel %s\n", 
		response_code, pvt->owner ? ast_channel_name(pvt->owner) : "unknown");
	
	/* Sofia-SIP automatically generates ACK for 2xx responses */
	/* We just need to tell it to send */
	nua_ack(pvt->nh, TAG_END());
	
	/* Mark ACK as sent */
	pvt->ack_sent = 1;
	
	return 0;
}

/*!
 * \brief Check if ACK was received for a dialog
 * \param pvt Private structure
 * \return 1 if ACK received, 0 otherwise
 */
int sofia_ack_received(struct sofia_pvt *pvt)
{
	return pvt ? pvt->ack_received : 0;
}

/*!
 * \brief Reset ACK state for new transaction
 * \param pvt Private structure
 */
void sofia_reset_ack_state(struct sofia_pvt *pvt)
{
	if (pvt) {
		pvt->ack_received = 0;
		pvt->ack_sent = 0;
	}
}