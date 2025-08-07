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
 * \brief Chan_sofia BYE method implementation
 *
 * \author Germán Aracil Boned <garacilb@gmail.com>
 *
 * \ingroup channel_drivers
 */

/*** DOCUMENTATION
 * BYE Method Implementation per RFC 3261 Section 15
 * 
 * BYE terminates a dialog and releases all associated resources.
 * 
 * Key rules:
 * 1. BYE can only be sent within an established dialog
 * 2. BYE is hop-by-hop, each proxy may add its own headers
 * 3. BYE should include Reason header for cause codes
 * 4. Both parties can send BYE at any time after dialog establishment
 * 5. BYE cannot be sent for early dialogs (use CANCEL instead)
 ***/

/*!
 * \brief Parse Reason header for hangup cause
 * \param sip SIP message
 * \return Asterisk hangup cause code
 */
static int parse_reason_header(sip_t const *sip)
{
	sip_reason_t *reason;
	int cause = AST_CAUSE_NORMAL_CLEARING;
	
	/* Look for Reason header */
	for (reason = sip->sip_reason; reason; reason = reason->re_next) {
		if (reason->re_protocol && strcasecmp(reason->re_protocol, "SIP") == 0) {
			if (reason->re_cause) {
				int sip_cause = atoi(reason->re_cause);
				/* Map SIP cause to Asterisk cause */
				switch (sip_cause) {
				case 404:
					cause = AST_CAUSE_UNALLOCATED;
					break;
				case 486:
					cause = AST_CAUSE_BUSY;
					break;
				case 480:
				case 487:
					cause = AST_CAUSE_NO_ANSWER;
					break;
				case 503:
					cause = AST_CAUSE_CONGESTION;
					break;
				case 403:
					cause = AST_CAUSE_CALL_REJECTED;
					break;
				default:
					/* Keep normal clearing */
					break;
				}
			}
		} else if (reason->re_protocol && strcasecmp(reason->re_protocol, "Q.850") == 0) {
			/* Q.850 cause codes map directly */
			if (reason->re_cause) {
				cause = atoi(reason->re_cause);
			}
		}
	}
	
	return cause;
}

/*!
 * \brief Validate BYE request
 * \param sip SIP message
 * \param pvt Private structure
 * \return 0 on success, -1 on failure
 */
static int validate_bye_request(sip_t const *sip, struct sofia_pvt *pvt)
{
	/* Validate required headers */
	if (!sip->sip_request || !sip->sip_request->rq_method_name) {
		ast_log(LOG_ERROR, "BYE: Missing request line\n");
		return -1;
	}
	
	if (!sip->sip_call_id) {
		ast_log(LOG_ERROR, "BYE: Missing Call-ID header\n");
		return -1;
	}
	
	if (!sip->sip_from || !sip->sip_from->a_tag) {
		ast_log(LOG_ERROR, "BYE: Missing From header or tag\n");
		return -1;
	}
	
	if (!sip->sip_to || !sip->sip_to->a_tag) {
		ast_log(LOG_ERROR, "BYE: Missing To header or tag\n");
		return -1;
	}
	
	if (!sip->sip_cseq) {
		ast_log(LOG_ERROR, "BYE: Missing CSeq header\n");
		return -1;
	}
	
	/* Verify dialog exists */
	if (!pvt) {
		ast_log(LOG_WARNING, "BYE: No dialog found for Call-ID %s\n",
			sip->sip_call_id->i_id);
		return -1;
	}
	
       /* Check dialog state - BYE only valid for confirmed dialogs */
       if (pvt->dialog_state != DIALOG_STATE_CONFIRMED) {
               ast_log(LOG_WARNING, "BYE: Invalid dialog state %d\n", pvt->dialog_state);
               return -1;
       }
	
	return 0;
}

/*!
 * \brief Handle BYE request
 * \param nh NUA handle
 * \param profile Sofia profile
 * \param sip SIP message
 * \param tags Sofia tags
 */
void handle_bye_request(nua_handle_t *nh, struct sip_profile *profile,
	sip_t const *sip, tagi_t tags[], msg_t *msg)
{
	struct sofia_pvt *pvt = NULL;
	int cause = AST_CAUSE_NORMAL_CLEARING;
	char call_id[256];
	char from_tag[128];
	char to_tag[128];
	
	if (!nh || !sip) {
		ast_log(LOG_ERROR, "BYE: Invalid parameters\n");
		if (msg) {
			nua_respond(nh, 500, "Internal Server Error", 
				NUTAG_WITH_THIS_MSG(msg), TAG_END());
		} else {
			nua_respond(nh, 500, "Internal Server Error", TAG_END());
		}
		return;
	}
	
	/* Get private data */
	pvt = nua_handle_magic(nh);
	
	/* Validate BYE request */
	if (validate_bye_request(sip, pvt) != 0) {
		if (msg) {
			nua_respond(nh, 481, "Call/Transaction Does Not Exist", 
				NUTAG_WITH_THIS_MSG(msg), TAG_END());
		} else {
			nua_respond(nh, 481, "Call/Transaction Does Not Exist", TAG_END());
		}
		return;
	}
	
	/* Extract dialog identifiers for logging */
	ast_copy_string(call_id, sip->sip_call_id->i_id, sizeof(call_id));
	ast_copy_string(from_tag, sip->sip_from->a_tag, sizeof(from_tag));
	ast_copy_string(to_tag, sip->sip_to->a_tag, sizeof(to_tag));
	
	ast_debug(1, "BYE received for dialog: Call-ID=%s, From-tag=%s, To-tag=%s\n",
		call_id, from_tag, to_tag);
	
	/* Parse Reason header if present */
	cause = parse_reason_header(sip);
	
	/* Send 200 OK immediately per RFC 3261 */
	if (msg) {
		nua_respond(nh, SIP_200_OK, NUTAG_WITH_THIS_MSG(msg), TAG_END());
	} else {
		nua_respond(nh, SIP_200_OK, TAG_END());
	}
	
	/* Update dialog state */
	pvt->dialog_state = DIALOG_STATE_TERMINATED;
	
	/* Handle channel teardown */
	if (pvt->owner) {
		struct ast_channel *owner = pvt->owner;
		
		ast_debug(2, "BYE terminating channel %s with cause %d\n",
			ast_channel_name(owner), cause);
		
		/* Set hangup cause */
		ast_channel_hangupcause_set(owner, cause);
		
		/* Stop any session timers */
		if (pvt->refresh_sched_id > -1 && profile->sched) {
			AST_SCHED_DEL(profile->sched, pvt->refresh_sched_id);
		}
		
		/* Queue hangup - let Asterisk handle the actual teardown */
		ast_queue_hangup_with_cause(owner, cause);
		
	} else {
		ast_debug(1, "BYE received but no owner channel\n");
	}
	
	/* Release RTP resources if any */
	if (pvt->rtp) {
		ast_debug(3, "Stopping RTP for terminated dialog\n");
		ast_rtp_instance_stop(pvt->rtp);
	}
	
	/* Log for debugging */
	ast_debug(3, "=== BYE Processed ===\n");
	ast_debug(3, "Call-ID: %s\n", call_id);
	ast_debug(3, "From: %s (tag=%s)\n",
		sip->sip_from->a_url->url_user, from_tag);
	ast_debug(3, "To: %s (tag=%s)\n",
		sip->sip_to->a_url->url_user, to_tag);
	ast_debug(3, "Cause: %d (%s)\n", cause, ast_cause2str(cause));
	ast_debug(3, "====================\n");
}

/*!
 * \brief Send BYE request
 * \param pvt Private structure
 * \param cause Hangup cause code
 * \return 0 on success, -1 on failure
 */
int sofia_send_bye(struct sofia_pvt *pvt, int cause)
{
	char reason_buf[256];
	int sip_cause = 200; /* Default to normal */
	const char *reason_text = "Normal Clearing";
	
	if (!pvt || !pvt->nh) {
		ast_log(LOG_ERROR, "Cannot send BYE - invalid private structure\n");
		return -1;
	}
	
	/* Only send BYE for confirmed dialogs */
	if (pvt->dialog_state != DIALOG_STATE_CONFIRMED) {
		ast_debug(2, "Not sending BYE - dialog not confirmed (state=%d)\n",
			pvt->dialog_state);
		return 0;
	}
	
	/* Map Asterisk cause to SIP cause */
	switch (cause) {
	case AST_CAUSE_UNALLOCATED:
		sip_cause = 404;
		reason_text = "Not Found";
		break;
	case AST_CAUSE_BUSY:
		sip_cause = 486;
		reason_text = "Busy Here";
		break;
	case AST_CAUSE_NO_ANSWER:
		sip_cause = 480;
		reason_text = "Temporarily Unavailable";
		break;
	case AST_CAUSE_CALL_REJECTED:
		sip_cause = 403;
		reason_text = "Forbidden";
		break;
	case AST_CAUSE_CONGESTION:
		sip_cause = 503;
		reason_text = "Service Unavailable";
		break;
	default:
		/* Use default values */
		break;
	}
	
	/* Build Reason header */
	snprintf(reason_buf, sizeof(reason_buf),
		"SIP;cause=%d;text=\"%s\";Q.850;cause=%d",
		sip_cause, reason_text, cause);
	
	ast_debug(1, "Sending BYE with Reason: %s\n", reason_buf);
	
	/* Send BYE */
	nua_bye(pvt->nh,
		SIPTAG_REASON_STR(reason_buf),
		TAG_END());
	
	/* Update dialog state */
	pvt->dialog_state = DIALOG_STATE_TERMINATED;
	
	return 0;
}

/*!
 * \brief Check if we should send BYE for this dialog
 * \param pvt Private structure
 * \return 1 if BYE should be sent, 0 otherwise
 */
int sofia_should_send_bye(struct sofia_pvt *pvt)
{
	if (!pvt) {
		return 0;
	}
	
	/* Only send BYE for confirmed dialogs that haven't been terminated */
	return (pvt->dialog_state == DIALOG_STATE_CONFIRMED);
}