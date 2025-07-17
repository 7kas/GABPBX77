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
 * \brief Chan_sofia CANCEL method implementation
 *
 * \author Germán Aracil Boned <garacilb@gmail.com>
 *
 * \ingroup channel_drivers
 */

/*** DOCUMENTATION
 * CANCEL Method Implementation per RFC 3261 Section 9
 * 
 * CANCEL is used to cancel a pending request, particularly INVITE.
 * 
 * Key rules:
 * 1. CANCEL should only be sent for INVITE (other methods respond too quickly)
 * 2. Must wait for provisional response before sending CANCEL
 * 3. CANCEL has no effect after final response
 * 4. CANCEL is hop-by-hop (each proxy responds)
 * 5. Must match original request exactly (except CSeq method and Via)
 * 6. Server responds 200 OK to CANCEL, 487 to original INVITE
 ***/

/*!
 * \brief Validate CANCEL request
 * \param sip SIP message
 * \param profile Sofia profile
 * \return 0 on success, -1 on failure
 */
static int validate_cancel_request(sip_t const *sip, struct sip_profile *profile)
{
	/* Validate required headers */
	if (!sip->sip_request || !sip->sip_request->rq_method_name) {
		ast_log(LOG_ERROR, "CANCEL: Missing request line\n");
		return -1;
	}
	
	if (!sip->sip_call_id) {
		ast_log(LOG_ERROR, "CANCEL: Missing Call-ID header\n");
		return -1;
	}
	
	if (!sip->sip_from || !sip->sip_from->a_tag) {
		ast_log(LOG_ERROR, "CANCEL: Missing From header or tag\n");
		return -1;
	}
	
	if (!sip->sip_to) {
		ast_log(LOG_ERROR, "CANCEL: Missing To header\n");
		return -1;
	}
	
	if (!sip->sip_cseq) {
		ast_log(LOG_ERROR, "CANCEL: Missing CSeq header\n");
		return -1;
	}
	
	/* Verify CSeq method is CANCEL */
	if (strcasecmp(sip->sip_cseq->cs_method_name, "CANCEL") != 0) {
		ast_log(LOG_ERROR, "CANCEL: CSeq method mismatch: %s\n",
			sip->sip_cseq->cs_method_name);
		return -1;
	}
	
	/* CANCEL must not contain Require or Proxy-Require */
	if (sip->sip_require) {
		ast_log(LOG_WARNING, "CANCEL: Contains Require header (RFC violation)\n");
	}
	
	if (sip->sip_proxy_require) {
		ast_log(LOG_WARNING, "CANCEL: Contains Proxy-Require header (RFC violation)\n");
	}
	
	return 0;
}

/*!
 * \brief Handle CANCEL request
 * \param nh NUA handle
 * \param profile Sofia profile
 * \param sip SIP message
 * \param tags Sofia tags
 * 
 * Per RFC 3261:
 * 1. Match CANCEL to pending transaction (usually INVITE)
 * 2. Send 200 OK for CANCEL immediately
 * 3. If match found and not yet finally responded, cancel it
 * 4. Original request should get 487 Request Terminated
 */
void handle_cancel_request(nua_handle_t *nh, struct sip_profile *profile,
	sip_t const *sip, tagi_t tags[])
{
	struct sofia_pvt *pvt = NULL;
	char call_id[256];
	char from_tag[128];
	char to_tag[128] = "";
	
	if (!nh || !sip) {
		ast_log(LOG_ERROR, "CANCEL: Invalid parameters\n");
		return;
	}
	
	/* Validate CANCEL request */
	if (validate_cancel_request(sip, profile) != 0) {
		ast_log(LOG_WARNING, "CANCEL: Validation failed\n");
		/* Sofia-SIP will handle the error response */
		return;
	}
	
	/* Extract identifiers for logging */
	ast_copy_string(call_id, sip->sip_call_id->i_id, sizeof(call_id));
	ast_copy_string(from_tag, sip->sip_from->a_tag, sizeof(from_tag));
	if (sip->sip_to->a_tag) {
		ast_copy_string(to_tag, sip->sip_to->a_tag, sizeof(to_tag));
	}
	
	ast_debug(1, "CANCEL received - Call-ID: %s, From-tag: %s, To-tag: %s\n",
		call_id, from_tag, to_tag);
	
	/* Get private data from handle */
	pvt = nua_handle_magic(nh);
	
	/* 
	 * Sofia-SIP automatically:
	 * 1. Sends 200 OK for CANCEL
	 * 2. Matches CANCEL to original transaction
	 * 3. Can auto-generate 487 if NTATAG_CANCEL_487 is set
	 * 
	 * We just need to handle the Asterisk side
	 */
	
	if (pvt && pvt->owner) {
		struct ast_channel *owner = pvt->owner;
		
		/* Check dialog state */
		if (pvt->dialog_state == DIALOG_STATE_EARLY ||
		    pvt->dialog_state == DIALOG_STATE_INITIAL) {
			
			ast_debug(2, "CANCEL: Terminating early dialog on channel %s\n",
				ast_channel_name(owner));
			
			/* Set cause to indicate request was cancelled */
			ast_channel_hangupcause_set(owner, AST_CAUSE_CALL_REJECTED);
			
			/* Store CANCEL info for CDR */
			pbx_builtin_setvar_helper(owner, "SIP_HANGUP_DISPOSITION", "recv_cancel");
			pbx_builtin_setvar_helper(owner, "SIP_INVITE_FAILURE_STATUS", "487");
			pbx_builtin_setvar_helper(owner, "SIP_INVITE_FAILURE_PHRASE", "Request Terminated");
			
			/* Extract Reason header if present */
			if (sip->sip_reason) {
				char reason_str[256];
				sip_reason_t *reason = sip->sip_reason;
				
				snprintf(reason_str, sizeof(reason_str), "%s;cause=%s%s%s",
					reason->re_protocol ? reason->re_protocol : "SIP",
					reason->re_cause ? reason->re_cause : "487",
					reason->re_text ? ";text=" : "",
					reason->re_text ? reason->re_text : "");
				
				pbx_builtin_setvar_helper(owner, "SIP_CANCEL_REASON", reason_str);
				ast_debug(2, "CANCEL Reason: %s\n", reason_str);
			}
			
			/* Queue hangup */
			ast_queue_hangup(owner);
			
		} else if (pvt->dialog_state == DIALOG_STATE_CONFIRMED) {
			/* Late CANCEL - dialog already established */
			ast_debug(1, "Late CANCEL received - dialog already confirmed\n");
			/* Sofia-SIP will send 481 automatically */
			
		} else {
			ast_debug(1, "CANCEL for dialog in state %d\n", pvt->dialog_state);
		}
		
	} else if (pvt) {
		/* CANCEL without owner - might be for failed INVITE */
		ast_debug(2, "CANCEL received for dialog without owner\n");
		/* Sofia-SIP handles the transaction matching and responses */
		
	} else {
		/* No context - let Sofia-SIP handle it */
		ast_debug(1, "CANCEL received without associated dialog\n");
		/* Sofia-SIP will send appropriate error response */
	}
	
	/* Log for debugging */
	ast_debug(3, "=== CANCEL Processed ===\n");
	ast_debug(3, "Call-ID: %s\n", call_id);
	ast_debug(3, "From: %s (tag=%s)\n",
		sip->sip_from->a_url->url_user, from_tag);
	ast_debug(3, "To: %s%s%s\n",
		sip->sip_to->a_url->url_user,
		to_tag[0] ? " (tag=" : "",
		to_tag[0] ? to_tag : "");
	ast_debug(3, "CSeq: %u %s\n",
		sip->sip_cseq->cs_seq, sip->sip_cseq->cs_method_name);
	ast_debug(3, "========================\n");
}

/*!
 * \brief Send CANCEL request
 * \param pvt Private structure
 * \return 0 on success, -1 on failure
 * 
 * Used to cancel our outgoing INVITE
 */
int sofia_send_cancel(struct sofia_pvt *pvt)
{
	if (!pvt || !pvt->nh) {
		ast_log(LOG_ERROR, "Cannot send CANCEL - invalid private structure\n");
		return -1;
	}
	
	/* Check dialog state - can only CANCEL early dialogs */
	if (pvt->dialog_state != DIALOG_STATE_EARLY &&
	    pvt->dialog_state != DIALOG_STATE_INITIAL) {
		ast_debug(2, "Not sending CANCEL - dialog state is %d\n",
			pvt->dialog_state);
		return -1;
	}
	
	ast_debug(1, "Sending CANCEL for channel %s\n",
		pvt->owner ? ast_channel_name(pvt->owner) : "unknown");
	
	/* Build Reason header if we have a cause */
	if (pvt->owner) {
		int cause = ast_channel_hangupcause(pvt->owner);
		char reason_buf[256];
		
		if (cause && cause != AST_CAUSE_NORMAL_CLEARING) {
			/* Map Asterisk cause to SIP cause */
			int sip_cause = 486; /* Default: Busy Here */
			const char *text = "Busy";
			
			switch (cause) {
			case AST_CAUSE_USER_BUSY:
				sip_cause = 486;
				text = "Busy Here";
				break;
			case AST_CAUSE_CALL_REJECTED:
				sip_cause = 603;
				text = "Decline";
				break;
			case AST_CAUSE_NO_ANSWER:
				sip_cause = 480;
				text = "Temporarily Unavailable";
				break;
			default:
				sip_cause = 486;
				text = ast_cause2str(cause);
				break;
			}
			
			snprintf(reason_buf, sizeof(reason_buf),
				"SIP;cause=%d;text=\"%s\"", sip_cause, text);
			
			/* Send CANCEL with Reason header */
			nua_cancel(pvt->nh,
				SIPTAG_REASON_STR(reason_buf),
				TAG_END());
		} else {
			/* Send CANCEL without Reason */
			nua_cancel(pvt->nh, TAG_END());
		}
	} else {
		/* No owner - send basic CANCEL */
		nua_cancel(pvt->nh, TAG_END());
	}
	
	return 0;
}

/*!
 * \brief Check if we should send CANCEL for this dialog
 * \param pvt Private structure
 * \return 1 if CANCEL should be sent, 0 otherwise
 */
int sofia_should_send_cancel(struct sofia_pvt *pvt)
{
	if (!pvt) {
		return 0;
	}
	
	/* Only send CANCEL for early dialogs (before final response) */
	return (pvt->dialog_state == DIALOG_STATE_EARLY ||
		pvt->dialog_state == DIALOG_STATE_INITIAL);
}