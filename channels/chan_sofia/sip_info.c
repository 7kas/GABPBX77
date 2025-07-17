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
 * \brief Chan_sofia INFO method implementation
 *
 * \author Germán Aracil Boned <garacilb@gmail.com>
 *
 * \ingroup channel_drivers
 */

/* Helper macro for responses with message context */
#define NUA_RESPOND_MSG(nh, status, phrase, msg, ...) \
	do { \
		if (msg) { \
			nua_respond(nh, status, phrase, \
				NUTAG_WITH_THIS_MSG(msg), ##__VA_ARGS__, TAG_END()); \
		} else { \
			nua_respond(nh, status, phrase, ##__VA_ARGS__, TAG_END()); \
		} \
	} while (0)

/*** DOCUMENTATION
 * INFO Method Implementation per RFC 2976
 * 
 * INFO carries application-level information within a dialog.
 * Common uses:
 * - DTMF digits transmission
 * - Media control commands
 * - Display updates
 * - Session keepalive
 ***/

/*!
 * \brief Convert RFC 2833 code to DTMF character
 * \param code RFC 2833 numeric code
 * \return DTMF character or 0 if invalid
 */
static char rfc2833_to_char(int code)
{
	if (code >= 0 && code <= 9) {
		return '0' + code;
	} else if (code == 10) {
		return '*';
	} else if (code == 11) {
		return '#';
	} else if (code >= 12 && code <= 15) {
		return 'A' + (code - 12);
	}
	return 0; /* Invalid code */
}

/*!
 * \brief Parse DTMF from application/dtmf-relay format
 * \param payload Payload data
 * \param digit Output DTMF digit
 * \param duration Output duration in ms
 * \return 0 on success, -1 on failure
 * 
 * Format:
 * Signal=5
 * Duration=160
 */
static int parse_dtmf_relay(const char *payload, char *digit, int *duration)
{
	const char *p;
	int signal = -1;
	
	*digit = 0;
	*duration = 0;
	
	/* Find Signal= */
	p = strstr(payload, "Signal=");
	if (!p) {
		p = strstr(payload, "signal=");
	}
	if (p) {
		p += 7;
		/* Some devices put a space after = */
		while (*p == ' ') p++;
		
		if (*p >= '0' && *p <= '9') {
			signal = *p - '0';
		} else if (*p == '*') {
			signal = 10;
		} else if (*p == '#') {
			signal = 11;
		} else if (*p >= 'A' && *p <= 'D') {
			signal = 12 + (*p - 'A');
		} else if (*p >= 'a' && *p <= 'd') {
			signal = 12 + (*p - 'a');
		}
	}
	
	if (signal < 0) {
		return -1;
	}
	
	*digit = rfc2833_to_char(signal);
	
	/* Find Duration= */
	p = strstr(payload, "Duration=");
	if (!p) {
		p = strstr(payload, "duration=");
	}
	if (p) {
		p += 9;
		while (*p == ' ') p++;
		*duration = atoi(p);
	}
	
	/* Default duration if not specified */
	if (*duration <= 0) {
		*duration = 100; /* 100ms default */
	}
	
	return 0;
}

/*!
 * \brief Parse DTMF from application/dtmf format
 * \param payload Payload data
 * \param digit Output DTMF digit
 * \return 0 on success, -1 on failure
 * 
 * Format: Just the RFC 2833 numeric code
 */
static int parse_dtmf_simple(const char *payload, char *digit)
{
	int code = atoi(payload);
	*digit = rfc2833_to_char(code);
	return *digit ? 0 : -1;
}

/*!
 * \brief Parse DTMF from Nortel format
 * \param payload Payload data
 * \param digit Output DTMF digit
 * \return 0 on success, -1 on failure
 * 
 * Format: d=5
 */
static int parse_dtmf_nortel(const char *payload, char *digit)
{
	const char *p;
	
	*digit = 0;
	
	p = strstr(payload, "d=");
	if (!p) {
		p = strstr(payload, "D=");
	}
	
	if (p) {
		p += 2;
		while (*p == ' ') p++;
		
		if ((*p >= '0' && *p <= '9') || *p == '*' || *p == '#' ||
		    (*p >= 'A' && *p <= 'D') || (*p >= 'a' && *p <= 'd')) {
			*digit = toupper(*p);
			return 0;
		}
	}
	
	return -1;
}

/*!
 * \brief Handle INFO request
 * \param nh NUA handle
 * \param profile Sofia profile
 * \param sip SIP message
 * \param tags Sofia tags
 */
void handle_info_request(nua_handle_t *nh, struct sip_profile *profile,
	sip_t const *sip, tagi_t tags[], msg_t *msg)
{
	struct sofia_pvt *pvt = NULL;
	const char *content_type = NULL;
	const char *payload = NULL;
	size_t payload_len = 0;
	char digit = 0;
	int duration = 0;
	
	if (!nh || !sip) {
		ast_log(LOG_ERROR, "INFO: Invalid parameters\n");
		return;
	}
	
	/* Get private data */
	pvt = nua_handle_magic(nh);
	
	/* INFO should be within a dialog */
	if (!pvt || !pvt->owner) {
		ast_debug(1, "INFO received without active dialog\n");
		NUA_RESPOND_MSG(nh, 481, "Call/Transaction Does Not Exist", msg);
		return;
	}
	
	/* Get content type and payload */
	if (sip->sip_content_type) {
		content_type = sip->sip_content_type->c_type;
	}
	
	if (sip->sip_payload) {
		payload = sip->sip_payload->pl_data;
		payload_len = sip->sip_payload->pl_len;
	}
	
	ast_debug(2, "INFO received on %s - Content-Type: %s, Length: %zu\n",
		ast_channel_name(pvt->owner),
		content_type ? content_type : "none",
		payload_len);
	
	/* Handle different content types */
	if (!content_type) {
		/* No content type - just acknowledge */
		NUA_RESPOND_MSG(nh, 200, "OK", msg);
		return;
	}
	
	/* DTMF handling */
	if (strcasecmp(content_type, "application/dtmf-relay") == 0) {
		/* RFC 2833 style DTMF */
		if (payload && parse_dtmf_relay(payload, &digit, &duration) == 0) {
			ast_debug(1, "INFO DTMF: digit='%c' duration=%dms\n", digit, duration);
			
			/* Queue DTMF to channel */
			struct ast_frame f = {
				.frametype = AST_FRAME_DTMF,
				.subclass.integer = digit,
				.len = duration,
				.src = "INFO"
			};
			ast_queue_frame(pvt->owner, &f);
			
			NUA_RESPOND_MSG(nh, 200, "OK", msg);
		} else {
			ast_log(LOG_WARNING, "Failed to parse DTMF relay payload\n");
			NUA_RESPOND_MSG(nh, 400, "Bad Request", msg);
		}
		
	} else if (strcasecmp(content_type, "application/dtmf") == 0) {
		/* Simple DTMF format */
		if (payload && parse_dtmf_simple(payload, &digit) == 0) {
			ast_debug(1, "INFO DTMF: digit='%c'\n", digit);
			
			/* Queue DTMF to channel */
			struct ast_frame f = {
				.frametype = AST_FRAME_DTMF,
				.subclass.integer = digit,
				.len = 100, /* Default 100ms */
				.src = "INFO"
			};
			ast_queue_frame(pvt->owner, &f);
			
			NUA_RESPOND_MSG(nh, 200, "OK", msg);
		} else {
			ast_log(LOG_WARNING, "Failed to parse simple DTMF payload\n");
			NUA_RESPOND_MSG(nh, 400, "Bad Request", msg);
		}
		
	} else if (strcasecmp(content_type, "application/vnd.nortelnetworks.digits") == 0) {
		/* Nortel DTMF format */
		if (payload && parse_dtmf_nortel(payload, &digit) == 0) {
			ast_debug(1, "INFO DTMF (Nortel): digit='%c'\n", digit);
			
			/* Queue DTMF to channel */
			struct ast_frame f = {
				.frametype = AST_FRAME_DTMF,
				.subclass.integer = digit,
				.len = 100, /* Default 100ms */
				.src = "INFO"
			};
			ast_queue_frame(pvt->owner, &f);
			
			NUA_RESPOND_MSG(nh, 200, "OK", msg);
		} else {
			ast_log(LOG_WARNING, "Failed to parse Nortel DTMF payload\n");
			NUA_RESPOND_MSG(nh, 400, "Bad Request", msg);
		}
		
	} else if (strcasecmp(content_type, "application/media_control+xml") == 0) {
		/* Media control - useful for video */
		ast_debug(2, "INFO media control received\n");
		/* TODO: Implement video key frame request if needed */
		NUA_RESPOND_MSG(nh, 200, "OK", msg);
		
	} else if (strcasecmp(content_type, "message/sipfrag") == 0) {
		/* SIP fragment - often used for display updates */
		ast_debug(2, "INFO sipfrag received: %.*s\n", (int)payload_len, payload);
		NUA_RESPOND_MSG(nh, 200, "OK", msg);
		
	} else if (strcasecmp(content_type, "text/plain") == 0) {
		/* Plain text - could be keepalive or other */
		ast_debug(2, "INFO text received: %.*s\n", (int)payload_len, payload);
		NUA_RESPOND_MSG(nh, 200, "OK", msg);
		
	} else {
		/* Unsupported content type */
		ast_debug(1, "Unsupported INFO content type: %s\n", content_type);
		NUA_RESPOND_MSG(nh, 415, "Unsupported Media Type", msg);
	}
}

/*!
 * \brief Send INFO request
 * \param pvt Private structure
 * \param content_type Content type
 * \param payload Payload data
 * \return 0 on success, -1 on failure
 */
int sofia_send_info(struct sofia_pvt *pvt, const char *content_type, const char *payload)
{
	if (!pvt || !pvt->nh) {
		ast_log(LOG_ERROR, "Cannot send INFO - invalid private structure\n");
		return -1;
	}
	
	/* INFO only valid in confirmed dialogs */
	if (pvt->dialog_state != DIALOG_STATE_CONFIRMED) {
		ast_debug(2, "Not sending INFO - dialog not confirmed\n");
		return -1;
	}
	
	ast_debug(2, "Sending INFO - Content-Type: %s\n", content_type);
	
	if (content_type && payload) {
		nua_info(pvt->nh,
			SIPTAG_CONTENT_TYPE_STR(content_type),
			SIPTAG_PAYLOAD_STR(payload),
			TAG_END());
	} else {
		/* Empty INFO */
		nua_info(pvt->nh, TAG_END());
	}
	
	return 0;
}

/*!
 * \brief Send DTMF digit via INFO
 * \param pvt Private structure
 * \param digit DTMF digit to send
 * \param duration Duration in milliseconds
 * \return 0 on success, -1 on failure
 */
int sofia_send_dtmf_info(struct sofia_pvt *pvt, char digit, int duration)
{
	char payload[128];
	int signal;
	
	if (!pvt || !pvt->nh) {
		return -1;
	}
	
	/* Convert digit to RFC 2833 signal */
	if (digit >= '0' && digit <= '9') {
		signal = digit - '0';
	} else if (digit == '*') {
		signal = 10;
	} else if (digit == '#') {
		signal = 11;
	} else if (digit >= 'A' && digit <= 'D') {
		signal = 12 + (digit - 'A');
	} else if (digit >= 'a' && digit <= 'd') {
		signal = 12 + (digit - 'a');
	} else {
		ast_log(LOG_WARNING, "Invalid DTMF digit: %c\n", digit);
		return -1;
	}
	
	/* Default duration */
	if (duration <= 0) {
		duration = 250; /* 250ms default */
	}
	
	/* Build payload */
	snprintf(payload, sizeof(payload), "Signal=%d\r\nDuration=%d\r\n", signal, duration);
	
	ast_debug(1, "Sending DTMF '%c' via INFO (signal=%d, duration=%dms)\n",
		digit, signal, duration);
	
	return sofia_send_info(pvt, "application/dtmf-relay", payload);
}