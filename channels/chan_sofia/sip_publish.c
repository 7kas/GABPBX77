/*
 * Asterisk -- An open source telephony toolkit.
 *
 * Copyright (C) 2024, Germán Aracil Boned garacilb@gmail.com
 * Copyright (C) 2024, 7kas servicios de internet SL.
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

/*! \file
 *
 * \brief PUBLISH method implementation for chan_sofia
 *
 * \author Germán Aracil Boned <garacilb@gmail.com>
 *
 * \ingroup channel_drivers
 */

/*** MODULEINFO
	<depend>sofia-sip</depend>
	<support_level>extended</support_level>
 ***/

/* PUBLISH method implementation as per RFC 3903
 *
 * PUBLISH is used to publish event state to an Event State Compositor (ESC).
 * Key features:
 * - Creates, modifies, and removes event state
 * - Uses entity-tags (ETags) for state management
 * - Supports conditional requests with SIP-If-Match
 * - Event packages: presence, dialog, message-summary
 */

struct sip_publication {
	char id[64];                    /* Unique publication ID */
	char uri[256];                  /* Published URI */
	char event[64];                 /* Event package */
	char etag[64];                  /* Entity tag */
	char *body;                     /* Published event state */
	int body_len;                   /* Body length */
	time_t expires;                 /* Expiration time */
	struct sip_endpoint *endpoint;  /* Publishing endpoint */
};

/* Global publications container */
static struct ao2_container *publications = NULL;

/* Forward declarations */
static int sip_publication_hash(const void *obj, const int flags);
static int sip_publication_cmp(void *obj, void *arg, int flags);
static void sip_publication_destructor(void *obj);
static struct sip_publication *find_publication(const char *uri, const char *event, const char *etag);
static char *generate_etag(void);
static int validate_event_package(const char *event);

/*!
 * \brief Initialize PUBLISH subsystem
 */
int sip_publish_init(void)
{
	/* Create publications container with 4096 buckets for O(1) lookup */
	publications = ao2_container_alloc_hash(AO2_ALLOC_OPT_LOCK_MUTEX, 0,
		4096, sip_publication_hash, NULL, sip_publication_cmp);
	
	if (!publications) {
		ast_log(LOG_ERROR, "Failed to create publications container\n");
		return -1;
	}
	
	ast_log(LOG_NOTICE, "PUBLISH subsystem initialized with 4096 bucket hash table\n");
	return 0;
}

/*!
 * \brief Destroy PUBLISH subsystem
 */
void sip_publish_destroy(void)
{
	if (publications) {
		ao2_ref(publications, -1);
		publications = NULL;
	}
}

/*!
 * \brief Hash function for publications
 */
static int sip_publication_hash(const void *obj, const int flags)
{
	const struct sip_publication *pub = obj;
	const char *key = (flags & OBJ_KEY) ? obj : pub->id;
	return ast_str_hash(key);
}

/*!
 * \brief Compare function for publications
 */
static int sip_publication_cmp(void *obj, void *arg, int flags)
{
	struct sip_publication *pub1 = obj;
	struct sip_publication *pub2 = arg;
	const char *key = (flags & OBJ_KEY) ? arg : pub2->id;
	
	return strcmp(pub1->id, key) ? 0 : CMP_MATCH | CMP_STOP;
}

/*!
 * \brief Destructor for publication
 */
static void sip_publication_destructor(void *obj)
{
	struct sip_publication *pub = obj;
	if (pub->body) {
		ast_free(pub->body);
	}
}

/*!
 * \brief Find publication by URI, event, and optionally etag
 */
static struct sip_publication *find_publication(const char *uri, const char *event, const char *etag)
{
	struct ao2_iterator iter;
	struct sip_publication *pub;
	struct sip_publication *found = NULL;
	
	iter = ao2_iterator_init(publications, 0);
	while ((pub = ao2_iterator_next(&iter))) {
		if (!strcasecmp(pub->uri, uri) && !strcasecmp(pub->event, event)) {
			if (!etag || !strcasecmp(pub->etag, etag)) {
				found = pub;
				break;
			}
		}
		ao2_ref(pub, -1);
	}
	ao2_iterator_destroy(&iter);
	
	return found;
}

/*!
 * \brief Generate unique entity tag
 */
static char *generate_etag(void)
{
	static char etag[64];
	unsigned int rand1 = ast_random();
	unsigned int rand2 = ast_random();
	snprintf(etag, sizeof(etag), "%08x%08x", rand1, rand2);
	return etag;
}

/*!
 * \brief Validate event package
 */
static int validate_event_package(const char *event)
{
	/* Supported event packages */
	static const char *supported[] = {
		"presence",
		"dialog",
		"message-summary",
		NULL
	};
	
	const char **pkg;
	for (pkg = supported; *pkg; pkg++) {
		if (!strcasecmp(event, *pkg)) {
			return 1;
		}
	}
	return 0;
}

/*!
 * \brief Handle incoming PUBLISH request
 *
 * RFC 3903 Section 6: Processing PUBLISH Requests
 */
void handle_publish_request(nua_handle_t *nh, struct sip_profile *profile, sip_t const *sip, tagi_t tags[], nua_t *nua, nua_saved_event_t *saved)
{
	const char *from = NULL;
	const char *to = NULL;
	const char *event = NULL;
	const char *if_match = NULL;
	const char *expires_str = NULL;
	int expires = 3600; /* Default 1 hour */
	struct sip_publication *pub = NULL;
	char *new_etag = NULL;
	su_home_t *home = NULL;
	msg_t *msg = NULL;
	
	/* Get the message from saved event data for proper response */
	if (saved) {
		nua_event_data_t const *data = nua_event_data(saved);
		if (data && data->e_msg) {
			msg = data->e_msg;
		}
	}
	
	if (!nh || !profile || !sip) {
		ast_log(LOG_ERROR, "Invalid parameters for PUBLISH request\n");
		return;
	}
	
	/* Extract headers */
	from = sip->sip_from ? sip->sip_from->a_url->url_user : "unknown";
	to = sip->sip_to ? sip->sip_to->a_url->url_user : "unknown";
	
	/* RFC 3903: PUBLISH MUST contain Event header */
	if (!sip->sip_event || !sip->sip_event->o_type) {
		ast_log(LOG_WARNING, "PUBLISH from %s missing Event header\n", from);
		nua_respond(nh, 400, "Bad Request - Missing Event Header", 
			TAG_IF(msg, NUTAG_WITH_THIS_MSG(msg)),
			TAG_END());
		return;
	}
	event = sip->sip_event->o_type;
	
	/* Check if we support this event package */
	if (!validate_event_package(event)) {
		ast_log(LOG_WARNING, "PUBLISH from %s for unsupported event package: %s\n", from, event);
		nua_respond(nh, 489, "Bad Event", 
			TAG_IF(msg, NUTAG_WITH_THIS_MSG(msg)),
			TAG_END());
		return;
	}
	
	/* Get SIP-If-Match header if present */
	if (sip->sip_if_match) {
		if_match = sip->sip_if_match->g_string;
	}
	
	/* Get Expires header */
	if (sip->sip_expires) {
		expires = sip->sip_expires->ex_delta;
	}
	/* Build expires string */
	if (sip->sip_expires) {
		static char exp_buf[32];
		snprintf(exp_buf, sizeof(exp_buf), "%ld", sip->sip_expires->ex_delta);
		expires_str = exp_buf;
	} else {
		expires_str = "3600";
	}
	
	/* Validate expires value */
	if (expires < 0) {
		expires = 0;
	} else if (expires > 0 && expires < 60) {
		/* Minimum expiration interval */
		ast_log(LOG_NOTICE, "PUBLISH from %s expires %d too brief\n", from, expires);
		nua_respond(nh, 423, "Interval Too Brief",
			SIPTAG_MIN_EXPIRES_STR("60"),
			TAG_IF(msg, NUTAG_WITH_THIS_MSG(msg)),
			TAG_END());
		return;
	}
	
	ast_debug(1, "PUBLISH request from %s to %s for event %s (expires=%d)\n",
		from, to, event, expires);
	
	/* Handle conditional request */
	if (if_match) {
		pub = find_publication(to, event, if_match);
		if (!pub) {
			ast_log(LOG_WARNING, "PUBLISH from %s with unknown etag: %s\n", from, if_match);
			nua_respond(nh, 412, "Conditional Request Failed", 
				TAG_IF(msg, NUTAG_WITH_THIS_MSG(msg)),
				TAG_END());
			return;
		}
	}
	
	/* Process based on body and expires */
	if (expires == 0 && pub) {
		/* Remove publication */
		ast_log(LOG_NOTICE, "Removing publication for %s event %s\n", to, event);
		ao2_unlink(publications, pub);
		ao2_ref(pub, -1);
		
		/* Send 200 OK with expires 0 */
		nua_respond(nh, 200, "OK",
			SIPTAG_EXPIRES_STR("0"),
			TAG_IF(msg, NUTAG_WITH_THIS_MSG(msg)),
			TAG_END());
		return;
	}
	
	/* Check for body */
	if (!sip->sip_payload || !sip->sip_payload->pl_data) {
		if (!pub) {
			/* Initial PUBLISH must have body (unless special semantics) */
			ast_log(LOG_WARNING, "Initial PUBLISH from %s has no body\n", from);
			nua_respond(nh, 400, "Bad Request - No Body", 
				TAG_IF(msg, NUTAG_WITH_THIS_MSG(msg)),
				TAG_END());
			return;
		}
		/* Refresh existing publication */
		pub->expires = time(NULL) + expires;
		new_etag = ast_strdupa(pub->etag);
	} else {
		/* Create or update publication */
		if (!pub) {
			/* Create new publication */
			pub = ao2_alloc(sizeof(*pub), sip_publication_destructor);
			if (!pub) {
				ast_log(LOG_ERROR, "Failed to allocate publication\n");
				nua_respond(nh, 500, "Server Internal Error", 
					TAG_IF(msg, NUTAG_WITH_THIS_MSG(msg)),
					TAG_END());
				return;
			}
			
			/* Generate unique ID */
			snprintf(pub->id, sizeof(pub->id), "%s_%s_%lu", to, event, ast_random());
			ast_copy_string(pub->uri, to, sizeof(pub->uri));
			ast_copy_string(pub->event, event, sizeof(pub->event));
			
			ao2_link(publications, pub);
		}
		
		/* Update body */
		if (pub->body) {
			ast_free(pub->body);
		}
		pub->body_len = sip->sip_payload->pl_len;
		pub->body = ast_malloc(pub->body_len + 1);
		if (!pub->body) {
			ast_log(LOG_ERROR, "Failed to allocate body\n");
			ao2_ref(pub, -1);
			nua_respond(nh, 500, "Server Internal Error", 
				TAG_IF(msg, NUTAG_WITH_THIS_MSG(msg)),
				TAG_END());
			return;
		}
		memcpy(pub->body, sip->sip_payload->pl_data, pub->body_len);
		pub->body[pub->body_len] = '\0';
		
		/* Generate new etag */
		new_etag = generate_etag();
		ast_copy_string(pub->etag, new_etag, sizeof(pub->etag));
		pub->expires = time(NULL) + expires;
	}
	
	/* Send 200 OK with SIP-ETag */
	home = su_home_new(sizeof(*home));
	if (home) {
		sip_etag_t *etag = sip_etag_format(home, "%s", new_etag);
		
		nua_respond(nh, 200, "OK",
			SIPTAG_EXPIRES_STR(expires_str),
			SIPTAG_ETAG(etag),
			TAG_IF(msg, NUTAG_WITH_THIS_MSG(msg)),
			TAG_END());
		
		su_home_unref(home);
	} else {
		nua_respond(nh, 200, "OK",
			SIPTAG_EXPIRES_STR(expires_str),
			TAG_IF(msg, NUTAG_WITH_THIS_MSG(msg)),
			TAG_END());
	}
	
	ast_log(LOG_NOTICE, "PUBLISH from %s for %s event %s: %s (etag=%s, expires=%d)\n",
		from, to, event,
		pub->body ? "updated" : "refreshed",
		new_etag, expires);
	
	if (pub) {
		ao2_ref(pub, -1);
	}
	
	/* TODO: Notify subscribers about state change */
	/* This would integrate with SUBSCRIBE/NOTIFY for real-time updates */
}

/*!
 * \brief CLI command to show publications
 */
static char *sip_show_publications(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
{
	struct ao2_iterator iter;
	struct sip_publication *pub;
	int count = 0;
	time_t now = time(NULL);
	
	switch (cmd) {
	case CLI_INIT:
		e->command = "sip show publications";
		e->usage =
			"Usage: sip show publications\n"
			"       Show all active event publications\n";
		return NULL;
	case CLI_GENERATE:
		return NULL;
	}
	
	if (a->argc != 3) {
		return CLI_SHOWUSAGE;
	}
	
	ast_cli(a->fd, "%-20s %-15s %-16s %-10s %-8s\n",
		"URI", "Event", "ETag", "Expires", "Body");
	ast_cli(a->fd, "%-20s %-15s %-16s %-10s %-8s\n",
		"--------------------", "---------------", "----------------",
		"----------", "--------");
	
	iter = ao2_iterator_init(publications, 0);
	while ((pub = ao2_iterator_next(&iter))) {
		int remaining = pub->expires - now;
		if (remaining < 0) {
			remaining = 0;
		}
		
		ast_cli(a->fd, "%-20s %-15s %-16s %-10d %-8d\n",
			pub->uri, pub->event, pub->etag,
			remaining, pub->body_len);
		
		count++;
		ao2_ref(pub, -1);
	}
	ao2_iterator_destroy(&iter);
	
	ast_cli(a->fd, "\n%d active publication%s\n", count, count != 1 ? "s" : "");
	
	return CLI_SUCCESS;
}

/* CLI command definition */
static struct ast_cli_entry sip_publish_cli[] = {
	AST_CLI_DEFINE(sip_show_publications, "Show active event publications"),
};

/*!
 * \brief Register PUBLISH CLI commands
 */
void sip_publish_register_cli(void)
{
	ast_cli_register_multiple(sip_publish_cli, ARRAY_LEN(sip_publish_cli));
}

/*!
 * \brief Unregister PUBLISH CLI commands
 */
void sip_publish_unregister_cli(void)
{
	ast_cli_unregister_multiple(sip_publish_cli, ARRAY_LEN(sip_publish_cli));
}

/*!
 * \brief Cleanup expired publications periodically
 */
void sip_publish_cleanup(void)
{
	struct ao2_iterator iter;
	struct sip_publication *pub;
	time_t now = time(NULL);
	int removed = 0;
	
	iter = ao2_iterator_init(publications, 0);
	while ((pub = ao2_iterator_next(&iter))) {
		if (pub->expires > 0 && pub->expires < now) {
			ao2_unlink(publications, pub);
			removed++;
		}
		ao2_ref(pub, -1);
	}
	ao2_iterator_destroy(&iter);
	
	if (removed > 0) {
		ast_debug(2, "Cleaned up %d expired publication%s\n",
			removed, removed != 1 ? "s" : "");
	}
}