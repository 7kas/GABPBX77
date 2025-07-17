/*
 * GABpbx -- An open source telephony toolkit.
 *
 * Copyright (C) 2024, GABpbx Development Team
 *
 * sip_blacklist.c - IP Blacklist management for Sofia-SIP
 */

#include "gabpbx.h"
#include "gabpbx/logger.h"
#include "gabpbx/strings.h"
#include "gabpbx/astobj2.h"
#include "gabpbx/time.h"
#include "gabpbx/cli.h"

#include <arpa/inet.h>
#include <sys/socket.h>

#include "include/sip_sofia.h"

/* Global blacklist container */
struct ao2_container *blacklist = NULL;

/* Hash function for blacklist entries - based on IP address */
static int blacklist_hash_fn(const void *obj, const int flags)
{
	const struct sip_blacklist_entry *entry;
	const char *key;
	
	switch (flags & OBJ_SEARCH_MASK) {
	case OBJ_SEARCH_KEY:
		key = obj;
		break;
	case OBJ_SEARCH_OBJECT:
		entry = obj;
		key = entry->ip_addr;
		break;
	default:
		ast_assert(0);
		return 0;
	}
	
	return ast_str_hash(key);
}

/* Comparison function for blacklist entries */
static int blacklist_cmp_fn(void *obj, void *arg, int flags)
{
	const struct sip_blacklist_entry *object_left = obj;
	const struct sip_blacklist_entry *object_right = arg;
	const char *right_key = arg;
	int cmp;
	
	switch (flags & OBJ_SEARCH_MASK) {
	case OBJ_SEARCH_OBJECT:
		right_key = object_right->ip_addr;
		/* Fall through */
	case OBJ_SEARCH_KEY:
		cmp = strcmp(object_left->ip_addr, right_key);
		break;
	case OBJ_SEARCH_PARTIAL_KEY:
		/* Not supported by this container. */
		ast_assert(0);
		return 0;
	default:
		cmp = 0;
		break;
	}
	
	return cmp ? 0 : CMP_MATCH;
}

/* Destructor for blacklist entries */
static void blacklist_entry_destructor(void *obj)
{
	/* Nothing special to clean up */
}

/* Initialize the blacklist system */
int sip_blacklist_init(void)
{
	if (blacklist) {
		ast_log(LOG_WARNING, "Blacklist already initialized\n");
		return 0;
	}
	
	blacklist = ao2_container_alloc_hash(AO2_ALLOC_OPT_LOCK_MUTEX, 0,
		SOFIA_BLACKLIST_SIZE, blacklist_hash_fn, NULL, blacklist_cmp_fn);
	
	if (!blacklist) {
		ast_log(LOG_ERROR, "Failed to create blacklist hash table\n");
		return -1;
	}
	
	ast_log(LOG_NOTICE, "IP blacklist initialized with %d buckets\n", SOFIA_BLACKLIST_SIZE);
	return 0;
}

/* Destroy the blacklist system */
void sip_blacklist_destroy(void)
{
	if (blacklist) {
		ao2_ref(blacklist, -1);
		blacklist = NULL;
		ast_log(LOG_NOTICE, "IP blacklist destroyed\n");
	}
}

/* Check if an IP is blacklisted - FAST O(1) check for every packet */
int sip_blacklist_check(const char *ip_addr)
{
	struct sip_blacklist_entry *entry;
	time_t now = time(NULL);
	int is_banned = 0;
	
	if (!blacklist || !ip_addr) {
		return 0;
	}
	
	/* Fast O(1) lookup */
	entry = ao2_find(blacklist, ip_addr, OBJ_SEARCH_KEY);
	if (!entry) {
		return 0;  /* Not in blacklist */
	}
	
	/* Check the is_banned flag */
	if (entry->is_banned) {
		/* Check if ban is still valid */
		if (entry->banned_until == 0) {
			/* Permanent ban */
			is_banned = 1;
			ast_log(LOG_DEBUG, "IP %s is permanently blacklisted\n", ip_addr);
		} else if (entry->banned_until > now) {
			/* Temporary ban still active */
			is_banned = 1;
			char time_str[64];
			ctime_r(&entry->banned_until, time_str);
			time_str[strlen(time_str)-1] = '\0'; /* Remove newline */
			ast_log(LOG_DEBUG, "IP %s is blacklisted until %s\n", 
				ip_addr, time_str);
		} else {
			/* Ban expired, clear the flag */
			entry->is_banned = 0;
			entry->banned_until = 0;
			ast_log(LOG_NOTICE, "Ban expired for IP %s, clearing ban flag\n", ip_addr);
		}
	}
	
	ao2_ref(entry, -1);
	return is_banned;
}

/* Reset failure counter for an IP (called on successful auth) */
void sip_blacklist_reset_failures(const char *ip_addr)
{
	struct sip_blacklist_entry *entry;
	
	if (!blacklist || !ip_addr) {
		return;
	}
	
	/* Look up entry */
	entry = ao2_find(blacklist, ip_addr, OBJ_SEARCH_KEY);
	if (entry) {
		/* Reset failure count but keep the entry for tracking */
		if (entry->fail_count > 0) {
			ast_log(LOG_DEBUG, "Resetting failure count for IP %s (was %d)\n", 
				ip_addr, entry->fail_count);
			entry->fail_count = 0;
			entry->last_attempt = time(NULL);
			ast_copy_string(entry->reason, "Auth success - counter reset", sizeof(entry->reason));
		}
		ao2_ref(entry, -1);
	}
}

/* Add an authentication failure for an IP */
void sip_blacklist_add_failure(const char *ip_addr, const char *username, const char *reason)
{
	struct sip_blacklist_entry *entry;
	struct sip_profile *profile;
	int threshold = SOFIA_DEFAULT_FAIL_THRESHOLD;
	int ban_duration = SOFIA_DEFAULT_BAN_TIME;
	time_t now = time(NULL);
	
	if (!blacklist || !ip_addr) {
		return;
	}
	
	/* Get default threshold from first profile with blacklist enabled */
	AST_RWLIST_RDLOCK(&profiles);
	AST_RWLIST_TRAVERSE(&profiles, profile, list) {
		if (profile->blacklist_enabled) {
			threshold = profile->blacklist_threshold;
			ban_duration = profile->blacklist_duration;
			break;
		}
	}
	AST_RWLIST_UNLOCK(&profiles);
	
	/* Look up or create entry */
	entry = ao2_find(blacklist, ip_addr, OBJ_SEARCH_KEY);
	if (!entry) {
		/* Create new entry */
		entry = ao2_alloc(sizeof(*entry), blacklist_entry_destructor);
		if (!entry) {
			ast_log(LOG_ERROR, "Failed to allocate blacklist entry\n");
			return;
		}
		ast_copy_string(entry->ip_addr, ip_addr, sizeof(entry->ip_addr));
		entry->fail_count = 0;
		ao2_link(blacklist, entry);
	}
	
	/* Update failure info */
	entry->fail_count++;
	entry->last_attempt = now;
	if (username) {
		ast_copy_string(entry->last_user, username, sizeof(entry->last_user));
	}
	if (reason) {
		ast_copy_string(entry->reason, reason, sizeof(entry->reason));
	}
	
	ast_log(LOG_WARNING, "Auth failure #%d from IP %s (user: %s, reason: %s)\n",
		entry->fail_count, ip_addr, username ? username : "unknown", reason ? reason : "none");
	
	/* Check if we should ban this IP */
	if (entry->fail_count >= threshold && !entry->is_banned) {
		/* Set the ban flag */
		entry->is_banned = 1;
		
		if (ban_duration == 0) {
			entry->banned_until = 0; /* Permanent ban */
			ast_log(LOG_NOTICE, "IP %s permanently banned after %d failures\n",
				ip_addr, entry->fail_count);
		} else {
			entry->banned_until = now + ban_duration;
			ast_log(LOG_NOTICE, "IP %s banned for %d seconds after %d failures\n",
				ip_addr, ban_duration, entry->fail_count);
		}
		
		/* TODO: Send security event */
	}
	
	ao2_ref(entry, -1);
}

/* Manually ban an IP */
void sip_blacklist_ban(const char *ip_addr, int duration, const char *reason)
{
	struct sip_blacklist_entry *entry;
	time_t now = time(NULL);
	struct sockaddr_in sa;
	struct sockaddr_in6 sa6;
	
	if (!blacklist || !ip_addr) {
		return;
	}
	
	/* Validate IP address */
	if (inet_pton(AF_INET, ip_addr, &(sa.sin_addr)) != 1 &&
	    inet_pton(AF_INET6, ip_addr, &(sa6.sin6_addr)) != 1) {
		ast_log(LOG_WARNING, "Invalid IP address for blacklist: %s\n", ip_addr);
		return;
	}
	
	/* Look up or create entry */
	entry = ao2_find(blacklist, ip_addr, OBJ_SEARCH_KEY);
	if (!entry) {
		/* Create new entry */
		entry = ao2_alloc(sizeof(*entry), blacklist_entry_destructor);
		if (!entry) {
			ast_log(LOG_ERROR, "Failed to allocate blacklist entry\n");
			return;
		}
		ast_copy_string(entry->ip_addr, ip_addr, sizeof(entry->ip_addr));
		ao2_link(blacklist, entry);
	}
	
	/* Set ban - duration 0 means permanent ban */
	entry->is_banned = 1;  /* Set the ban flag */
	
	if (duration == 0) {
		entry->banned_until = 0; /* Special value for permanent ban */
		ast_log(LOG_NOTICE, "IP %s permanently banned (reason: %s)\n",
			ip_addr, reason ? reason : "manual ban");
	} else {
		entry->banned_until = now + duration;
		ast_log(LOG_NOTICE, "IP %s manually banned for %d seconds (reason: %s)\n",
			ip_addr, duration, reason ? reason : "manual ban");
	}
	
	if (reason) {
		ast_copy_string(entry->reason, reason, sizeof(entry->reason));
	}
	
	ao2_ref(entry, -1);
}

/* Unban an IP */
void sip_blacklist_unban(const char *ip_addr)
{
	struct sip_blacklist_entry *entry;
	
	if (!blacklist || !ip_addr) {
		return;
	}
	
	entry = ao2_find(blacklist, ip_addr, OBJ_SEARCH_KEY);
	if (entry) {
		ao2_unlink(blacklist, entry);
		ao2_ref(entry, -1);
		ast_log(LOG_NOTICE, "IP %s removed from blacklist\n", ip_addr);
	}
}

/* Clean up expired entries */
void sip_blacklist_cleanup(void)
{
	struct ao2_iterator iter;
	struct sip_blacklist_entry *entry;
	time_t now = time(NULL);
	int removed = 0;
	
	if (!blacklist) {
		return;
	}
	
	iter = ao2_iterator_init(blacklist, 0);
	while ((entry = ao2_iterator_next(&iter))) {
		/* Check if ban has expired */
		if (entry->is_banned && entry->banned_until > 0 && entry->banned_until <= now) {
			/* Clear the ban flag for expired bans */
			entry->is_banned = 0;
			ast_log(LOG_DEBUG, "Clearing expired ban for IP %s\n", entry->ip_addr);
		}
		
		/* Remove entries with no failures and no active ban */
		if (!entry->is_banned && entry->fail_count == 0) {
			ao2_unlink(blacklist, entry);
			removed++;
		}
		ao2_ref(entry, -1);
	}
	ao2_iterator_destroy(&iter);
	
	if (removed > 0) {
		ast_log(LOG_DEBUG, "Cleaned up %d expired blacklist entries\n", removed);
	}
}