/*
 * GABpbx -- An open source telephony toolkit.
 *
 * Copyright (C) 2024, GABpbx Development Team
 *
 * sip_auth_cache.c - Authentication cache for Sofia-SIP
 */

#include "gabpbx.h"
#include "gabpbx/logger.h"
#include "gabpbx/strings.h"
#include "gabpbx/astobj2.h"
#include "gabpbx/time.h"

#include "include/sip_sofia.h"

/* Global auth cache container */
struct ao2_container *auth_cache = NULL;

/* Hash function for auth cache entries - based on key */
static int auth_cache_hash_fn(const void *obj, const int flags)
{
	const struct sip_auth_cache_entry *entry;
	const char *key;
	
	switch (flags & OBJ_SEARCH_MASK) {
	case OBJ_SEARCH_KEY:
		key = obj;
		break;
	case OBJ_SEARCH_OBJECT:
		entry = obj;
		key = entry->key;
		break;
	default:
		ast_assert(0);
		return 0;
	}
	
	return ast_str_hash(key);
}

/* Comparison function for auth cache entries */
static int auth_cache_cmp_fn(void *obj, void *arg, int flags)
{
	const struct sip_auth_cache_entry *object_left = obj;
	const struct sip_auth_cache_entry *object_right = arg;
	const char *right_key = arg;
	int cmp;
	
	switch (flags & OBJ_SEARCH_MASK) {
	case OBJ_SEARCH_OBJECT:
		right_key = object_right->key;
		/* Fall through */
	case OBJ_SEARCH_KEY:
		cmp = strcmp(object_left->key, right_key);
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

/* Destructor for auth cache entries */
static void auth_cache_entry_destructor(void *obj)
{
	/* Nothing special to clean up */
}

/* Initialize the auth cache system */
int sip_auth_cache_init(void)
{
	if (auth_cache) {
		ast_log(LOG_WARNING, "Auth cache already initialized\n");
		return 0;
	}
	
	auth_cache = ao2_container_alloc_hash(AO2_ALLOC_OPT_LOCK_MUTEX, 0,
		SOFIA_AUTH_CACHE_SIZE, auth_cache_hash_fn, NULL, auth_cache_cmp_fn);
	
	if (!auth_cache) {
		ast_log(LOG_ERROR, "Failed to create auth cache hash table\n");
		return -1;
	}
	
	ast_log(LOG_NOTICE, "Authentication cache initialized with %d buckets\n", SOFIA_AUTH_CACHE_SIZE);
	return 0;
}

/* Destroy the auth cache system */
void sip_auth_cache_destroy(void)
{
	if (auth_cache) {
		ao2_ref(auth_cache, -1);
		auth_cache = NULL;
		ast_log(LOG_NOTICE, "Authentication cache destroyed\n");
	}
}

/* Build cache key from auth parameters */
static void build_cache_key(char *key, size_t key_size, const char *username, 
                           const char *realm, const char *nonce, const char *uri)
{
	snprintf(key, key_size, "%s:%s:%s:%s", username, realm, nonce, uri);
}

/* Check if auth response is in cache and valid */
int sip_auth_cache_check(const char *username, const char *realm, const char *nonce, 
                        const char *uri, const char *response, const char *ip_addr)
{
	struct sip_auth_cache_entry *entry;
	char key[256];
	time_t now = time(NULL);
	int valid = 0;
	
	if (!auth_cache || !username || !realm || !nonce || !uri || !response) {
		return 0;
	}
	
	/* Build lookup key */
	build_cache_key(key, sizeof(key), username, realm, nonce, uri);
	
	/* Fast O(1) lookup */
	entry = ao2_find(auth_cache, key, OBJ_SEARCH_KEY);
	if (!entry) {
		ast_log(LOG_DEBUG, "Auth cache miss for %s\n", username);
		return 0;  /* Not in cache */
	}
	
	/* Check if cached entry is still valid */
	if (entry->expires > now) {
		/* Check response matches */
		if (!strcmp(entry->response, response)) {
			/* Optional: verify IP address matches */
			if (!ip_addr || !entry->ip_addr[0] || !strcmp(entry->ip_addr, ip_addr)) {
				valid = 1;
				ast_log(LOG_DEBUG, "Auth cache hit for %s (expires in %ld seconds)\n", 
					username, entry->expires - now);
			} else {
				ast_log(LOG_DEBUG, "Auth cache IP mismatch for %s (cached: %s, current: %s)\n",
					username, entry->ip_addr, ip_addr);
			}
		} else {
			ast_log(LOG_DEBUG, "Auth cache response mismatch for %s\n", username);
		}
	} else {
		/* Entry expired, remove it */
		ast_log(LOG_DEBUG, "Auth cache entry expired for %s\n", username);
		ao2_unlink(auth_cache, entry);
	}
	
	ao2_ref(entry, -1);
	return valid;
}

/* Store successful auth in cache */
void sip_auth_cache_store(const char *username, const char *realm, const char *nonce,
                         const char *uri, const char *response, const char *ip_addr, int ttl)
{
	struct sip_auth_cache_entry *entry;
	char key[256];
	time_t now = time(NULL);
	
	if (!auth_cache || !username || !realm || !nonce || !uri || !response) {
		return;
	}
	
	/* Use default TTL if not specified */
	if (ttl <= 0) {
		ttl = SOFIA_AUTH_CACHE_TTL;
	}
	
	/* Build cache key */
	build_cache_key(key, sizeof(key), username, realm, nonce, uri);
	
	/* Look for existing entry */
	entry = ao2_find(auth_cache, key, OBJ_SEARCH_KEY);
	if (entry) {
		/* Update existing entry */
		ao2_lock(entry);
		ast_copy_string(entry->response, response, sizeof(entry->response));
		if (ip_addr) {
			ast_copy_string(entry->ip_addr, ip_addr, sizeof(entry->ip_addr));
		}
		entry->expires = now + ttl;
		ao2_unlock(entry);
		ast_log(LOG_DEBUG, "Updated auth cache for %s (TTL: %d seconds)\n", username, ttl);
		ao2_ref(entry, -1);
	} else {
		/* Create new entry */
		entry = ao2_alloc(sizeof(*entry), auth_cache_entry_destructor);
		if (!entry) {
			ast_log(LOG_ERROR, "Failed to allocate auth cache entry\n");
			return;
		}
		
		ast_copy_string(entry->key, key, sizeof(entry->key));
		ast_copy_string(entry->response, response, sizeof(entry->response));
		if (ip_addr) {
			ast_copy_string(entry->ip_addr, ip_addr, sizeof(entry->ip_addr));
		}
		entry->expires = now + ttl;
		
		ao2_link(auth_cache, entry);
		ao2_ref(entry, -1);
		
		ast_log(LOG_DEBUG, "Cached auth for %s (TTL: %d seconds)\n", username, ttl);
	}
}

/* Clean up expired entries */
void sip_auth_cache_cleanup(void)
{
	struct ao2_iterator iter;
	struct sip_auth_cache_entry *entry;
	time_t now = time(NULL);
	int removed = 0;
	
	if (!auth_cache) {
		return;
	}
	
	iter = ao2_iterator_init(auth_cache, 0);
	while ((entry = ao2_iterator_next(&iter))) {
		if (entry->expires <= now) {
			ao2_unlink(auth_cache, entry);
			removed++;
		}
		ao2_ref(entry, -1);
	}
	ao2_iterator_destroy(&iter);
	
	if (removed > 0) {
		ast_log(LOG_DEBUG, "Cleaned up %d expired auth cache entries\n", removed);
	}
}