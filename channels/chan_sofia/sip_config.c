/*
 * GABpbx -- An open source telephony toolkit.
 *
 * Copyright (C) 2024, GABpbx Development Team
 *
 * sip_config.c - Configuration handling for Sofia-SIP
 */

#include "gabpbx.h"
#include "gabpbx/config.h"
#include "gabpbx/logger.h"
#include "gabpbx/strings.h"
#include "gabpbx/utils.h"

#include "include/sip_sofia.h"
#include "gabpbx/astobj2.h"

/* Global lists */
struct sip_profile_list profiles = AST_RWLIST_HEAD_INIT_VALUE;
struct ao2_container *endpoints = NULL;  /* Hash table for endpoints */
struct sip_trunk_list trunks = AST_RWLIST_HEAD_INIT_VALUE;

/* Hash function for endpoints - based on name */
static int endpoint_hash_fn(const void *obj, const int flags)
{
	const struct sip_endpoint *endpoint;
	const char *key;
	
	switch (flags & OBJ_SEARCH_MASK) {
	case OBJ_SEARCH_KEY:
		key = obj;
		break;
	case OBJ_SEARCH_OBJECT:
		endpoint = obj;
		key = endpoint->name;
		break;
	default:
		ast_assert(0);
		return 0;
	}
	
	return ast_str_hash(key);
}

/* Comparison function for endpoints */
static int endpoint_cmp_fn(void *obj, void *arg, int flags)
{
	const struct sip_endpoint *object_left = obj;
	const struct sip_endpoint *object_right = arg;
	const char *right_key = arg;
	int cmp;
	
	switch (flags & OBJ_SEARCH_MASK) {
	case OBJ_SEARCH_OBJECT:
		right_key = object_right->name;
		/* Fall through */
	case OBJ_SEARCH_KEY:
		cmp = strcasecmp(object_left->name, right_key);
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

struct sip_profile *sip_profile_find(const char *name)
{
	struct sip_profile *profile;
	
	AST_RWLIST_RDLOCK(&profiles);
	AST_RWLIST_TRAVERSE(&profiles, profile, list) {
		if (!strcasecmp(profile->name, name)) {
			break;
		}
	}
	AST_RWLIST_UNLOCK(&profiles);
	
	return profile;
}

struct sip_endpoint *sip_endpoint_find(struct sip_profile *profile, const char *name)
{
	struct sip_endpoint *endpoint;
	struct ao2_iterator iter;
	
	if (!endpoints || !name) {
		return NULL;
	}
	
	/* If profile is specified, we need to iterate to check profile match */
	if (profile) {
		iter = ao2_iterator_init(endpoints, 0);
		while ((endpoint = ao2_iterator_next(&iter))) {
			if (endpoint->profile == profile && !strcasecmp(endpoint->name, name)) {
				ao2_iterator_destroy(&iter);
				/* Return with ref count increased - caller must ao2_ref -1 */
				return endpoint;
			}
			ao2_ref(endpoint, -1);
		}
		ao2_iterator_destroy(&iter);
		return NULL;
	}
	
	/* No profile specified - direct lookup by name */
	endpoint = ao2_find(endpoints, name, OBJ_SEARCH_KEY);
	return endpoint; /* Returns with ref count increased if found */
}

struct sip_trunk *sip_trunk_find(struct sip_profile *profile, const char *host)
{
	struct sip_trunk *trunk;
	
	AST_RWLIST_RDLOCK(&trunks);
	AST_RWLIST_TRAVERSE(&trunks, trunk, list) {
		if (trunk->profile == profile && !strcasecmp(trunk->host, host)) {
			break;
		}
	}
	AST_RWLIST_UNLOCK(&trunks);
	
	return trunk;
}

static struct sip_profile *profile_alloc(const char *name)
{
	struct sip_profile *profile;
	
	profile = ast_calloc(1, sizeof(*profile));
	if (!profile) {
		return NULL;
	}
	
	ast_copy_string(profile->name, name, sizeof(profile->name));
	ast_mutex_init(&profile->lock);
	
	/* Defaults - Changed to port 60000 for security */
	profile->bindport = 60000;
	strcpy(profile->bindip, "0.0.0.0");
	strcpy(profile->context, "default");
	profile->max_contacts_global = 3; /* Default: 3 contacts per peer */
	profile->registration_timeout = 3600;
	profile->registration_refresh_percent = 90; /* Default: refresh at 90% of expiry */
	/* profile->auth_registrations = 1; -- Removed: auth per endpoint */
	profile->enable_options = 1;
	profile->enable_messaging = 1;
	profile->ring_all_except_inuse_global = 0; /* Default: ring all devices */
	
	/* Transport defaults */
	strcpy(profile->transport_protocol, "UDP,TCP"); /* Default: both UDP and TCP */
	
	/* Blacklist defaults */
	profile->blacklist_enabled = 1; /* Enabled by default for security */
	profile->blacklist_threshold = SOFIA_DEFAULT_FAIL_THRESHOLD;
	profile->blacklist_duration = SOFIA_DEFAULT_BAN_TIME;
	
	/* Auth cache defaults */
	profile->auth_cache_enabled = 1; /* Enabled by default for performance */
	profile->auth_cache_ttl = SOFIA_AUTH_CACHE_TTL;
	profile->nonce_ttl = 30; /* Default: 30 seconds for nonce reuse */
	
	/* Event queue defaults */
	profile->event_queue_size = SOFIA_EVENT_QUEUE_SIZE; /* Default: 1000 events */
	profile->event_queue_workers = 0; /* 0 = auto-calculate based on CPU count */
	
	/* Create scheduler context */
	profile->sched = ast_sched_context_create();
	if (!profile->sched) {
		ast_log(LOG_ERROR, "Failed to create scheduler context for profile %s\n", name);
	}
	
	return profile;
}

static void profile_destroy(struct sip_profile *profile)
{
	if (!profile) {
		return;
	}
	
	if (profile->sched) {
		ast_sched_context_destroy(profile->sched);
		profile->sched = NULL;
	}
	
	ast_mutex_destroy(&profile->lock);
	ast_free(profile);
}

/* Destructor for endpoint objects */
static void endpoint_destructor(void *obj)
{
	/* Nothing special to clean up for now */
}

static struct sip_endpoint *endpoint_alloc(const char *name)
{
	struct sip_endpoint *endpoint;
	
	endpoint = ao2_alloc(sizeof(*endpoint), endpoint_destructor);
	if (!endpoint) {
		return NULL;
	}
	
	ast_copy_string(endpoint->name, name, sizeof(endpoint->name));
	strcpy(endpoint->context, "default");
	endpoint->max_contacts = 0; /* 0 means use profile default */
	endpoint->can_send_message = 1;
	endpoint->send_options = 1;
	endpoint->num_useragents = 0;
	endpoint->require_useragent = 0;
	
	return endpoint;
}

static void endpoint_destroy(struct sip_endpoint *endpoint)
{
	if (!endpoint) {
		return;
	}
	
	/* Just decrease reference count - ao2 will handle destruction */
	ao2_ref(endpoint, -1);
}

static struct sip_trunk *trunk_alloc(const char *name)
{
	struct sip_trunk *trunk;
	
	trunk = ast_calloc(1, sizeof(*trunk));
	if (!trunk) {
		return NULL;
	}
	
	ast_copy_string(trunk->name, name, sizeof(trunk->name));
	strcpy(trunk->context, "default");
	trunk->port = 6000;
	trunk->monitor = 1;
	trunk->monitor_frequency = 60;
	
	return trunk;
}

static void trunk_destroy(struct sip_trunk *trunk)
{
	if (!trunk) {
		return;
	}
	
	ast_free(trunk);
}

static void parse_profile(struct ast_config *cfg, const char *cat)
{
	struct sip_profile *profile;
	struct sip_profile *existing;
	struct ast_variable *var;
	
	/* Check if profile already exists */
	existing = sip_profile_find(cat);
	if (existing) {
		ast_log(LOG_WARNING, "Profile '%s' already exists, skipping duplicate\n", cat);
		return;
	}
	
	profile = profile_alloc(cat);
	if (!profile) {
		ast_log(LOG_ERROR, "Failed to allocate profile '%s'\n", cat);
		return;
	}
	
	var = ast_variable_browse(cfg, cat);
	while (var) {
		if (!strcasecmp(var->name, "bindip")) {
			ast_copy_string(profile->bindip, var->value, sizeof(profile->bindip));
		} else if (!strcasecmp(var->name, "bindport")) {
			profile->bindport = atoi(var->value);
		} else if (!strcasecmp(var->name, "context")) {
			ast_copy_string(profile->context, var->value, sizeof(profile->context));
		} else if (!strcasecmp(var->name, "enabled")) {
			profile->enabled = ast_true(var->value);
		/* Removed auth_calls - auth now per endpoint
		} else if (!strcasecmp(var->name, "auth_calls")) {
			profile->auth_calls = ast_true(var->value); */
		/* Removed auth_registrations - auth now per endpoint 
		} else if (!strcasecmp(var->name, "auth_registrations") || !strcasecmp(var->name, "enable_registrations")) {
			profile->auth_registrations = ast_true(var->value); */
		} else if (!strcasecmp(var->name, "enable_options")) {
			profile->enable_options = ast_true(var->value);
		} else if (!strcasecmp(var->name, "enable_messaging")) {
			profile->enable_messaging = ast_true(var->value);
		} else if (!strcasecmp(var->name, "enable_presence")) {
			profile->enable_presence = ast_true(var->value);
		} else if (!strcasecmp(var->name, "max_registrations") || !strcasecmp(var->name, "max_contacts")) {
			profile->max_contacts_global = atoi(var->value);
			if (profile->max_contacts_global < 1) {
				profile->max_contacts_global = 1;
			}
		} else if (!strcasecmp(var->name, "registration_timeout")) {
			profile->registration_timeout = atoi(var->value);
		} else if (!strcasecmp(var->name, "registration_refresh_percent")) {
			profile->registration_refresh_percent = atoi(var->value);
			if (profile->registration_refresh_percent < 50) {
				profile->registration_refresh_percent = 50; /* Minimum 50% */
			} else if (profile->registration_refresh_percent > 95) {
				profile->registration_refresh_percent = 95; /* Maximum 95% */
			}
		} else if (!strcasecmp(var->name, "ring_all_except_inuse")) {
			profile->ring_all_except_inuse_global = ast_true(var->value);
		} else if (!strcasecmp(var->name, "blacklist_enabled")) {
			profile->blacklist_enabled = ast_true(var->value);
		} else if (!strcasecmp(var->name, "blacklist_threshold")) {
			profile->blacklist_threshold = atoi(var->value);
			if (profile->blacklist_threshold < 1) {
				profile->blacklist_threshold = SOFIA_DEFAULT_FAIL_THRESHOLD;
			}
		} else if (!strcasecmp(var->name, "blacklist_duration")) {
			profile->blacklist_duration = atoi(var->value);
			if (profile->blacklist_duration < 60) {
				profile->blacklist_duration = SOFIA_DEFAULT_BAN_TIME;
			}
		} else if (!strcasecmp(var->name, "auth_cache_enabled")) {
			profile->auth_cache_enabled = ast_true(var->value);
		} else if (!strcasecmp(var->name, "auth_cache_ttl")) {
			profile->auth_cache_ttl = atoi(var->value);
			if (profile->auth_cache_ttl < 60) {
				profile->auth_cache_ttl = 60; /* Minimum 60 seconds */
			} else if (profile->auth_cache_ttl > 3600) {
				profile->auth_cache_ttl = 3600; /* Maximum 1 hour */
			}
		} else if (!strcasecmp(var->name, "nonce_ttl")) {
			profile->nonce_ttl = atoi(var->value);
			if (profile->nonce_ttl < 10) {
				profile->nonce_ttl = 10; /* Minimum 10 seconds */
			} else if (profile->nonce_ttl > 300) {
				profile->nonce_ttl = 300; /* Maximum 5 minutes */
			}
		} else if (!strcasecmp(var->name, "session_timers")) {
			profile->session_timers_enabled = ast_true(var->value);
		} else if (!strcasecmp(var->name, "session_min_se")) {
			profile->session_min_se = atoi(var->value);
			if (profile->session_min_se < 90) {
				profile->session_min_se = 90; /* RFC 4028 absolute minimum */
			}
		} else if (!strcasecmp(var->name, "session_default_se")) {
			profile->session_default_se = atoi(var->value);
			if (profile->session_default_se < profile->session_min_se) {
				profile->session_default_se = profile->session_min_se;
			}
		} else if (!strcasecmp(var->name, "event_queue_size")) {
			profile->event_queue_size = atoi(var->value);
			if (profile->event_queue_size < 100) {
				ast_log(LOG_WARNING, "event_queue_size too small (%d), using minimum 100\n", 
					profile->event_queue_size);
				profile->event_queue_size = 100;
			} else if (profile->event_queue_size > 10000) {
				ast_log(LOG_WARNING, "event_queue_size too large (%d), using maximum 10000\n", 
					profile->event_queue_size);
				profile->event_queue_size = 10000;
			}
		} else if (!strcasecmp(var->name, "event_queue_workers")) {
			profile->event_queue_workers = atoi(var->value);
			if (profile->event_queue_workers < 1) {
				ast_log(LOG_WARNING, "event_queue_workers too small (%d), using minimum 1\n", 
					profile->event_queue_workers);
				profile->event_queue_workers = 1;
			} else if (profile->event_queue_workers > 64) {
				ast_log(LOG_WARNING, "event_queue_workers too large (%d), using maximum 64\n", 
					profile->event_queue_workers);
				profile->event_queue_workers = 64;
			}
		} else if (!strcasecmp(var->name, "nat") || !strcasecmp(var->name, "nat_mode")) {
			profile->nat_mode = ast_true(var->value);
		} else if (!strcasecmp(var->name, "externip")) {
			ast_copy_string(profile->externip, var->value, sizeof(profile->externip));
		} else if (!strcasecmp(var->name, "localnet")) {
			/* TODO: Support multiple localnet definitions */
			ast_copy_string(profile->localnet, var->value, sizeof(profile->localnet));
		} else if (!strcasecmp(var->name, "transport_protocol") || !strcasecmp(var->name, "transport")) {
			/* Parse transport protocol(s) - only UDP and TCP for now */
			char *protocols = ast_strdupa(var->value);
			char *protocol;
			char valid_transports[32] = "";
			
			while ((protocol = strsep(&protocols, ","))) {
				protocol = ast_strip(protocol);
				
				if (!strcasecmp(protocol, "UDP") || !strcasecmp(protocol, "TCP")) {
					if (strlen(valid_transports) > 0) {
						strncat(valid_transports, ",", sizeof(valid_transports) - strlen(valid_transports) - 1);
					}
					strncat(valid_transports, protocol, sizeof(valid_transports) - strlen(valid_transports) - 1);
				} else {
					ast_log(LOG_WARNING, "Invalid transport protocol '%s' in profile '%s' (only UDP and TCP supported)\n", 
						protocol, profile->name);
				}
			}
			
			if (strlen(valid_transports) > 0) {
				ast_copy_string(profile->transport_protocol, valid_transports, 
					sizeof(profile->transport_protocol));
			}
		}
		var = var->next;
	}
	
	if (profile->enabled) {
		/* Check for duplicate IP:port combinations */
		struct sip_profile *existing;
		int duplicate_found = 0;
		
		AST_RWLIST_RDLOCK(&profiles);
		AST_RWLIST_TRAVERSE(&profiles, existing, list) {
			if (!strcasecmp(existing->bindip, profile->bindip) && 
			    existing->bindport == profile->bindport) {
				ast_log(LOG_ERROR, "Profile '%s' conflicts with profile '%s' on %s:%d\n",
					profile->name, existing->name, profile->bindip, profile->bindport);
				duplicate_found = 1;
				break;
			}
			/* Check TLS port if enabled */
			if (strstr(profile->transport_protocol, "TLS")) {
				int tls_port = profile->tls_bindport ? profile->tls_bindport : profile->bindport + 1;
				int existing_tls_port = existing->tls_bindport ? existing->tls_bindport : existing->bindport + 1;
				
				if (strstr(existing->transport_protocol, "TLS") && 
				    !strcasecmp(existing->bindip, profile->bindip) && 
				    existing_tls_port == tls_port) {
					ast_log(LOG_ERROR, "Profile '%s' TLS conflicts with profile '%s' on %s:%d\n",
						profile->name, existing->name, profile->bindip, tls_port);
					duplicate_found = 1;
					break;
				}
			}
		}
		AST_RWLIST_UNLOCK(&profiles);
		
		if (duplicate_found) {
			profile_destroy(profile);
			return;
		}
		
		/* Verify at least one transport is enabled */
		if (ast_strlen_zero(profile->transport_protocol)) {
			ast_log(LOG_ERROR, "Profile '%s' has no transports enabled\n", profile->name);
			profile_destroy(profile);
			return;
		}
		
		AST_RWLIST_WRLOCK(&profiles);
		AST_RWLIST_INSERT_TAIL(&profiles, profile, list);
		AST_RWLIST_UNLOCK(&profiles);
		
		ast_log(LOG_NOTICE, "Loaded profile '%s' on %s:%d (Transport: %s)\n", 
			profile->name, profile->bindip, profile->bindport,
			profile->transport_protocol);
	} else {
		profile_destroy(profile);
	}
}

static void parse_endpoint(struct ast_config *cfg, const char *cat)
{
	struct sip_endpoint *endpoint;
	struct ast_variable *var;
	const char *profile_name = NULL;
	
	endpoint = endpoint_alloc(cat);
	if (!endpoint) {
		ast_log(LOG_ERROR, "Failed to allocate endpoint '%s'\n", cat);
		return;
	}
	
	var = ast_variable_browse(cfg, cat);
	while (var) {
		if (!strcasecmp(var->name, "profile")) {
			profile_name = var->value;
		} else if (!strcasecmp(var->name, "username")) {
			ast_copy_string(endpoint->username, var->value, sizeof(endpoint->username));
		} else if (!strcasecmp(var->name, "secret")) {
			ast_copy_string(endpoint->secret, var->value, sizeof(endpoint->secret));
		} else if (!strcasecmp(var->name, "context")) {
			ast_copy_string(endpoint->context, var->value, sizeof(endpoint->context));
		} else if (!strcasecmp(var->name, "auth_type")) {
			if (!strcasecmp(var->value, "ip")) {
				endpoint->auth_type = AUTH_TYPE_IP;
			} else if (!strcasecmp(var->value, "register")) {
				endpoint->auth_type = AUTH_TYPE_REGISTER;
			} else {
				ast_log(LOG_WARNING, "Unknown auth_type '%s' for endpoint '%s', using 'register'\n",
					var->value, cat);
				endpoint->auth_type = AUTH_TYPE_REGISTER;
			}
		} else if (!strcasecmp(var->name, "host")) {
			ast_copy_string(endpoint->host, var->value, sizeof(endpoint->host));
		} else if (!strcasecmp(var->name, "port")) {
			endpoint->port = atoi(var->value);
			if (endpoint->port < 0 || endpoint->port > 65535) {
				endpoint->port = 0; /* 0 means any port */
			}
		} else if (!strcasecmp(var->name, "max_registrations") || !strcasecmp(var->name, "max_contacts")) {
			endpoint->max_contacts = atoi(var->value);
			if (endpoint->max_contacts < 0) {
				endpoint->max_contacts = 0; /* 0 means use profile default */
			} else if (endpoint->max_contacts > SOFIA_MAX_REG_PER_USER) {
				endpoint->max_contacts = SOFIA_MAX_REG_PER_USER;
			}
		} else if (!strcasecmp(var->name, "ring_all_except_inuse")) {
			endpoint->ring_all_except_inuse = ast_true(var->value);
		} else if (!strcasecmp(var->name, "can_send_message")) {
			endpoint->can_send_message = ast_true(var->value);
		} else if (!strcasecmp(var->name, "can_subscribe")) {
			endpoint->can_subscribe = ast_true(var->value);
		} else if (!strcasecmp(var->name, "send_options")) {
			endpoint->send_options = ast_true(var->value);
		} else if (!strcasecmp(var->name, "require_useragent")) {
			endpoint->require_useragent = ast_true(var->value);
		} else if (!strcasecmp(var->name, "allowed_useragent") || 
		           !strcasecmp(var->name, "allowed_useragents")) {
			/* Support comma-separated User-Agent patterns (up to 3 total) */
			char *patterns = ast_strdupa(var->value);
			char *pattern;
			
			/* Parse comma-separated patterns */
			while ((pattern = strsep(&patterns, ",")) && endpoint->num_useragents < 3) {
				/* Trim whitespace */
				pattern = ast_strip(pattern);
				
				if (!ast_strlen_zero(pattern)) {
					ast_copy_string(endpoint->allowed_useragents[endpoint->num_useragents], 
						pattern, sizeof(endpoint->allowed_useragents[0]));
					endpoint->num_useragents++;
					ast_log(LOG_DEBUG, "Added allowed User-Agent pattern #%d: '%s'\n", 
						endpoint->num_useragents, pattern);
				}
			}
			
			if (pattern && *pattern) {
				ast_log(LOG_WARNING, "Maximum 3 User-Agent patterns allowed - ignoring remaining patterns\n");
			}
		}
		var = var->next;
	}
	
	if (!profile_name) {
		ast_log(LOG_ERROR, "Endpoint '%s' missing profile\n", cat);
		endpoint_destroy(endpoint);
		return;
	}
	
	endpoint->profile = sip_profile_find(profile_name);
	if (!endpoint->profile) {
		ast_log(LOG_ERROR, "Endpoint '%s' references unknown profile '%s'\n", 
			cat, profile_name);
		endpoint_destroy(endpoint);
		return;
	}
	
	/* Add endpoint to hash table */
	ao2_link(endpoints, endpoint);
	
	ast_log(LOG_NOTICE, "Loaded endpoint '%s' with profile '%s' (max_contacts=%d)\n", 
		endpoint->name, profile_name, endpoint->max_contacts);
	
	/* Release our reference - container now holds the only reference */
	ao2_ref(endpoint, -1);
}

static void parse_trunk(struct ast_config *cfg, const char *cat)
{
	struct sip_trunk *trunk;
	struct ast_variable *var;
	const char *profile_name = NULL;
	
	trunk = trunk_alloc(cat);
	if (!trunk) {
		ast_log(LOG_ERROR, "Failed to allocate trunk '%s'\n", cat);
		return;
	}
	
	var = ast_variable_browse(cfg, cat);
	while (var) {
		if (!strcasecmp(var->name, "profile")) {
			profile_name = var->value;
		} else if (!strcasecmp(var->name, "host")) {
			ast_copy_string(trunk->host, var->value, sizeof(trunk->host));
		} else if (!strcasecmp(var->name, "port")) {
			trunk->port = atoi(var->value);
		} else if (!strcasecmp(var->name, "username")) {
			ast_copy_string(trunk->username, var->value, sizeof(trunk->username));
		} else if (!strcasecmp(var->name, "secret")) {
			ast_copy_string(trunk->secret, var->value, sizeof(trunk->secret));
		} else if (!strcasecmp(var->name, "context")) {
			ast_copy_string(trunk->context, var->value, sizeof(trunk->context));
		} else if (!strcasecmp(var->name, "monitor")) {
			trunk->monitor = ast_true(var->value);
		} else if (!strcasecmp(var->name, "monitor_frequency")) {
			trunk->monitor_frequency = atoi(var->value);
			if (trunk->monitor_frequency < 10) {
				trunk->monitor_frequency = 10;
			}
		}
		var = var->next;
	}
	
	if (!profile_name) {
		ast_log(LOG_ERROR, "Trunk '%s' missing profile\n", cat);
		trunk_destroy(trunk);
		return;
	}
	
	if (ast_strlen_zero(trunk->host)) {
		ast_log(LOG_ERROR, "Trunk '%s' missing host\n", cat);
		trunk_destroy(trunk);
		return;
	}
	
	trunk->profile = sip_profile_find(profile_name);
	if (!trunk->profile) {
		ast_log(LOG_ERROR, "Trunk '%s' references unknown profile '%s'\n", 
			cat, profile_name);
		trunk_destroy(trunk);
		return;
	}
	
	AST_RWLIST_WRLOCK(&trunks);
	AST_RWLIST_INSERT_TAIL(&trunks, trunk, list);
	AST_RWLIST_UNLOCK(&trunks);
	
	ast_log(LOG_NOTICE, "Loaded trunk '%s' to %s:%d (monitor=%s)\n", 
		trunk->name, trunk->host, trunk->port, trunk->monitor ? "yes" : "no");
}

int sip_config_load(int reload)
{
	struct ast_config *cfg;
	struct ast_flags config_flags = { reload ? CONFIG_FLAG_FILEUNCHANGED : 0 };
	const char *cat;
	
	ast_log(LOG_NOTICE, "Loading SIP configuration from %s\n", SOFIA_CONFIG);
	
	cfg = ast_config_load(SOFIA_CONFIG, config_flags);
	if (!cfg || cfg == CONFIG_STATUS_FILEINVALID) {
		ast_log(LOG_ERROR, "Unable to load config %s\n", SOFIA_CONFIG);
		return -1;
	} else if (cfg == CONFIG_STATUS_FILEUNCHANGED) {
		ast_log(LOG_NOTICE, "Configuration unchanged\n");
		return 0;
	}
	
	ast_log(LOG_NOTICE, "Configuration loaded successfully\n");
	
	/* Initialize endpoints hash table if not already done */
	if (!endpoints) {
		endpoints = ao2_container_alloc_hash(AO2_ALLOC_OPT_LOCK_MUTEX, 0,
			SOFIA_HASH_SIZE, endpoint_hash_fn, NULL, endpoint_cmp_fn);
		if (!endpoints) {
			ast_log(LOG_ERROR, "Failed to create endpoints hash table\n");
			ast_config_destroy(cfg);
			return -1;
		}
		ast_log(LOG_NOTICE, "Created endpoints hash table with %d buckets\n", SOFIA_HASH_SIZE);
	}
	
	/* Clear existing config if reloading */
	if (reload) {
		struct sip_profile *profile;
		struct sip_trunk *trunk;
		
		ast_log(LOG_NOTICE, "Clearing existing configuration for reload\n");
		
		/* Clear all trunks */
		AST_RWLIST_WRLOCK(&trunks);
		while ((trunk = AST_RWLIST_REMOVE_HEAD(&trunks, list))) {
			trunk_destroy(trunk);
		}
		AST_RWLIST_UNLOCK(&trunks);
		
		/* Clear all endpoints */
		if (endpoints) {
			ao2_callback(endpoints, OBJ_UNLINK | OBJ_NODATA | OBJ_MULTIPLE, NULL, NULL);
		}
		
		/* Clear all profiles - MUST destroy NUA instances first */
		AST_RWLIST_WRLOCK(&profiles);
		while ((profile = AST_RWLIST_REMOVE_HEAD(&profiles, list))) {
			if (profile->nua) {
				ast_log(LOG_NOTICE, "Destroying NUA for profile '%s'\n", profile->name);
				nua_destroy(profile->nua);
				profile->nua = NULL;
			}
			profile_destroy(profile);
		}
		AST_RWLIST_UNLOCK(&profiles);
	}
	
	/* Process all sections */
	cat = ast_category_browse(cfg, NULL);
	while (cat) {
		const char *type = ast_variable_retrieve(cfg, cat, "type");
		
		ast_log(LOG_NOTICE, "Processing config section [%s] type=%s\n", cat, type ? type : "none");
		
		if (!strcasecmp(cat, "general")) {
			/* Process general options */
			ast_log(LOG_NOTICE, "Processing general section\n");
		} else if (type && !strcasecmp(type, "profile")) {
			ast_log(LOG_NOTICE, "Parsing profile: %s\n", cat);
			parse_profile(cfg, cat);
		} else if (type && (!strcasecmp(type, "endpoint") || !strcasecmp(type, "peer"))) {
			ast_log(LOG_NOTICE, "Parsing endpoint: %s\n", cat);
			parse_endpoint(cfg, cat);
		} else if (type && !strcasecmp(type, "trunk")) {
			ast_log(LOG_NOTICE, "Parsing trunk: %s\n", cat);
			parse_trunk(cfg, cat);
		}
		
		cat = ast_category_browse(cfg, cat);
	}
	
	ast_config_destroy(cfg);
	
	ast_log(LOG_NOTICE, "Configuration loading complete. Profiles: %d, Endpoints: %d\n",
		AST_RWLIST_EMPTY(&profiles) ? 0 : 1,
		endpoints ? ao2_container_count(endpoints) : 0);
	
	return 0;
}

void sip_config_destroy(void)
{
	struct sip_profile *profile;
	struct sip_trunk *trunk;
	
	/* Destroy all trunks */
	AST_RWLIST_WRLOCK(&trunks);
	while ((trunk = AST_RWLIST_REMOVE_HEAD(&trunks, list))) {
		trunk_destroy(trunk);
	}
	AST_RWLIST_UNLOCK(&trunks);
	
	/* Destroy endpoints hash table */
	if (endpoints) {
		ao2_ref(endpoints, -1);
		endpoints = NULL;
	}
	
	/* Destroy all profiles */
	AST_RWLIST_WRLOCK(&profiles);
	while ((profile = AST_RWLIST_REMOVE_HEAD(&profiles, list))) {
		profile_destroy(profile);
	}
	AST_RWLIST_UNLOCK(&profiles);
}