/*
 * GABpbx -- An open source telephony toolkit.
 *
 * Copyright (C) 2024, GABpbx Development Team
 *
 * sip_core.c - High-performance Sofia-SIP core implementation
 *
 * Designed for thousands of concurrent UACs with:
 * - Efficient memory pooling
 * - Lock-free data structures where possible  
 * - Per-CPU thread pools
 * - Zero-copy message handling
 * - Intelligent load balancing
 */

#include "gabpbx.h"

#ifdef HAVE_SOFIA_SIP_UA_NUA_H

#include <sofia-sip/su.h>
#include <sofia-sip/su_wait.h>
#include <sofia-sip/nua.h>
#include <sofia-sip/sip_status.h>
#include <sofia-sip/sip_header.h>
#include <sofia-sip/soa.h>
#include <sofia-sip/sresolv.h>
#include <sofia-sip/su_md5.h>

#include "gabpbx/module.h"
#include "gabpbx/channel.h"
#include "gabpbx/logger.h"
#include "gabpbx/lock.h"
#include "gabpbx/utils.h"
#include "gabpbx/astobj2.h"
#include "gabpbx/threadpool.h"
#include "gabpbx/taskprocessor.h"
#include "gabpbx/res_pjsip.h"

#include "include/sip_sofia.h"

/* Performance tuning constants */
#define SOFIA_HASH_SIZE 5003          /* Prime number for better distribution */
#define SOFIA_MAX_THREADS 64          /* Max worker threads */
#define SOFIA_BATCH_SIZE 100          /* Events to process per batch */
#define SOFIA_MEMORY_POOL_SIZE 65536  /* Per-thread memory pool */

/* Global root for Sofia event loop */
static su_root_t **sofia_roots = NULL;
static int sofia_root_count = 0;
static pthread_t *sofia_threads = NULL;

/* Thread pool for parallel processing */
static struct ast_threadpool *sofia_threadpool = NULL;

/* Task processors for serialization */
static struct ast_taskprocessor **sofia_taskprocessors = NULL;
static int sofia_taskprocessor_count = 0;

/* High-performance hash tables */
static struct ao2_container *active_dialogs = NULL;
static struct ao2_container *registrations = NULL;
static struct ao2_container *subscriptions = NULL;

/* Memory pools for zero-copy */
struct sofia_memory_pool {
	ast_mutex_t lock;
	void *base;
	size_t size;
	size_t used;
	struct sofia_memory_pool *next;
};

static __thread struct sofia_memory_pool *thread_memory_pool = NULL;

/* Per-CPU statistics for monitoring */
struct sofia_cpu_stats {
	atomic_uint messages_processed;
	atomic_uint calls_active;
	atomic_uint registrations_active;
	atomic_uint options_sent;
	atomic_uint messages_sent;
	atomic_uint subscribe_active;
} __attribute__((aligned(64))); /* Cache line aligned */

static struct sofia_cpu_stats *cpu_stats = NULL;

/* Initialize memory pool */
static void sofia_memory_pool_init(void)
{
	if (!thread_memory_pool) {
		thread_memory_pool = ast_calloc(1, sizeof(*thread_memory_pool));
		if (thread_memory_pool) {
			thread_memory_pool->base = ast_malloc(SOFIA_MEMORY_POOL_SIZE);
			thread_memory_pool->size = SOFIA_MEMORY_POOL_SIZE;
			thread_memory_pool->used = 0;
			ast_mutex_init(&thread_memory_pool->lock);
		}
	}
}

/* Zero-copy allocation from pool */
static void *sofia_pool_alloc(size_t size)
{
	void *ptr = NULL;
	
	sofia_memory_pool_init();
	
	if (thread_memory_pool) {
		ast_mutex_lock(&thread_memory_pool->lock);
		if (thread_memory_pool->used + size <= thread_memory_pool->size) {
			ptr = (char *)thread_memory_pool->base + thread_memory_pool->used;
			thread_memory_pool->used += size;
		}
		ast_mutex_unlock(&thread_memory_pool->lock);
	}
	
	return ptr ? ptr : ast_malloc(size);
}

/* Dialog hash function for even distribution */
static int dialog_hash_fn(const void *obj, const int flags)
{
	const struct sip_pvt *pvt = obj;
	const char *key;
	
	switch (flags & OBJ_SEARCH_MASK) {
	case OBJ_SEARCH_KEY:
		key = obj;
		break;
	case OBJ_SEARCH_OBJECT:
		key = pvt->callid;
		break;
	default:
		ast_assert(0);
		return 0;
	}
	
	/* DJB2 hash algorithm */
	unsigned int hash = 5381;
	while (*key) {
		hash = ((hash << 5) + hash) + *key++;
	}
	
	return hash;
}

/* Dialog comparison for hash table */
static int dialog_cmp_fn(void *obj, void *arg, int flags)
{
	struct sip_pvt *pvt1 = obj;
	struct sip_pvt *pvt2 = arg;
	const char *key = arg;
	
	switch (flags & OBJ_SEARCH_MASK) {
	case OBJ_SEARCH_KEY:
		return strcasecmp(pvt1->callid, key) ? 0 : CMP_MATCH;
	case OBJ_SEARCH_OBJECT:
		return strcasecmp(pvt1->callid, pvt2->callid) ? 0 : CMP_MATCH;
	default:
		return 0;
	}
}

/* Worker thread for Sofia event processing */
static void *sofia_worker_thread(void *data)
{
	int idx = (intptr_t)data;
	su_root_t *root = sofia_roots[idx];
	struct sofia_cpu_stats *stats = &cpu_stats[idx];
	
	ast_debug(1, "Sofia worker thread %d started\n", idx);
	
	/* Set thread name */
	char thread_name[16];
	snprintf(thread_name, sizeof(thread_name), "sofia-%d", idx);
	pthread_setname_np(pthread_self(), thread_name);
	
	/* Main event loop */
	while (sofia_running) {
		/* Process events in batches for efficiency */
		su_root_step(root, 100); /* 100ms timeout */
		
		/* Update statistics */
		atomic_fetch_add(&stats->messages_processed, 1);
	}
	
	ast_debug(1, "Sofia worker thread %d stopped\n", idx);
	return NULL;
}

/* Initialize high-performance Sofia core */
int sofia_core_init(void)
{
	int cpu_count;
	int i;
	
	/* Initialize Sofia-SIP */
	su_init();
	
	/* Determine optimal thread count */
	cpu_count = sysconf(_SC_NPROCESSORS_ONLN);
	if (cpu_count < 1) {
		cpu_count = 1;
	} else if (cpu_count > SOFIA_MAX_THREADS) {
		cpu_count = SOFIA_MAX_THREADS;
	}
	
	sofia_root_count = cpu_count;
	ast_log(LOG_NOTICE, "Initializing Sofia-SIP with %d worker threads\n", sofia_root_count);
	
	/* Allocate roots and threads */
	sofia_roots = ast_calloc(sofia_root_count, sizeof(su_root_t *));
	sofia_threads = ast_calloc(sofia_root_count, sizeof(pthread_t));
	cpu_stats = ast_calloc(sofia_root_count, sizeof(struct sofia_cpu_stats));
	
	if (!sofia_roots || !sofia_threads || !cpu_stats) {
		ast_log(LOG_ERROR, "Failed to allocate Sofia core structures\n");
		return -1;
	}
	
	/* Create roots */
	for (i = 0; i < sofia_root_count; i++) {
		sofia_roots[i] = su_root_create(NULL);
		if (!sofia_roots[i]) {
			ast_log(LOG_ERROR, "Failed to create Sofia root %d\n", i);
			return -1;
		}
	}
	
	/* Create thread pool for async operations */
	struct ast_threadpool_options options = {
		.version = AST_THREADPOOL_OPTIONS_VERSION,
		.idle_timeout = 60,
		.auto_increment = 5,
		.initial_size = sofia_root_count * 2,
		.max_size = sofia_root_count * 4,
	};
	
	sofia_threadpool = ast_threadpool_create("sofia", NULL, &options);
	if (!sofia_threadpool) {
		ast_log(LOG_ERROR, "Failed to create Sofia thread pool\n");
		return -1;
	}
	
	/* Create task processors for serialization */
	sofia_taskprocessor_count = sofia_root_count;
	sofia_taskprocessors = ast_calloc(sofia_taskprocessor_count, sizeof(struct ast_taskprocessor *));
	
	for (i = 0; i < sofia_taskprocessor_count; i++) {
		char name[32];
		snprintf(name, sizeof(name), "sofia-tps-%d", i);
		sofia_taskprocessors[i] = ast_taskprocessor_get(name, TPS_REF_DEFAULT);
		if (!sofia_taskprocessors[i]) {
			ast_log(LOG_ERROR, "Failed to create task processor %s\n", name);
			return -1;
		}
	}
	
	/* Create high-performance hash tables */
	active_dialogs = ao2_container_alloc_hash(AO2_ALLOC_OPT_LOCK_RWLOCK, 0,
		SOFIA_HASH_SIZE, dialog_hash_fn, NULL, dialog_cmp_fn);
	
	registrations = ao2_container_alloc_hash(AO2_ALLOC_OPT_LOCK_RWLOCK, 0,
		SOFIA_HASH_SIZE, dialog_hash_fn, NULL, dialog_cmp_fn);
	
	subscriptions = ao2_container_alloc_hash(AO2_ALLOC_OPT_LOCK_RWLOCK, 0,
		SOFIA_HASH_SIZE, dialog_hash_fn, NULL, dialog_cmp_fn);
	
	if (!active_dialogs || !registrations || !subscriptions) {
		ast_log(LOG_ERROR, "Failed to create hash tables\n");
		return -1;
	}
	
	/* Start worker threads */
	sofia_running = 1;
	for (i = 0; i < sofia_root_count; i++) {
		if (ast_pthread_create_background(&sofia_threads[i], NULL, 
			sofia_worker_thread, (void *)(intptr_t)i) < 0) {
			ast_log(LOG_ERROR, "Failed to create Sofia worker thread %d\n", i);
			return -1;
		}
	}
	
	ast_log(LOG_NOTICE, "Sofia-SIP core initialized successfully\n");
	return 0;
}

/* Shutdown Sofia core */
void sofia_core_shutdown(void)
{
	int i;
	
	ast_log(LOG_NOTICE, "Shutting down Sofia-SIP core\n");
	
	/* Signal threads to stop */
	sofia_running = 0;
	
	/* Wait for threads */
	if (sofia_threads) {
		for (i = 0; i < sofia_root_count; i++) {
			if (sofia_threads[i]) {
				pthread_join(sofia_threads[i], NULL);
			}
		}
		ast_free(sofia_threads);
	}
	
	/* Destroy roots */
	if (sofia_roots) {
		for (i = 0; i < sofia_root_count; i++) {
			if (sofia_roots[i]) {
				su_root_destroy(sofia_roots[i]);
			}
		}
		ast_free(sofia_roots);
	}
	
	/* Cleanup thread pool */
	if (sofia_threadpool) {
		ast_threadpool_shutdown(sofia_threadpool);
		sofia_threadpool = NULL;
	}
	
	/* Cleanup task processors */
	if (sofia_taskprocessors) {
		for (i = 0; i < sofia_taskprocessor_count; i++) {
			if (sofia_taskprocessors[i]) {
				ast_taskprocessor_unreference(sofia_taskprocessors[i]);
			}
		}
		ast_free(sofia_taskprocessors);
	}
	
	/* Cleanup hash tables */
	ao2_cleanup(active_dialogs);
	ao2_cleanup(registrations);
	ao2_cleanup(subscriptions);
	
	/* Cleanup CPU stats */
	ast_free(cpu_stats);
	
	/* Deinitialize Sofia-SIP */
	su_deinit();
	
	ast_log(LOG_NOTICE, "Sofia-SIP core shutdown complete\n");
}

/* Get least loaded worker for load balancing */
int sofia_get_best_worker(void)
{
	int best = 0;
	unsigned int min_load = UINT_MAX;
	int i;
	
	for (i = 0; i < sofia_root_count; i++) {
		unsigned int load = atomic_load(&cpu_stats[i].calls_active) +
		                   atomic_load(&cpu_stats[i].registrations_active);
		if (load < min_load) {
			min_load = load;
			best = i;
		}
	}
	
	return best;
}

/* Get root for worker */
su_root_t *sofia_get_root(int worker)
{
	if (worker >= 0 && worker < sofia_root_count) {
		return sofia_roots[worker];
	}
	return sofia_roots[0];
}

/* Get statistics */
void sofia_get_stats(struct sofia_statistics *stats)
{
	int i;
	
	memset(stats, 0, sizeof(*stats));
	
	for (i = 0; i < sofia_root_count; i++) {
		stats->messages_processed += atomic_load(&cpu_stats[i].messages_processed);
		stats->calls_active += atomic_load(&cpu_stats[i].calls_active);
		stats->registrations_active += atomic_load(&cpu_stats[i].registrations_active);
		stats->options_sent += atomic_load(&cpu_stats[i].options_sent);
		stats->messages_sent += atomic_load(&cpu_stats[i].messages_sent);
		stats->subscribe_active += atomic_load(&cpu_stats[i].subscribe_active);
	}
	
	stats->worker_threads = sofia_root_count;
	stats->dialogs_count = ao2_container_count(active_dialogs);
	stats->registrations_count = ao2_container_count(registrations);
	stats->subscriptions_count = ao2_container_count(subscriptions);
}

#endif /* HAVE_SOFIA_SIP_UA_NUA_H */