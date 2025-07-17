/*
 * GABpbx -- An open source telephony toolkit.
 *
 * Copyright (C) 2025, 7kas servicios de internet SL
 *
 * Germán Aracil Boned <garacilb@gmail.com>
 *
 * Async Event Queue Implementation for chan_sofia
 *
 * This file implements an asynchronous event queue system to prevent
 * Sofia-SIP event thread blocking during SIP message processing.
 * 
 * GABpbx is a fork of Asterisk 22
 */

#include <pthread.h>
#include <time.h>
#include <errno.h>

/* Global event queue instance */
struct sofia_event_queue *sofia_queue = NULL;

/* Forward declaration */
static void sofia_process_queued_event(struct sofia_queued_event *event);

/* Initialize the event queue system */
int sofia_queue_init(void)
{
	int i;
	struct sip_profile *profile;
	int max_queue_size = SOFIA_EVENT_QUEUE_SIZE;
	int max_workers = 0;
	
	/* Find the maximum configured values across all profiles */
	AST_RWLIST_RDLOCK(&profiles);
	AST_RWLIST_TRAVERSE(&profiles, profile, list) {
		if (profile->enabled) {
			if (profile->event_queue_size > max_queue_size) {
				max_queue_size = profile->event_queue_size;
			}
			if (profile->event_queue_workers > max_workers) {
				max_workers = profile->event_queue_workers;
			}
		}
	}
	AST_RWLIST_UNLOCK(&profiles);
	
	/* Allocate queue structure */
	sofia_queue = ast_calloc(1, sizeof(*sofia_queue));
	if (!sofia_queue) {
		ast_log(LOG_ERROR, "Failed to allocate event queue\n");
		return -1;
	}
	
	/* Initialize queue */
	AST_LIST_HEAD_INIT_NOLOCK(&sofia_queue->events);
	ast_mutex_init(&sofia_queue->lock);
	ast_cond_init(&sofia_queue->cond, NULL);
	
	sofia_queue->shutdown = 0;
	sofia_queue->num_events = 0;
	sofia_queue->max_events = max_queue_size;
	sofia_queue->num_workers = 0;
	sofia_queue->max_workers = SOFIA_MAX_WORKER_THREADS;
	sofia_queue->events_processed = 0;
	sofia_queue->events_dropped = 0;
	
	/* Calculate initial number of workers */
	int initial_workers;
	if (max_workers == 0) {
		/* Auto-calculate based on CPU count */
		int cpu_count = sysconf(_SC_NPROCESSORS_ONLN);
		initial_workers = (cpu_count / 2) + 1;
		if (initial_workers < SOFIA_MIN_WORKER_THREADS) {
			initial_workers = SOFIA_MIN_WORKER_THREADS;
		}
		if (initial_workers > SOFIA_MAX_WORKER_THREADS) {
			initial_workers = SOFIA_MAX_WORKER_THREADS;
		}
	} else {
		/* Use configured value */
		initial_workers = max_workers;
	}
	
	/* Allocate thread array */
	sofia_queue->worker_threads = ast_calloc(sofia_queue->max_workers, sizeof(pthread_t));
	if (!sofia_queue->worker_threads) {
		ast_log(LOG_ERROR, "Failed to allocate worker thread array\n");
		ast_mutex_destroy(&sofia_queue->lock);
		ast_cond_destroy(&sofia_queue->cond);
		ast_free(sofia_queue);
		sofia_queue = NULL;
		return -1;
	}
	
	/* Start initial worker threads */
	for (i = 0; i < initial_workers; i++) {
		if (sofia_spawn_worker_thread() != 0) {
			ast_log(LOG_ERROR, "Failed to spawn worker thread %d\n", i);
			/* Continue with fewer threads */
			break;
		}
	}
	
	if (sofia_queue->num_workers == 0) {
		ast_log(LOG_ERROR, "No worker threads could be started\n");
		sofia_queue_destroy();
		return -1;
	}
	
	ast_log(LOG_NOTICE, "Sofia event queue initialized: size=%d, workers=%d (max=%d)\n", 
		sofia_queue->max_events, sofia_queue->num_workers, sofia_queue->max_workers);
	
	/* Ensure the global pointer is visible to all threads */
	__sync_synchronize();  /* Memory barrier */
	
	return 0;
}

/* Destroy the event queue system */
void sofia_queue_destroy(void)
{
	int i;
	struct sofia_queued_event *event;
	
	if (!sofia_queue) {
		return;
	}
	
	ast_log(LOG_NOTICE, "Shutting down Sofia event queue\n");
	
	/* Signal shutdown */
	ast_mutex_lock(&sofia_queue->lock);
	sofia_queue->shutdown = 1;
	ast_cond_broadcast(&sofia_queue->cond);
	ast_mutex_unlock(&sofia_queue->lock);
	
	/* Wait for all worker threads to exit */
	for (i = 0; i < sofia_queue->num_workers; i++) {
		if (sofia_queue->worker_threads[i] != AST_PTHREADT_NULL) {
			pthread_join(sofia_queue->worker_threads[i], NULL);
		}
	}
	
	/* Free any remaining queued events */
	ast_mutex_lock(&sofia_queue->lock);
	while ((event = AST_LIST_REMOVE_HEAD(&sofia_queue->events, list))) {
		sofia_free_queued_event(event);
	}
	ast_mutex_unlock(&sofia_queue->lock);
	
	/* Clean up */
	ast_mutex_destroy(&sofia_queue->lock);
	ast_cond_destroy(&sofia_queue->cond);
	ast_free(sofia_queue->worker_threads);
	
	ast_log(LOG_NOTICE, "Sofia event queue stats: processed=%d, dropped=%d\n",
		sofia_queue->events_processed, sofia_queue->events_dropped);
	
	ast_free(sofia_queue);
	sofia_queue = NULL;
}

/* Queue an event for async processing */
int sofia_queue_event(struct sip_profile *profile, nua_handle_t *nh, 
                     enum nua_event_e event, int status, char const *phrase,
                     nua_t *nua, msg_t *msg, sip_t const *sip, 
                     nua_saved_event_t *saved)
{
	struct sofia_queued_event *qevent;
	int queue_depth;
	
	if (!sofia_queue || sofia_queue->shutdown) {
		ast_log(LOG_ERROR, "Event queue not available\n");
		return -1;
	}
	
	/* Check queue depth */
	ast_mutex_lock(&sofia_queue->lock);
	queue_depth = sofia_queue->num_events;
	
	/* Reject if queue is full */
	if (queue_depth >= SOFIA_QUEUE_HIGH_WATER) {
		sofia_queue->events_dropped++;
		ast_mutex_unlock(&sofia_queue->lock);
		
		ast_log(LOG_WARNING, "Event queue full (%d/%d), dropping event %s\n",
			queue_depth, sofia_queue->max_events, nua_event_name(event));
		
		/* Send 503 for INVITE if queue is full */
		if (event == nua_i_invite && nh) {
			nua_respond(nh, SIP_503_SERVICE_UNAVAILABLE,
				SIPTAG_RETRY_AFTER_STR("10"),
				TAG_END());
		}
		
		return -1;
	}
	ast_mutex_unlock(&sofia_queue->lock);
	
	/* Check if we need more worker threads */
	sofia_check_queue_depth();
	
	/* Allocate event structure */
	qevent = ast_calloc(1, sizeof(*qevent));
	if (!qevent) {
		ast_log(LOG_ERROR, "Failed to allocate queued event\n");
		return -1;
	}
	
	/* Initialize event structure */
	qevent->profile = profile;
	qevent->event = event;
	qevent->queued_time = time(NULL);
	
	/* Create home for this event */
	qevent->home = su_home_new(sizeof(*qevent->home));
	if (!qevent->home) {
		ast_log(LOG_ERROR, "Failed to create su_home for event\n");
		ast_free(qevent);
		return -1;
	}
	
	/* Save NUA handle with reference */
	if (nh) {
		qevent->nh = nua_handle_ref(nh);
	}
	
	/* Save the event data */
	if (saved) {
		/* Copy the saved event data */
		memcpy(qevent->saved, saved, sizeof(qevent->saved));
	} else if (msg) {
		/* Save event from message */
		nua_save_event(nua, qevent->saved);
	}
	
	/* Clone the SIP message into our home */
	if (sip && msg) {
		qevent->msg = msg_dup(msg);
		if (qevent->msg) {
			qevent->sip = sip_object(qevent->msg);
		}
	}
	
	/* Queue the event */
	ast_mutex_lock(&sofia_queue->lock);
	AST_LIST_INSERT_TAIL(&sofia_queue->events, qevent, list);
	sofia_queue->num_events++;
	ast_debug(5, "Signaling worker thread for %s event\n", nua_event_name(event));
	ast_cond_signal(&sofia_queue->cond);
	ast_mutex_unlock(&sofia_queue->lock);
	
	ast_log(LOG_NOTICE, "Queued %s event (depth=%d)\n", 
		nua_event_name(event), sofia_queue->num_events);
	
	return 0;
}

/* Dequeue an event for processing */
struct sofia_queued_event *sofia_dequeue_event(void)
{
	struct sofia_queued_event *event = NULL;
	
	if (!sofia_queue) {
		ast_log(LOG_ERROR, "sofia_dequeue_event: queue is NULL!\n");
		return NULL;
	}
	
	ast_mutex_lock(&sofia_queue->lock);
	
	/* Wait for an event or shutdown */
	while (!sofia_queue->shutdown && AST_LIST_EMPTY(&sofia_queue->events)) {
		struct timespec ts;
		struct timeval tv;
		int res;
		
		ast_debug(5, "Worker waiting for events (queue empty)\n");
		
		/* Wait with timeout to avoid permanent blocking */
		tv = ast_tvnow();
		ts.tv_sec = tv.tv_sec + 1;
		ts.tv_nsec = tv.tv_usec * 1000;
		
		res = ast_cond_timedwait(&sofia_queue->cond, &sofia_queue->lock, &ts);
		if (res == ETIMEDOUT) {
			ast_debug(5, "Worker wait timeout, checking queue again\n");
		} else {
			ast_debug(5, "Worker woke up! shutdown=%d, empty=%d\n", 
				sofia_queue->shutdown, AST_LIST_EMPTY(&sofia_queue->events));
		}
	}
	
	/* Get the next event if not shutting down */
	if (!sofia_queue->shutdown && !AST_LIST_EMPTY(&sofia_queue->events)) {
		event = AST_LIST_REMOVE_HEAD(&sofia_queue->events, list);
		sofia_queue->num_events--;
		sofia_queue->events_processed++;
		ast_debug(5, "Dequeued event %s (remaining: %d)\n", 
			nua_event_name(event->event), sofia_queue->num_events);
	}
	
	ast_mutex_unlock(&sofia_queue->lock);
	
	return event;
}

/* Free a queued event */
void sofia_free_queued_event(struct sofia_queued_event *event)
{
	if (!event) {
		return;
	}
	
	/* Release NUA handle reference */
	if (event->nh) {
		nua_handle_unref(event->nh);
	}
	
	/* Free the message */
	if (event->msg) {
		msg_destroy(event->msg);
	}
	
	/* Destroy the home */
	if (event->home) {
		su_home_unref(event->home);
	}
	
	/* Free the event structure */
	ast_free(event);
}

/* Worker thread function */
void *sofia_worker_thread(void *data)
{
	struct sofia_queued_event *event;
	int thread_id = (int)(long)data;
	int events_processed = 0;
	
	ast_log(LOG_NOTICE, "Sofia worker thread %d started\n", thread_id);
	
	/* Verify queue is initialized */
	if (!sofia_queue) {
		ast_log(LOG_ERROR, "Worker thread %d: sofia_queue is NULL!\n", thread_id);
		return NULL;
	}
	
	ast_log(LOG_NOTICE, "Worker thread %d: Queue verified, entering main loop\n", thread_id);
	
	/* Process events until shutdown */
	while (!sofia_queue->shutdown) {
		ast_debug(5, "Worker thread %d calling dequeue\n", thread_id);
		event = sofia_dequeue_event();
		if (!event) {
			/* Shutdown or spurious wakeup */
			ast_debug(5, "Worker thread %d: dequeue returned NULL\n", thread_id);
			continue;
		}
		
		/* Process the event */
		ast_log(LOG_NOTICE, "Worker %d processing %s event (total: %d)\n", 
			thread_id, nua_event_name(event->event), ++events_processed);
		
		/* Call the original event handler */
		sofia_process_queued_event(event);
		
		/* Free the event */
		sofia_free_queued_event(event);
	}
	
	ast_log(LOG_NOTICE, "Sofia worker thread %d exiting (processed %d events)\n", 
		thread_id, events_processed);
	
	return NULL;
}

/* Spawn a new worker thread */
int sofia_spawn_worker_thread(void)
{
	pthread_t thread_id;
	pthread_attr_t attr;
	int thread_num;
	
	if (!sofia_queue) {
		return -1;
	}
	
	ast_mutex_lock(&sofia_queue->lock);
	
	/* Check if we can spawn more threads */
	if (sofia_queue->num_workers >= sofia_queue->max_workers) {
		ast_mutex_unlock(&sofia_queue->lock);
		return -1;
	}
	
	thread_num = sofia_queue->num_workers;
	ast_mutex_unlock(&sofia_queue->lock);
	
	/* Create thread attributes */
	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
	
	/* Create the thread */
	if (ast_pthread_create(&thread_id, &attr, sofia_worker_thread, 
	                      (void *)(long)thread_num) != 0) {
		ast_log(LOG_ERROR, "Failed to create worker thread %d\n", thread_num);
		pthread_attr_destroy(&attr);
		return -1;
	}
	
	pthread_attr_destroy(&attr);
	
	/* Store thread ID */
	ast_mutex_lock(&sofia_queue->lock);
	sofia_queue->worker_threads[thread_num] = thread_id;
	sofia_queue->num_workers++;
	ast_mutex_unlock(&sofia_queue->lock);
	
	ast_log(LOG_NOTICE, "Spawned new Sofia worker thread %d (total: %d)\n",
		thread_num, sofia_queue->num_workers);
	
	return 0;
}

/* Check queue depth and spawn threads if needed */
void sofia_check_queue_depth(void)
{
	int queue_depth;
	int active_workers;
	int queue_per_worker;
	
	if (!sofia_queue) {
		return;
	}
	
	ast_mutex_lock(&sofia_queue->lock);
	queue_depth = sofia_queue->num_events;
	active_workers = sofia_queue->num_workers;
	ast_mutex_unlock(&sofia_queue->lock);
	
	/* Calculate events per worker */
	if (active_workers > 0) {
		queue_per_worker = queue_depth / active_workers;
	} else {
		queue_per_worker = queue_depth;
	}
	
	/* Spawn new thread if queue is getting deep */
	if (queue_per_worker > 100 && active_workers < sofia_queue->max_workers) {
		ast_log(LOG_NOTICE, "Queue depth %d, spawning additional worker\n", queue_depth);
		sofia_spawn_worker_thread();
	}
}

/* Process a queued event (called by worker threads) */
static void sofia_process_queued_event(struct sofia_queued_event *event)
{
	nua_event_data_t ev_data;
	
	if (!event || !event->profile) {
		return;
	}
	
	/* Reconstruct event data */
	memset(&ev_data, 0, sizeof(ev_data));
	ev_data.e_event = event->event;
	ev_data.e_msg = event->msg;
	
	/* Call the appropriate handler based on event type */
	switch (event->event) {
	case nua_i_invite:
		if (event->sip) {
			sofia_handle_invite(event->profile, event->nh, event->sip, 
			                   event->profile->nua, event->saved);
		}
		break;
		
	case nua_i_register:
		if (event->sip) {
			/* For async processing, we need to use saved event data */
			nua_saved_event_t saved_copy[1];
			memcpy(saved_copy, event->saved, sizeof(saved_copy));
			handle_register_request(event->profile, event->nh, event->sip, 
			                       event->profile->nua, event->msg, NULL, saved_copy);
		}
		break;
		
	case nua_i_options:
		if (event->sip) {
			handle_options_request(event->profile, event->nh, event->sip, 
			                      event->profile->nua, event->msg, NULL, event->saved);
		}
		break;
		
	case nua_i_subscribe:
		if (event->sip) {
			handle_subscribe_request(event->profile, event->nh, event->sip, 
			                        event->profile->nua, event->msg, NULL, event->saved);
		}
		break;
		
	case nua_i_publish:
		if (event->sip) {
			handle_publish_request(event->nh, event->profile, event->sip, 
			                      NULL, event->profile->nua, event->saved);
		}
		break;
		
	case nua_i_info:
		if (event->sip) {
			handle_info_request(event->nh, event->profile, event->sip, NULL, event->msg);
		}
		break;
		
	case nua_i_cancel:
		if (event->sip) {
			handle_cancel_request(event->nh, event->profile, event->sip, NULL);
		}
		break;
		
	case nua_i_ack:
		if (event->sip) {
			handle_ack_request(event->nh, event->profile, event->sip, NULL);
		}
		break;
		
	case nua_i_bye:
		if (event->sip) {
			handle_bye_request(event->nh, event->profile, event->sip, NULL, event->msg);
		}
		break;
		
	default:
		ast_debug(2, "Unhandled queued event: %s\n", nua_event_name(event->event));
		break;
	}
}