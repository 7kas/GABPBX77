/*
 * GABpbx -- An open source telephony toolkit.
 *
 * Copyright (C) 2013, Digium, Inc.
 *
 * David M. Lee, II <dlee@digium.com>
 *
 * See http://www.gabpbx.org for more information about
 * the GABpbx project. Please do not directly contact
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
 * \brief Typical cache pattern for Stasis topics.
 *
 * \author David M. Lee, II <dlee@digium.com>
 */

/*** MODULEINFO
	<support_level>core</support_level>
 ***/

#include "gabpbx.h"

#include "gabpbx/astobj2.h"
#include "gabpbx/stasis_cache_pattern.h"

struct stasis_cp_all {
	struct stasis_topic *topic;
	struct stasis_topic *topic_cached;
	struct stasis_cache *cache;

	struct stasis_forward *forward_all_to_cached;
};

struct stasis_cp_single {
	struct stasis_topic *topic;
	struct stasis_caching_topic *topic_cached;

	struct stasis_forward *forward_topic_to_all;
	struct stasis_forward *forward_cached_to_all;
};

static void all_dtor(void *obj)
{
	struct stasis_cp_all *all = obj;

	ao2_cleanup(all->topic);
	all->topic = NULL;
	ao2_cleanup(all->topic_cached);
	all->topic_cached = NULL;
	ao2_cleanup(all->cache);
	all->cache = NULL;
	stasis_forward_cancel(all->forward_all_to_cached);
	all->forward_all_to_cached = NULL;
}

struct stasis_cp_all *stasis_cp_all_create(const char *name,
	snapshot_get_id id_fn)
{
	char *cached_name = NULL;
	struct stasis_cp_all *all;
	static int cache_id;

	all = ao2_t_alloc(sizeof(*all), all_dtor, name);
	if (!all) {
		return NULL;
	}

	ast_asprintf(&cached_name, "cache_pattern:%d/%s", ast_atomic_fetchadd_int(&cache_id, +1), name);
	if (!cached_name) {
		ao2_ref(all, -1);

		return NULL;
	}

	all->topic = stasis_topic_create(name);
	all->topic_cached = stasis_topic_create(cached_name);
	ast_free(cached_name);
	all->cache = stasis_cache_create(id_fn);
	all->forward_all_to_cached =
		stasis_forward_all(all->topic, all->topic_cached);

	if (!all->topic || !all->topic_cached || !all->cache ||
		!all->forward_all_to_cached) {
		ao2_ref(all, -1);

		return NULL;
	}

	return all;
}

struct stasis_topic *stasis_cp_all_topic(struct stasis_cp_all *all)
{
	if (!all) {
		return NULL;
	}
	return all->topic;
}

struct stasis_topic *stasis_cp_all_topic_cached(
	struct stasis_cp_all *all)
{
	if (!all) {
		return NULL;
	}
	return all->topic_cached;
}

struct stasis_cache *stasis_cp_all_cache(struct stasis_cp_all *all)
{
	if (!all) {
		return NULL;
	}
	return all->cache;
}

static void one_dtor(void *obj)
{
	struct stasis_cp_single *one = obj;

	/* Should already be unsubscribed */
	ast_assert(one->topic_cached == NULL);
	ast_assert(one->forward_topic_to_all == NULL);
	ast_assert(one->forward_cached_to_all == NULL);

	ao2_cleanup(one->topic);
	one->topic = NULL;
}

struct stasis_cp_single *stasis_cp_single_create(struct stasis_cp_all *all,
	const char *name)
{
	struct stasis_cp_single *one;

	one = stasis_cp_sink_create(all, name);
	if (!one) {
		return NULL;
	}

	one->forward_topic_to_all = stasis_forward_all(one->topic, all->topic);
	one->forward_cached_to_all = stasis_forward_all(
		stasis_caching_get_topic(one->topic_cached), all->topic_cached);

	if (!one->forward_topic_to_all || !one->forward_cached_to_all) {
		ao2_ref(one, -1);

		return NULL;
	}

	return one;
}

struct stasis_cp_single *stasis_cp_sink_create(struct stasis_cp_all *all,
	const char *name)
{
	struct stasis_cp_single *one;

	one = ao2_t_alloc(sizeof(*one), one_dtor, name);
	if (!one) {
		return NULL;
	}

	one->topic = stasis_topic_create(name);
	if (!one->topic) {
		ao2_ref(one, -1);

		return NULL;
	}

	one->topic_cached = stasis_caching_topic_create(one->topic, all->cache);
	if (!one->topic_cached) {
		ao2_ref(one, -1);

		return NULL;
	}

	return one;
}

void stasis_cp_single_unsubscribe(struct stasis_cp_single *one)
{
	if (!one) {
		return;
	}

	stasis_forward_cancel(one->forward_topic_to_all);
	one->forward_topic_to_all = NULL;
	stasis_forward_cancel(one->forward_cached_to_all);
	one->forward_cached_to_all = NULL;
	stasis_caching_unsubscribe(one->topic_cached);
	one->topic_cached = NULL;

	ao2_cleanup(one);
}

struct stasis_topic *stasis_cp_single_topic(struct stasis_cp_single *one)
{
	if (!one) {
		return NULL;
	}
	return one->topic;
}

struct stasis_topic *stasis_cp_single_topic_cached(
	struct stasis_cp_single *one)
{
	if (!one) {
		return NULL;
	}
	return stasis_caching_get_topic(one->topic_cached);
}

int stasis_cp_single_accept_message_type(struct stasis_cp_single *one,
	struct stasis_message_type *type)
{
	if (!one) {
		return -1;
	}
	return stasis_caching_accept_message_type(one->topic_cached, type);
}

int stasis_cp_single_set_filter(struct stasis_cp_single *one,
	enum stasis_subscription_message_filter filter)
{
	if (!one) {
		return -1;
	}
	return stasis_caching_set_filter(one->topic_cached, filter);
}
