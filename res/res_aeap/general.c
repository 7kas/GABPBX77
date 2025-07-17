/*
 * GABpbx -- An open source telephony toolkit.
 *
 * Copyright (C) 2021, Sangoma Technologies Corporation
 *
 * Kevin Harwell <kharwell@sangoma.com>
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

#include "gabpbx.h"

#include "gabpbx/astobj2.h"
#include "gabpbx/sched.h"

#include "general.h"

/*! \brief Scheduler for transaction timeouts */
static struct ast_sched_context *sched = NULL;

struct ast_sched_context *aeap_sched_context(void)
{
	return sched;
}

void aeap_general_finalize(void)
{
	if (sched) {
		ast_sched_context_destroy(sched);
		sched = NULL;
	}
}

int aeap_general_initialize(void)
{
	sched = ast_sched_context_create();
	if (!sched) {
		ast_log_chan(NULL, LOG_ERROR, "AEAP scheduler: unable to create context");
		return -1;
	}

	if (ast_sched_start_thread(sched)) {
		ast_log_chan(NULL, LOG_ERROR, "AEAP scheduler: unable to start thread");
		aeap_general_finalize();
		return -1;
	}

	return 0;
}

