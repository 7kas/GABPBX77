/*
 * GABpbx -- An open source telephony toolkit.
 *
 * Copyright (C) 1999 - 2009, Digium, Inc.
 *
 * Mark Spencer <markster@digium.com>
 *
 * Includes code and algorithms from the Zapata library.
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

/*!
 * \file
 * \brief Custom Comma Separated Value CDR records.
 *
 * \author Mark Spencer <markster@digium.com>
 *
 * \arg See also \ref AstCDR
 *
 * Logs in LOG_DIR/cdr_custom
 * \ingroup cdr_drivers
 */

/*! \li \ref cdr_custom.c uses the configuration file \ref cdr_custom.conf
 * \addtogroup configuration_file Configuration Files
 */

/*!
 * \page cdr_custom.conf cdr_custom.conf
 * \verbinclude cdr_custom.conf.sample
 */

/*** MODULEINFO
	<support_level>core</support_level>
 ***/

#include "gabpbx.h"

#include <time.h>

#include "gabpbx/paths.h"	/* use ast_config_AST_LOG_DIR */
#include "gabpbx/channel.h"
#include "gabpbx/cdr.h"
#include "gabpbx/module.h"
#include "gabpbx/config.h"
#include "gabpbx/pbx.h"
#include "gabpbx/utils.h"
#include "gabpbx/lock.h"
#include "gabpbx/threadstorage.h"
#include "gabpbx/strings.h"

#define CONFIG "cdr_custom.conf"

AST_THREADSTORAGE(custom_buf);

static const char name[] = "cdr-custom";

struct cdr_custom_config {
	AST_DECLARE_STRING_FIELDS(
		AST_STRING_FIELD(filename);
		AST_STRING_FIELD(format);
		);
	ast_mutex_t lock;
	AST_RWLIST_ENTRY(cdr_custom_config) list;
};

static AST_RWLIST_HEAD_STATIC(sinks, cdr_custom_config);

static void free_config(void)
{
	struct cdr_custom_config *sink;

	while ((sink = AST_RWLIST_REMOVE_HEAD(&sinks, list))) {
		ast_mutex_destroy(&sink->lock);
		ast_string_field_free_memory(sink);
		ast_free(sink);
	}
}

static int load_config(void)
{
	struct ast_config *cfg;
	struct ast_variable *var;
	struct ast_flags config_flags = { 0 };
	int res = 0;

	cfg = ast_config_load(CONFIG, config_flags);
	if (!cfg || cfg == CONFIG_STATUS_FILEINVALID) {
		ast_log_chan(NULL, LOG_ERROR, "Unable to load " CONFIG ". Not logging custom CSV CDRs.\n");
		return -1;
	}

	var = ast_variable_browse(cfg, "mappings");
	while (var) {
		if (!ast_strlen_zero(var->name) && !ast_strlen_zero(var->value)) {
			struct cdr_custom_config *sink = ast_calloc_with_stringfields(1, struct cdr_custom_config, 1024);

			if (!sink) {
				ast_log_chan(NULL, LOG_ERROR, "Unable to allocate memory for configuration settings.\n");
				res = -2;
				break;
			}

			ast_string_field_build(sink, format, "%s\n", var->value);
			if (var->name[0] == '/') {
				ast_string_field_build(sink, filename, "%s", var->name);
			} else {
				ast_string_field_build(sink, filename, "%s/%s/%s", ast_config_AST_LOG_DIR, name, var->name);
			}
			ast_mutex_init(&sink->lock);

			AST_RWLIST_INSERT_TAIL(&sinks, sink, list);
		} else {
			ast_log_chan(NULL, LOG_NOTICE, "Mapping must have both a filename and a format at line %d\n", var->lineno);
		}
		var = var->next;
	}
	ast_config_destroy(cfg);

	return res;
}

static int custom_log(struct ast_cdr *cdr)
{
	struct ast_channel *dummy;
	struct ast_str *str;
	struct cdr_custom_config *config;

	/* Batching saves memory management here.  Otherwise, it's the same as doing an allocation and free each time. */
	if (!(str = ast_str_thread_get(&custom_buf, 16))) {
		return -1;
	}

	dummy = ast_dummy_channel_alloc();
	if (!dummy) {
		ast_log_chan(NULL, LOG_ERROR, "Unable to allocate channel for variable substitution.\n");
		return -1;
	}

	/* We need to dup here since the cdr actually belongs to the other channel,
	   so when we release this channel we don't want the CDR getting cleaned
	   up prematurely. */
	ast_channel_cdr_set(dummy, ast_cdr_dup(cdr));

	AST_RWLIST_RDLOCK(&sinks);

	AST_LIST_TRAVERSE(&sinks, config, list) {
		FILE *out;

		ast_str_substitute_variables(&str, 0, dummy, config->format);

		/* Even though we have a lock on the list, we could be being chased by
		   another thread and this lock ensures that we won't step on anyone's
		   toes.  Once each CDR backend gets it's own thread, this lock can be
		   removed. */
		ast_mutex_lock(&config->lock);

		/* Because of the absolutely unconditional need for the
		   highest reliability possible in writing billing records,
		   we open write and close the log file each time */
		if ((out = fopen(config->filename, "a"))) {
			fputs(ast_str_buffer(str), out);
			fflush(out); /* be particularly anal here */
			fclose(out);
		} else {
			ast_log_chan(NULL, LOG_ERROR, "Unable to re-open master file %s : %s\n", config->filename, strerror(errno));
		}

		ast_mutex_unlock(&config->lock);
	}

	AST_RWLIST_UNLOCK(&sinks);

	ast_channel_unref(dummy);

	return 0;
}

static int unload_module(void)
{
	if (ast_cdr_unregister(name)) {
		return -1;
	}

	if (AST_RWLIST_WRLOCK(&sinks)) {
		ast_cdr_register(name, ast_module_info->description, custom_log);
		ast_log_chan(NULL, LOG_ERROR, "Unable to lock sink list.  Unload failed.\n");
		return -1;
	}

	free_config();
	AST_RWLIST_UNLOCK(&sinks);
	return 0;
}

static enum ast_module_load_result load_module(void)
{
	if (AST_RWLIST_WRLOCK(&sinks)) {
		ast_log_chan(NULL, LOG_ERROR, "Unable to lock sink list.  Load failed.\n");
		return AST_MODULE_LOAD_DECLINE;
	}

	load_config();
	AST_RWLIST_UNLOCK(&sinks);
	ast_cdr_register(name, ast_module_info->description, custom_log);
	return AST_MODULE_LOAD_SUCCESS;
}

static int reload(void)
{
	if (AST_RWLIST_WRLOCK(&sinks)) {
		ast_log_chan(NULL, LOG_ERROR, "Unable to lock sink list.  Load failed.\n");
		return AST_MODULE_LOAD_DECLINE;
	}

	free_config();
	load_config();
	AST_RWLIST_UNLOCK(&sinks);
	return AST_MODULE_LOAD_SUCCESS;
}

AST_MODULE_INFO(GABPBX_GPL_KEY, AST_MODFLAG_LOAD_ORDER, "Customizable Comma Separated Values CDR Backend",
	.support_level = AST_MODULE_SUPPORT_CORE,
	.load = load_module,
	.unload = unload_module,
	.reload = reload,
	.load_pri = AST_MODPRI_CDR_DRIVER,
	.requires = "cdr",
);
