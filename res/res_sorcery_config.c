/*
 * GABpbx -- An open source telephony toolkit.
 *
 * Copyright (C) 2012 - 2013, Digium, Inc.
 *
 * Joshua Colp <jcolp@digium.com>
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
 *
 * \brief Sorcery Configuration File Object Wizard
 *
 * \author Joshua Colp <jcolp@digium.com>
 */

/*** MODULEINFO
	<support_level>core</support_level>
 ***/

#include "gabpbx.h"

#include <regex.h>

#include "gabpbx/module.h"
#include "gabpbx/sorcery.h"
#include "gabpbx/astobj2.h"
#include "gabpbx/config.h"
#include "gabpbx/uuid.h"
#include "gabpbx/hashtab.h"

/*! \brief Structure for storing configuration file sourced objects */
struct sorcery_config {
	/*! \brief UUID for identifying us when opening a configuration file */
	char uuid[AST_UUID_STR_LEN];

	/*! \brief Objects retrieved from the configuration file */
	struct ao2_global_obj objects;

	/*! \brief Any specific variable criteria for considering a defined category for this object */
	struct ast_variable *criteria;

	/*! \brief An explicit name for the configuration section, with it there can be only one */
	char *explicit_name;

	/*! \brief Number of buckets to use for objects */
	unsigned int buckets;

	/*! \brief Enable file level integrity instead of object level */
	unsigned int file_integrity:1;

	/*! \brief Enable enforcement of a single configuration object of this type */
	unsigned int single_object:1;

	/*! \brief Configuration is invalid in some way, force reload */
	unsigned int configuration_invalid:1;

	/*! \brief Configuration contains at least one object with dynamic contents */
	unsigned int has_dynamic_contents:1;

	/*! \brief Filename of the configuration file */
	char filename[];
};

/*! \brief Structure used for fields comparison */
struct sorcery_config_fields_cmp_params {
	/*! \brief Pointer to the sorcery structure */
	const struct ast_sorcery *sorcery;

	/*! \brief Pointer to the fields to check */
	const struct ast_variable *fields;

	/*! \brief Regular expression for checking object id */
	regex_t *regex;

	/*! \brief Prefix for matching object id */
	const char *prefix;

	/*! \brief Prefix length in bytes for matching object id */
	const size_t prefix_len;

	/*! \brief Optional container to put object into */
	struct ao2_container *container;
};

static void *sorcery_config_open(const char *data);
static void sorcery_config_load(void *data, const struct ast_sorcery *sorcery, const char *type);
static void sorcery_config_reload(void *data, const struct ast_sorcery *sorcery, const char *type);
static void *sorcery_config_retrieve_id(const struct ast_sorcery *sorcery, void *data, const char *type, const char *id);
static void *sorcery_config_retrieve_fields(const struct ast_sorcery *sorcery, void *data, const char *type, const struct ast_variable *fields);
static void sorcery_config_retrieve_multiple(const struct ast_sorcery *sorcery, void *data, const char *type, struct ao2_container *objects,
					     const struct ast_variable *fields);
static void sorcery_config_retrieve_regex(const struct ast_sorcery *sorcery, void *data, const char *type, struct ao2_container *objects, const char *regex);
static void sorcery_config_retrieve_prefix(const struct ast_sorcery *sorcery, void *data, const char *type, struct ao2_container *objects, const char *prefix, const size_t prefix_len);
static void sorcery_config_close(void *data);

static struct ast_sorcery_wizard config_object_wizard = {
	.name = "config",
	.open = sorcery_config_open,
	.load = sorcery_config_load,
	.reload = sorcery_config_reload,
	.force_reload = sorcery_config_load,
	.retrieve_id = sorcery_config_retrieve_id,
	.retrieve_fields = sorcery_config_retrieve_fields,
	.retrieve_multiple = sorcery_config_retrieve_multiple,
	.retrieve_regex = sorcery_config_retrieve_regex,
	.retrieve_prefix = sorcery_config_retrieve_prefix,
	.close = sorcery_config_close,
};

/*! \brief Destructor function for sorcery config */
static void sorcery_config_destructor(void *obj)
{
	struct sorcery_config *config = obj;

	ao2_global_obj_release(config->objects);
	ast_rwlock_destroy(&config->objects.lock);
	ast_variables_destroy(config->criteria);
	ast_free(config->explicit_name);
}

static int sorcery_config_fields_cmp(void *obj, void *arg, int flags)
{
	const struct sorcery_config_fields_cmp_params *params = arg;
	RAII_VAR(struct ast_variable *, objset, NULL, ast_variables_destroy);

	if (params->regex) {
		/* If a regular expression has been provided see if it matches, otherwise move on */
		if (!regexec(params->regex, ast_sorcery_object_get_id(obj), 0, NULL, 0)) {
			ao2_link(params->container, obj);
		}
		return 0;
	} else if (params->prefix) {
		if (!strncmp(params->prefix, ast_sorcery_object_get_id(obj), params->prefix_len)) {
			ao2_link(params->container, obj);
		}
		return 0;
	} else if (params->fields &&
	    (!(objset = ast_sorcery_objectset_create(params->sorcery, obj)) ||
	     (!ast_variable_lists_match(objset, params->fields, 0)))) {
		/* If we can't turn the object into an object set OR if differences exist between the fields
		 * passed in and what are present on the object they are not a match.
		 */
		return 0;
	}

	/* We want this object */
	if (params->container) {
		/*
		 * We are putting the found objects into the given container instead
		 * of the normal container traversal return mechanism.
		 */
		ao2_link(params->container, obj);
		return 0;
	} else {
		return CMP_MATCH;
	}
}

static void *sorcery_config_retrieve_fields(const struct ast_sorcery *sorcery, void *data, const char *type, const struct ast_variable *fields)
{
	struct sorcery_config *config = data;
	RAII_VAR(struct ao2_container *, objects, ao2_global_obj_ref(config->objects), ao2_cleanup);
	struct sorcery_config_fields_cmp_params params = {
		.sorcery = sorcery,
		.fields = fields,
		.container = NULL,
	};

	/* If no fields are present return nothing, we require *something*, same goes if no objects exist yet */
	if (!objects || !fields) {
		return NULL;
	}

	return ao2_callback(objects, 0, sorcery_config_fields_cmp, &params);
}

static void *sorcery_config_retrieve_id(const struct ast_sorcery *sorcery, void *data, const char *type, const char *id)
{
	struct sorcery_config *config = data;
	RAII_VAR(struct ao2_container *, objects, ao2_global_obj_ref(config->objects), ao2_cleanup);

	return objects ? ao2_find(objects, id, OBJ_SEARCH_KEY) : NULL;
}

static void sorcery_config_retrieve_multiple(const struct ast_sorcery *sorcery, void *data, const char *type, struct ao2_container *objects, const struct ast_variable *fields)
{
	struct sorcery_config *config = data;
	RAII_VAR(struct ao2_container *, config_objects, ao2_global_obj_ref(config->objects), ao2_cleanup);
	struct sorcery_config_fields_cmp_params params = {
		.sorcery = sorcery,
		.fields = fields,
		.container = objects,
	};

	if (!config_objects) {
		return;
	}

	ao2_callback(config_objects, OBJ_NODATA | OBJ_MULTIPLE, sorcery_config_fields_cmp, &params);
}

static void sorcery_config_retrieve_regex(const struct ast_sorcery *sorcery, void *data, const char *type, struct ao2_container *objects, const char *regex)
{
	struct sorcery_config *config = data;
	RAII_VAR(struct ao2_container *, config_objects, ao2_global_obj_ref(config->objects), ao2_cleanup);
	regex_t expression;
	struct sorcery_config_fields_cmp_params params = {
		.sorcery = sorcery,
		.container = objects,
		.regex = &expression,
	};

	if (ast_strlen_zero(regex)) {
		regex = ".";
	}

	if (!config_objects || regcomp(&expression, regex, REG_EXTENDED | REG_NOSUB)) {
		return;
	}

	ao2_callback(config_objects, OBJ_NODATA | OBJ_MULTIPLE, sorcery_config_fields_cmp, &params);
	regfree(&expression);
}

static void sorcery_config_retrieve_prefix(const struct ast_sorcery *sorcery, void *data, const char *type, struct ao2_container *objects, const char *prefix, const size_t prefix_len)
{
	struct sorcery_config *config = data;
	RAII_VAR(struct ao2_container *, config_objects, ao2_global_obj_ref(config->objects), ao2_cleanup);
	struct sorcery_config_fields_cmp_params params = {
		.sorcery = sorcery,
		.container = objects,
		.prefix = prefix,
		.prefix_len = prefix_len,
	};

	if (!config_objects) {
		return;
	}

	ao2_callback(config_objects, OBJ_NODATA | OBJ_MULTIPLE, sorcery_config_fields_cmp, &params);
}

/*! \brief Internal function which determines if a category matches based on explicit name */
static int sorcery_is_explicit_name_met(const struct ast_sorcery *sorcery, const char *type,
	struct ast_category *category, struct sorcery_config *config)
{
	struct ast_sorcery_object_type *object_type;
	struct ast_variable *field;
	int met = 1;

	if (ast_strlen_zero(config->explicit_name) || strcmp(ast_category_get_name(category), config->explicit_name)) {
		return 0;
	}

	object_type = ast_sorcery_get_object_type(sorcery, type);
	if (!object_type) {
		return 0;
	}

	/* We iterate the configured fields to see if we don't know any, if we don't then
	 * this is likely not for the given type and we skip it. If it actually is then criteria
	 * may pick it up in which case it would just get rejected as an invalid configuration later.
	 */
	for (field = ast_category_first(category); field; field = field->next) {
		if (!ast_sorcery_is_object_field_registered(object_type, field->name)) {
			met = 0;
			break;
		}
	}

	ao2_ref(object_type, -1);

	return met;
}

/*! \brief Internal function which determines if a category matches based on criteria */
static int sorcery_is_criteria_met(struct ast_category *category, struct sorcery_config *config)
{
	RAII_VAR(struct ast_variable *, diff, NULL, ast_variables_destroy);

	if (!config->criteria) {
		return 0;
	}

	return (!ast_sorcery_changeset_create(ast_category_first(category), config->criteria, &diff) && !diff) ? 1 : 0;
}

/*! \brief Internal function which determines if criteria has been met for considering an object set applicable */
static int sorcery_is_configuration_met(const struct ast_sorcery *sorcery, const char *type,
	struct ast_category *category, struct sorcery_config *config)
{
	if (!config->criteria && ast_strlen_zero(config->explicit_name)) {
		/* Nothing is configured to allow specific matching, so accept it! */
		return 1;
	} else if (sorcery_is_explicit_name_met(sorcery, type, category, config)) {
		return 1;
	} else if (sorcery_is_criteria_met(category, config)) {
		return 1;
	} else {
		/* Nothing explicitly matched so reject */
		return 0;
	}
}

static void sorcery_config_internal_load(void *data, const struct ast_sorcery *sorcery, const char *type, unsigned int reload)
{
	struct sorcery_config *config = data;
	struct ast_flags flags = { reload && !config->configuration_invalid && !config->has_dynamic_contents ? CONFIG_FLAG_FILEUNCHANGED : 0 };
	struct ast_config *cfg = ast_config_load2(config->filename, config->uuid, flags);
	struct ast_category *category = NULL;
	RAII_VAR(struct ao2_container *, objects, NULL, ao2_cleanup);
	const char *id = NULL;
	unsigned int buckets = 0;
	unsigned int has_dynamic_contents = 0;

	if (!cfg) {
		ast_log_chan(NULL, LOG_ERROR, "Unable to load config file '%s'\n", config->filename);
		return;
	} else if (cfg == CONFIG_STATUS_FILEUNCHANGED) {
		ast_debug(1, "Config file '%s' was unchanged\n", config->filename);
		return;
	} else if (cfg == CONFIG_STATUS_FILEINVALID) {
		ast_log_chan(NULL, LOG_ERROR, "Contents of config file '%s' are invalid and cannot be parsed\n", config->filename);
		return;
	}

	/* When parsing the configuration assume it is valid until proven otherwise */
	config->configuration_invalid = 0;

	if (!config->buckets) {
		while ((category = ast_category_browse_filtered(cfg, NULL, category, NULL))) {

			/* If given configuration has not been met skip the category, it is not applicable */
			if (!sorcery_is_configuration_met(sorcery, type, category, config)) {
				continue;
			}

			buckets++;
		}

		/* Determine the optimal number of buckets */
		while (buckets && !ast_is_prime(buckets)) {
			/* This purposely goes backwards to ensure that the container doesn't have a ton of
			 * empty buckets for objects that will never get added.
			 */
			buckets--;
		}

		if (!buckets) {
			buckets = 1;
		}
	} else {
		buckets = config->buckets;
	}

	/* For single object configurations there can only ever be one bucket, if there's more than the single
	 * object requirement has been violated.
	 */
	if (config->single_object && buckets > 1) {
		ast_log_chan(NULL, LOG_ERROR, "Config file '%s' could not be loaded; configuration contains more than one object of type '%s'\n",
			config->filename, type);
		ast_config_destroy(cfg);
		config->configuration_invalid = 1;
		return;
	}

	ast_debug(2, "Using bucket size of '%d' for objects of type '%s' from '%s'\n",
		buckets, type, config->filename);

	objects = ao2_container_alloc_hash(AO2_ALLOC_OPT_LOCK_NOLOCK, 0, buckets,
		ast_sorcery_object_id_hash, NULL, ast_sorcery_object_id_compare);
	if (!objects) {
		ast_log_chan(NULL, LOG_ERROR, "Could not create bucket for new objects from '%s', keeping existing objects\n",
			config->filename);
		ast_config_destroy(cfg);
		config->configuration_invalid = 1; /* Not strictly invalid but we want to try next time */
		return;
	}

	while ((category = ast_category_browse_filtered(cfg, NULL, category, NULL))) {
		RAII_VAR(void *, obj, NULL, ao2_cleanup);
		id = ast_category_get_name(category);

		/* If given configuration has not been met skip the category, it is not applicable */
		if (!sorcery_is_configuration_met(sorcery, type, category, config)) {
			continue;
		}

		/*  Confirm an object with this id does not already exist in the bucket.
		 *  If it exists, however, the configuration is invalid so stop
		 *  processing and destroy it. */
		obj = ao2_find(objects, id, OBJ_SEARCH_KEY);
		if (obj) {
			ast_log_chan(NULL, LOG_ERROR, "Config file '%s' could not be loaded; configuration contains a duplicate object: '%s' of type '%s'\n",
				config->filename, id, type);
			ast_config_destroy(cfg);
			config->configuration_invalid = 1;
			return;
		}

		if (!(obj = ast_sorcery_alloc(sorcery, type, id)) ||
		    ast_sorcery_objectset_apply(sorcery, obj, ast_category_first(category))) {

			if (config->file_integrity) {
				ast_log_chan(NULL, LOG_ERROR, "Config file '%s' could not be loaded due to error with object '%s' of type '%s'\n",
					config->filename, id, type);
				ast_config_destroy(cfg);
				config->configuration_invalid = 1;
				return;
			} else {
				ast_log_chan(NULL, LOG_ERROR, "Could not create an object of type '%s' with id '%s' from configuration file '%s'\n",
					type, id, config->filename);
				config->configuration_invalid = 1;
			}

			ao2_cleanup(obj);

			/* To ensure we don't lose the object that already exists we retrieve it from the old objects container and add it to the new one */
			if (!(obj = sorcery_config_retrieve_id(sorcery, data, type, id))) {
				continue;
			}

			ast_log_chan(NULL, LOG_NOTICE, "Retaining existing configuration for object of type '%s' with id '%s'\n", type, id);
		}

		/* We store the dynamic contents state until the end in case this reload or load
		 * gets rolled back.
		 */
		has_dynamic_contents |= ast_sorcery_object_has_dynamic_contents(obj);

		ao2_link(objects, obj);
	}

	config->has_dynamic_contents = has_dynamic_contents;
	ao2_global_obj_replace_unref(config->objects, objects);
	ast_config_destroy(cfg);
}

static void sorcery_config_load(void *data, const struct ast_sorcery *sorcery, const char *type)
{
	sorcery_config_internal_load(data, sorcery, type, 0);
}

static void sorcery_config_reload(void *data, const struct ast_sorcery *sorcery, const char *type)
{
	sorcery_config_internal_load(data, sorcery, type, 1);
}

static void *sorcery_config_open(const char *data)
{
	char *tmp;
	char *filename;
	char *option;
	struct sorcery_config *config;

	if (ast_strlen_zero(data)) {
		return NULL;
	}

 	tmp = ast_strdupa(data);
 	filename = strsep(&tmp, ",");

	if (ast_strlen_zero(filename) || !(config = ao2_alloc_options(sizeof(*config) + strlen(filename) + 1, sorcery_config_destructor, AO2_ALLOC_OPT_LOCK_NOLOCK))) {
		return NULL;
	}

	ast_uuid_generate_str(config->uuid, sizeof(config->uuid));

	ast_rwlock_init(&config->objects.lock);
	strcpy(config->filename, filename);

	while ((option = strsep(&tmp, ","))) {
		char *name = strsep(&option, "="), *value = option;

		if (!strcasecmp(name, "buckets")) {
			if (sscanf(value, "%30u", &config->buckets) != 1) {
				ast_log_chan(NULL, LOG_ERROR, "Unsupported bucket size of '%s' used for configuration file '%s', defaulting to automatic determination\n",
					value, filename);
			}
		} else if (!strcasecmp(name, "integrity")) {
			if (!strcasecmp(value, "file")) {
				config->file_integrity = 1;
			} else if (!strcasecmp(value, "object")) {
				config->file_integrity = 0;
			} else {
				ast_log_chan(NULL, LOG_ERROR, "Unsupported integrity value of '%s' used for configuration file '%s', defaulting to 'object'\n",
					value, filename);
			}
		} else if (!strcasecmp(name, "criteria")) {
			char *field = strsep(&value, "=");
			struct ast_variable *criteria = ast_variable_new(field, value, "");

			if (criteria) {
				criteria->next = config->criteria;
				config->criteria = criteria;
			} else {
				/* This is fatal since not following criteria would potentially yield invalid objects */
				ast_log_chan(NULL, LOG_ERROR, "Could not create criteria entry of field '%s' with value '%s' for configuration file '%s'\n",
					field, value, filename);
				ao2_ref(config, -1);
				return NULL;
			}
		} else if (!strcasecmp(name, "explicit_name")) {
			ast_free(config->explicit_name);
			config->explicit_name = ast_strdup(value);
			if (ast_strlen_zero(config->explicit_name)) {
				/* This is fatal since it could stop a configuration section from getting applied */
				ast_log_chan(NULL, LOG_ERROR, "Could not create explicit name entry of '%s' for configuration file '%s'\n",
					value, filename);
				ao2_ref(config, -1);
				return NULL;
			}
		} else if (!strcasecmp(name, "single_object")) {
			if (ast_strlen_zero(value)) {
				ast_log_chan(NULL, LOG_ERROR, "Could not set single object value for configuration file '%s' as the value is empty\n",
					filename);
				ao2_ref(config, -1);
				return NULL;
			}
			config->single_object = ast_true(value);
		} else {
			ast_log_chan(NULL, LOG_ERROR, "Unsupported option '%s' used for configuration file '%s'\n", name, filename);
		}
	}

	return config;
}

static void sorcery_config_close(void *data)
{
	struct sorcery_config *config = data;

	ao2_ref(config, -1);
}

static int load_module(void)
{
	if (ast_sorcery_wizard_register(&config_object_wizard)) {
		return AST_MODULE_LOAD_DECLINE;
	}

	return AST_MODULE_LOAD_SUCCESS;
}

static int unload_module(void)
{
	ast_sorcery_wizard_unregister(&config_object_wizard);
	return 0;
}

AST_MODULE_INFO(GABPBX_GPL_KEY, AST_MODFLAG_GLOBAL_SYMBOLS | AST_MODFLAG_LOAD_ORDER, "Sorcery Configuration File Object Wizard",
	.support_level = AST_MODULE_SUPPORT_CORE,
	.load = load_module,
	.unload = unload_module,
	.load_pri = AST_MODPRI_REALTIME_DRIVER,
);
