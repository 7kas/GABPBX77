/*
 * GABpbx -- An open source telephony toolkit.
 *
 * Copyright (C) 2012 - 2013, Digium, Inc.
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

/*
 * !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
 * !!!!!                               DO NOT EDIT                        !!!!!
 * !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
 * This file is generated by a mustache template. Please see the original
 * template in rest-api-templates/res_ari_resource.c.mustache
 */

/*! \file
 *
 * \brief GABpbx resources
 *
 * \author David M. Lee, II <dlee@digium.com>
 */

/*** MODULEINFO
	<depend type="module">res_ari</depend>
	<depend type="module">res_ari_model</depend>
	<depend type="module">res_stasis</depend>
	<support_level>core</support_level>
 ***/

#include "gabpbx.h"

#include "gabpbx/app.h"
#include "gabpbx/module.h"
#include "gabpbx/stasis_app.h"
#include "ari/resource_gabpbx.h"
#if defined(AST_DEVMODE)
#include "ari/ari_model_validators.h"
#endif

#define MAX_VALS 128

/*!
 * \brief Parameter parsing callback for /gabpbx/config/dynamic/{configClass}/{objectType}/{id}.
 * \param ser TCP/TLS session object
 * \param get_params GET parameters in the HTTP request.
 * \param path_vars Path variables extracted from the request.
 * \param headers HTTP headers.
 * \param body
 * \param[out] response Response to the HTTP request.
 */
static void ast_ari_gabpbx_get_object_cb(
	struct ast_tcptls_session_instance *ser,
	struct ast_variable *get_params, struct ast_variable *path_vars,
	struct ast_variable *headers, struct ast_json *body, struct ast_ari_response *response)
{
	struct ast_ari_gabpbx_get_object_args args = {};
	struct ast_variable *i;
#if defined(AST_DEVMODE)
	int is_valid;
	int code;
#endif /* AST_DEVMODE */

	for (i = path_vars; i; i = i->next) {
		if (strcmp(i->name, "configClass") == 0) {
			args.config_class = (i->value);
		} else
		if (strcmp(i->name, "objectType") == 0) {
			args.object_type = (i->value);
		} else
		if (strcmp(i->name, "id") == 0) {
			args.id = (i->value);
		} else
		{}
	}
	ast_ari_gabpbx_get_object(headers, &args, response);
#if defined(AST_DEVMODE)
	code = response->response_code;

	switch (code) {
	case 0: /* Implementation is still a stub, or the code wasn't set */
		is_valid = response->message == NULL;
		break;
	case 500: /* Internal Server Error */
	case 501: /* Not Implemented */
	case 404: /* {configClass|objectType|id} not found */
		is_valid = 1;
		break;
	default:
		if (200 <= code && code <= 299) {
			is_valid = ast_ari_validate_list(response->message,
				ast_ari_validate_config_tuple_fn());
		} else {
			ast_log_chan(NULL, LOG_ERROR, "Invalid error response %d for /gabpbx/config/dynamic/{configClass}/{objectType}/{id}\n", code);
			is_valid = 0;
		}
	}

	if (!is_valid) {
		ast_log_chan(NULL, LOG_ERROR, "Response validation failed for /gabpbx/config/dynamic/{configClass}/{objectType}/{id}\n");
		ast_ari_response_error(response, 500,
			"Internal Server Error", "Response validation failed");
	}
#endif /* AST_DEVMODE */

fin: __attribute__((unused))
	return;
}
int ast_ari_gabpbx_update_object_parse_body(
	struct ast_json *body,
	struct ast_ari_gabpbx_update_object_args *args)
{
	/* Parse query parameters out of it */
	return 0;
}

/*!
 * \brief Parameter parsing callback for /gabpbx/config/dynamic/{configClass}/{objectType}/{id}.
 * \param ser TCP/TLS session object
 * \param get_params GET parameters in the HTTP request.
 * \param path_vars Path variables extracted from the request.
 * \param headers HTTP headers.
 * \param body
 * \param[out] response Response to the HTTP request.
 */
static void ast_ari_gabpbx_update_object_cb(
	struct ast_tcptls_session_instance *ser,
	struct ast_variable *get_params, struct ast_variable *path_vars,
	struct ast_variable *headers, struct ast_json *body, struct ast_ari_response *response)
{
	struct ast_ari_gabpbx_update_object_args args = {};
	struct ast_variable *i;
#if defined(AST_DEVMODE)
	int is_valid;
	int code;
#endif /* AST_DEVMODE */

	for (i = path_vars; i; i = i->next) {
		if (strcmp(i->name, "configClass") == 0) {
			args.config_class = (i->value);
		} else
		if (strcmp(i->name, "objectType") == 0) {
			args.object_type = (i->value);
		} else
		if (strcmp(i->name, "id") == 0) {
			args.id = (i->value);
		} else
		{}
	}
	args.fields = body;
	ast_ari_gabpbx_update_object(headers, &args, response);
#if defined(AST_DEVMODE)
	code = response->response_code;

	switch (code) {
	case 0: /* Implementation is still a stub, or the code wasn't set */
		is_valid = response->message == NULL;
		break;
	case 500: /* Internal Server Error */
	case 501: /* Not Implemented */
	case 400: /* Bad request body */
	case 403: /* Could not create or update object */
	case 404: /* {configClass|objectType} not found */
		is_valid = 1;
		break;
	default:
		if (200 <= code && code <= 299) {
			is_valid = ast_ari_validate_list(response->message,
				ast_ari_validate_config_tuple_fn());
		} else {
			ast_log_chan(NULL, LOG_ERROR, "Invalid error response %d for /gabpbx/config/dynamic/{configClass}/{objectType}/{id}\n", code);
			is_valid = 0;
		}
	}

	if (!is_valid) {
		ast_log_chan(NULL, LOG_ERROR, "Response validation failed for /gabpbx/config/dynamic/{configClass}/{objectType}/{id}\n");
		ast_ari_response_error(response, 500,
			"Internal Server Error", "Response validation failed");
	}
#endif /* AST_DEVMODE */

fin: __attribute__((unused))
	return;
}
/*!
 * \brief Parameter parsing callback for /gabpbx/config/dynamic/{configClass}/{objectType}/{id}.
 * \param ser TCP/TLS session object
 * \param get_params GET parameters in the HTTP request.
 * \param path_vars Path variables extracted from the request.
 * \param headers HTTP headers.
 * \param body
 * \param[out] response Response to the HTTP request.
 */
static void ast_ari_gabpbx_delete_object_cb(
	struct ast_tcptls_session_instance *ser,
	struct ast_variable *get_params, struct ast_variable *path_vars,
	struct ast_variable *headers, struct ast_json *body, struct ast_ari_response *response)
{
	struct ast_ari_gabpbx_delete_object_args args = {};
	struct ast_variable *i;
#if defined(AST_DEVMODE)
	int is_valid;
	int code;
#endif /* AST_DEVMODE */

	for (i = path_vars; i; i = i->next) {
		if (strcmp(i->name, "configClass") == 0) {
			args.config_class = (i->value);
		} else
		if (strcmp(i->name, "objectType") == 0) {
			args.object_type = (i->value);
		} else
		if (strcmp(i->name, "id") == 0) {
			args.id = (i->value);
		} else
		{}
	}
	ast_ari_gabpbx_delete_object(headers, &args, response);
#if defined(AST_DEVMODE)
	code = response->response_code;

	switch (code) {
	case 0: /* Implementation is still a stub, or the code wasn't set */
		is_valid = response->message == NULL;
		break;
	case 500: /* Internal Server Error */
	case 501: /* Not Implemented */
	case 403: /* Could not delete object */
	case 404: /* {configClass|objectType|id} not found */
		is_valid = 1;
		break;
	default:
		if (200 <= code && code <= 299) {
			is_valid = ast_ari_validate_void(
				response->message);
		} else {
			ast_log_chan(NULL, LOG_ERROR, "Invalid error response %d for /gabpbx/config/dynamic/{configClass}/{objectType}/{id}\n", code);
			is_valid = 0;
		}
	}

	if (!is_valid) {
		ast_log_chan(NULL, LOG_ERROR, "Response validation failed for /gabpbx/config/dynamic/{configClass}/{objectType}/{id}\n");
		ast_ari_response_error(response, 500,
			"Internal Server Error", "Response validation failed");
	}
#endif /* AST_DEVMODE */

fin: __attribute__((unused))
	return;
}
int ast_ari_gabpbx_get_info_parse_body(
	struct ast_json *body,
	struct ast_ari_gabpbx_get_info_args *args)
{
	struct ast_json *field;
	/* Parse query parameters out of it */
	field = ast_json_object_get(body, "only");
	if (field) {
		/* If they were silly enough to both pass in a query param and a
		 * JSON body, free up the query value.
		 */
		ast_free(args->only);
		if (ast_json_typeof(field) == AST_JSON_ARRAY) {
			/* Multiple param passed as array */
			size_t i;
			args->only_count = ast_json_array_size(field);
			args->only = ast_malloc(sizeof(*args->only) * args->only_count);

			if (!args->only) {
				return -1;
			}

			for (i = 0; i < args->only_count; ++i) {
				args->only[i] = ast_json_string_get(ast_json_array_get(field, i));
			}
		} else {
			/* Multiple param passed as single value */
			args->only_count = 1;
			args->only = ast_malloc(sizeof(*args->only) * args->only_count);
			if (!args->only) {
				return -1;
			}
			args->only[0] = ast_json_string_get(field);
		}
	}
	return 0;
}

/*!
 * \brief Parameter parsing callback for /gabpbx/info.
 * \param ser TCP/TLS session object
 * \param get_params GET parameters in the HTTP request.
 * \param path_vars Path variables extracted from the request.
 * \param headers HTTP headers.
 * \param body
 * \param[out] response Response to the HTTP request.
 */
static void ast_ari_gabpbx_get_info_cb(
	struct ast_tcptls_session_instance *ser,
	struct ast_variable *get_params, struct ast_variable *path_vars,
	struct ast_variable *headers, struct ast_json *body, struct ast_ari_response *response)
{
	struct ast_ari_gabpbx_get_info_args args = {};
	struct ast_variable *i;
#if defined(AST_DEVMODE)
	int is_valid;
	int code;
#endif /* AST_DEVMODE */

	for (i = get_params; i; i = i->next) {
		if (strcmp(i->name, "only") == 0) {
			/* Parse comma separated list */
			char *vals[MAX_VALS];
			size_t j;

			args.only_parse = ast_strdup(i->value);
			if (!args.only_parse) {
				ast_ari_response_alloc_failed(response);
				goto fin;
			}

			if (strlen(args.only_parse) == 0) {
				/* ast_app_separate_args can't handle "" */
				args.only_count = 1;
				vals[0] = args.only_parse;
			} else {
				args.only_count = ast_app_separate_args(
					args.only_parse, ',', vals,
					ARRAY_LEN(vals));
			}

			if (args.only_count == 0) {
				ast_ari_response_alloc_failed(response);
				goto fin;
			}

			if (args.only_count >= MAX_VALS) {
				ast_ari_response_error(response, 400,
					"Bad Request",
					"Too many values for only");
				goto fin;
			}

			args.only = ast_malloc(sizeof(*args.only) * args.only_count);
			if (!args.only) {
				ast_ari_response_alloc_failed(response);
				goto fin;
			}

			for (j = 0; j < args.only_count; ++j) {
				args.only[j] = (vals[j]);
			}
		} else
		{}
	}
	if (ast_ari_gabpbx_get_info_parse_body(body, &args)) {
		ast_ari_response_alloc_failed(response);
		goto fin;
	}
	ast_ari_gabpbx_get_info(headers, &args, response);
#if defined(AST_DEVMODE)
	code = response->response_code;

	switch (code) {
	case 0: /* Implementation is still a stub, or the code wasn't set */
		is_valid = response->message == NULL;
		break;
	case 500: /* Internal Server Error */
	case 501: /* Not Implemented */
		is_valid = 1;
		break;
	default:
		if (200 <= code && code <= 299) {
			is_valid = ast_ari_validate_gabpbx_info(
				response->message);
		} else {
			ast_log_chan(NULL, LOG_ERROR, "Invalid error response %d for /gabpbx/info\n", code);
			is_valid = 0;
		}
	}

	if (!is_valid) {
		ast_log_chan(NULL, LOG_ERROR, "Response validation failed for /gabpbx/info\n");
		ast_ari_response_error(response, 500,
			"Internal Server Error", "Response validation failed");
	}
#endif /* AST_DEVMODE */

fin: __attribute__((unused))
	ast_free(args.only_parse);
	ast_free(args.only);
	return;
}
/*!
 * \brief Parameter parsing callback for /gabpbx/ping.
 * \param ser TCP/TLS session object
 * \param get_params GET parameters in the HTTP request.
 * \param path_vars Path variables extracted from the request.
 * \param headers HTTP headers.
 * \param body
 * \param[out] response Response to the HTTP request.
 */
static void ast_ari_gabpbx_ping_cb(
	struct ast_tcptls_session_instance *ser,
	struct ast_variable *get_params, struct ast_variable *path_vars,
	struct ast_variable *headers, struct ast_json *body, struct ast_ari_response *response)
{
	struct ast_ari_gabpbx_ping_args args = {};
#if defined(AST_DEVMODE)
	int is_valid;
	int code;
#endif /* AST_DEVMODE */

	ast_ari_gabpbx_ping(headers, &args, response);
#if defined(AST_DEVMODE)
	code = response->response_code;

	switch (code) {
	case 0: /* Implementation is still a stub, or the code wasn't set */
		is_valid = response->message == NULL;
		break;
	case 500: /* Internal Server Error */
	case 501: /* Not Implemented */
		is_valid = 1;
		break;
	default:
		if (200 <= code && code <= 299) {
			is_valid = ast_ari_validate_gabpbx_ping(
				response->message);
		} else {
			ast_log_chan(NULL, LOG_ERROR, "Invalid error response %d for /gabpbx/ping\n", code);
			is_valid = 0;
		}
	}

	if (!is_valid) {
		ast_log_chan(NULL, LOG_ERROR, "Response validation failed for /gabpbx/ping\n");
		ast_ari_response_error(response, 500,
			"Internal Server Error", "Response validation failed");
	}
#endif /* AST_DEVMODE */

fin: __attribute__((unused))
	return;
}
/*!
 * \brief Parameter parsing callback for /gabpbx/modules.
 * \param ser TCP/TLS session object
 * \param get_params GET parameters in the HTTP request.
 * \param path_vars Path variables extracted from the request.
 * \param headers HTTP headers.
 * \param body
 * \param[out] response Response to the HTTP request.
 */
static void ast_ari_gabpbx_list_modules_cb(
	struct ast_tcptls_session_instance *ser,
	struct ast_variable *get_params, struct ast_variable *path_vars,
	struct ast_variable *headers, struct ast_json *body, struct ast_ari_response *response)
{
	struct ast_ari_gabpbx_list_modules_args args = {};
#if defined(AST_DEVMODE)
	int is_valid;
	int code;
#endif /* AST_DEVMODE */

	ast_ari_gabpbx_list_modules(headers, &args, response);
#if defined(AST_DEVMODE)
	code = response->response_code;

	switch (code) {
	case 0: /* Implementation is still a stub, or the code wasn't set */
		is_valid = response->message == NULL;
		break;
	case 500: /* Internal Server Error */
	case 501: /* Not Implemented */
		is_valid = 1;
		break;
	default:
		if (200 <= code && code <= 299) {
			is_valid = ast_ari_validate_list(response->message,
				ast_ari_validate_module_fn());
		} else {
			ast_log_chan(NULL, LOG_ERROR, "Invalid error response %d for /gabpbx/modules\n", code);
			is_valid = 0;
		}
	}

	if (!is_valid) {
		ast_log_chan(NULL, LOG_ERROR, "Response validation failed for /gabpbx/modules\n");
		ast_ari_response_error(response, 500,
			"Internal Server Error", "Response validation failed");
	}
#endif /* AST_DEVMODE */

fin: __attribute__((unused))
	return;
}
/*!
 * \brief Parameter parsing callback for /gabpbx/modules/{moduleName}.
 * \param ser TCP/TLS session object
 * \param get_params GET parameters in the HTTP request.
 * \param path_vars Path variables extracted from the request.
 * \param headers HTTP headers.
 * \param body
 * \param[out] response Response to the HTTP request.
 */
static void ast_ari_gabpbx_get_module_cb(
	struct ast_tcptls_session_instance *ser,
	struct ast_variable *get_params, struct ast_variable *path_vars,
	struct ast_variable *headers, struct ast_json *body, struct ast_ari_response *response)
{
	struct ast_ari_gabpbx_get_module_args args = {};
	struct ast_variable *i;
#if defined(AST_DEVMODE)
	int is_valid;
	int code;
#endif /* AST_DEVMODE */

	for (i = path_vars; i; i = i->next) {
		if (strcmp(i->name, "moduleName") == 0) {
			args.module_name = (i->value);
		} else
		{}
	}
	ast_ari_gabpbx_get_module(headers, &args, response);
#if defined(AST_DEVMODE)
	code = response->response_code;

	switch (code) {
	case 0: /* Implementation is still a stub, or the code wasn't set */
		is_valid = response->message == NULL;
		break;
	case 500: /* Internal Server Error */
	case 501: /* Not Implemented */
	case 404: /* Module could not be found in running modules. */
	case 409: /* Module information could not be retrieved. */
		is_valid = 1;
		break;
	default:
		if (200 <= code && code <= 299) {
			is_valid = ast_ari_validate_module(
				response->message);
		} else {
			ast_log_chan(NULL, LOG_ERROR, "Invalid error response %d for /gabpbx/modules/{moduleName}\n", code);
			is_valid = 0;
		}
	}

	if (!is_valid) {
		ast_log_chan(NULL, LOG_ERROR, "Response validation failed for /gabpbx/modules/{moduleName}\n");
		ast_ari_response_error(response, 500,
			"Internal Server Error", "Response validation failed");
	}
#endif /* AST_DEVMODE */

fin: __attribute__((unused))
	return;
}
/*!
 * \brief Parameter parsing callback for /gabpbx/modules/{moduleName}.
 * \param ser TCP/TLS session object
 * \param get_params GET parameters in the HTTP request.
 * \param path_vars Path variables extracted from the request.
 * \param headers HTTP headers.
 * \param body
 * \param[out] response Response to the HTTP request.
 */
static void ast_ari_gabpbx_load_module_cb(
	struct ast_tcptls_session_instance *ser,
	struct ast_variable *get_params, struct ast_variable *path_vars,
	struct ast_variable *headers, struct ast_json *body, struct ast_ari_response *response)
{
	struct ast_ari_gabpbx_load_module_args args = {};
	struct ast_variable *i;
#if defined(AST_DEVMODE)
	int is_valid;
	int code;
#endif /* AST_DEVMODE */

	for (i = path_vars; i; i = i->next) {
		if (strcmp(i->name, "moduleName") == 0) {
			args.module_name = (i->value);
		} else
		{}
	}
	ast_ari_gabpbx_load_module(headers, &args, response);
#if defined(AST_DEVMODE)
	code = response->response_code;

	switch (code) {
	case 0: /* Implementation is still a stub, or the code wasn't set */
		is_valid = response->message == NULL;
		break;
	case 500: /* Internal Server Error */
	case 501: /* Not Implemented */
	case 409: /* Module could not be loaded. */
		is_valid = 1;
		break;
	default:
		if (200 <= code && code <= 299) {
			is_valid = ast_ari_validate_void(
				response->message);
		} else {
			ast_log_chan(NULL, LOG_ERROR, "Invalid error response %d for /gabpbx/modules/{moduleName}\n", code);
			is_valid = 0;
		}
	}

	if (!is_valid) {
		ast_log_chan(NULL, LOG_ERROR, "Response validation failed for /gabpbx/modules/{moduleName}\n");
		ast_ari_response_error(response, 500,
			"Internal Server Error", "Response validation failed");
	}
#endif /* AST_DEVMODE */

fin: __attribute__((unused))
	return;
}
/*!
 * \brief Parameter parsing callback for /gabpbx/modules/{moduleName}.
 * \param ser TCP/TLS session object
 * \param get_params GET parameters in the HTTP request.
 * \param path_vars Path variables extracted from the request.
 * \param headers HTTP headers.
 * \param body
 * \param[out] response Response to the HTTP request.
 */
static void ast_ari_gabpbx_unload_module_cb(
	struct ast_tcptls_session_instance *ser,
	struct ast_variable *get_params, struct ast_variable *path_vars,
	struct ast_variable *headers, struct ast_json *body, struct ast_ari_response *response)
{
	struct ast_ari_gabpbx_unload_module_args args = {};
	struct ast_variable *i;
#if defined(AST_DEVMODE)
	int is_valid;
	int code;
#endif /* AST_DEVMODE */

	for (i = path_vars; i; i = i->next) {
		if (strcmp(i->name, "moduleName") == 0) {
			args.module_name = (i->value);
		} else
		{}
	}
	ast_ari_gabpbx_unload_module(headers, &args, response);
#if defined(AST_DEVMODE)
	code = response->response_code;

	switch (code) {
	case 0: /* Implementation is still a stub, or the code wasn't set */
		is_valid = response->message == NULL;
		break;
	case 500: /* Internal Server Error */
	case 501: /* Not Implemented */
	case 404: /* Module not found in running modules. */
	case 409: /* Module could not be unloaded. */
		is_valid = 1;
		break;
	default:
		if (200 <= code && code <= 299) {
			is_valid = ast_ari_validate_void(
				response->message);
		} else {
			ast_log_chan(NULL, LOG_ERROR, "Invalid error response %d for /gabpbx/modules/{moduleName}\n", code);
			is_valid = 0;
		}
	}

	if (!is_valid) {
		ast_log_chan(NULL, LOG_ERROR, "Response validation failed for /gabpbx/modules/{moduleName}\n");
		ast_ari_response_error(response, 500,
			"Internal Server Error", "Response validation failed");
	}
#endif /* AST_DEVMODE */

fin: __attribute__((unused))
	return;
}
/*!
 * \brief Parameter parsing callback for /gabpbx/modules/{moduleName}.
 * \param ser TCP/TLS session object
 * \param get_params GET parameters in the HTTP request.
 * \param path_vars Path variables extracted from the request.
 * \param headers HTTP headers.
 * \param body
 * \param[out] response Response to the HTTP request.
 */
static void ast_ari_gabpbx_reload_module_cb(
	struct ast_tcptls_session_instance *ser,
	struct ast_variable *get_params, struct ast_variable *path_vars,
	struct ast_variable *headers, struct ast_json *body, struct ast_ari_response *response)
{
	struct ast_ari_gabpbx_reload_module_args args = {};
	struct ast_variable *i;
#if defined(AST_DEVMODE)
	int is_valid;
	int code;
#endif /* AST_DEVMODE */

	for (i = path_vars; i; i = i->next) {
		if (strcmp(i->name, "moduleName") == 0) {
			args.module_name = (i->value);
		} else
		{}
	}
	ast_ari_gabpbx_reload_module(headers, &args, response);
#if defined(AST_DEVMODE)
	code = response->response_code;

	switch (code) {
	case 0: /* Implementation is still a stub, or the code wasn't set */
		is_valid = response->message == NULL;
		break;
	case 500: /* Internal Server Error */
	case 501: /* Not Implemented */
	case 404: /* Module not found in running modules. */
	case 409: /* Module could not be reloaded. */
		is_valid = 1;
		break;
	default:
		if (200 <= code && code <= 299) {
			is_valid = ast_ari_validate_void(
				response->message);
		} else {
			ast_log_chan(NULL, LOG_ERROR, "Invalid error response %d for /gabpbx/modules/{moduleName}\n", code);
			is_valid = 0;
		}
	}

	if (!is_valid) {
		ast_log_chan(NULL, LOG_ERROR, "Response validation failed for /gabpbx/modules/{moduleName}\n");
		ast_ari_response_error(response, 500,
			"Internal Server Error", "Response validation failed");
	}
#endif /* AST_DEVMODE */

fin: __attribute__((unused))
	return;
}
/*!
 * \brief Parameter parsing callback for /gabpbx/logging.
 * \param ser TCP/TLS session object
 * \param get_params GET parameters in the HTTP request.
 * \param path_vars Path variables extracted from the request.
 * \param headers HTTP headers.
 * \param body
 * \param[out] response Response to the HTTP request.
 */
static void ast_ari_gabpbx_list_log_channels_cb(
	struct ast_tcptls_session_instance *ser,
	struct ast_variable *get_params, struct ast_variable *path_vars,
	struct ast_variable *headers, struct ast_json *body, struct ast_ari_response *response)
{
	struct ast_ari_gabpbx_list_log_channels_args args = {};
#if defined(AST_DEVMODE)
	int is_valid;
	int code;
#endif /* AST_DEVMODE */

	ast_ari_gabpbx_list_log_channels(headers, &args, response);
#if defined(AST_DEVMODE)
	code = response->response_code;

	switch (code) {
	case 0: /* Implementation is still a stub, or the code wasn't set */
		is_valid = response->message == NULL;
		break;
	case 500: /* Internal Server Error */
	case 501: /* Not Implemented */
		is_valid = 1;
		break;
	default:
		if (200 <= code && code <= 299) {
			is_valid = ast_ari_validate_list(response->message,
				ast_ari_validate_log_channel_fn());
		} else {
			ast_log_chan(NULL, LOG_ERROR, "Invalid error response %d for /gabpbx/logging\n", code);
			is_valid = 0;
		}
	}

	if (!is_valid) {
		ast_log_chan(NULL, LOG_ERROR, "Response validation failed for /gabpbx/logging\n");
		ast_ari_response_error(response, 500,
			"Internal Server Error", "Response validation failed");
	}
#endif /* AST_DEVMODE */

fin: __attribute__((unused))
	return;
}
int ast_ari_gabpbx_add_log_parse_body(
	struct ast_json *body,
	struct ast_ari_gabpbx_add_log_args *args)
{
	struct ast_json *field;
	/* Parse query parameters out of it */
	field = ast_json_object_get(body, "configuration");
	if (field) {
		args->configuration = ast_json_string_get(field);
	}
	return 0;
}

/*!
 * \brief Parameter parsing callback for /gabpbx/logging/{logChannelName}.
 * \param ser TCP/TLS session object
 * \param get_params GET parameters in the HTTP request.
 * \param path_vars Path variables extracted from the request.
 * \param headers HTTP headers.
 * \param body
 * \param[out] response Response to the HTTP request.
 */
static void ast_ari_gabpbx_add_log_cb(
	struct ast_tcptls_session_instance *ser,
	struct ast_variable *get_params, struct ast_variable *path_vars,
	struct ast_variable *headers, struct ast_json *body, struct ast_ari_response *response)
{
	struct ast_ari_gabpbx_add_log_args args = {};
	struct ast_variable *i;
#if defined(AST_DEVMODE)
	int is_valid;
	int code;
#endif /* AST_DEVMODE */

	for (i = get_params; i; i = i->next) {
		if (strcmp(i->name, "configuration") == 0) {
			args.configuration = (i->value);
		} else
		{}
	}
	for (i = path_vars; i; i = i->next) {
		if (strcmp(i->name, "logChannelName") == 0) {
			args.log_channel_name = (i->value);
		} else
		{}
	}
	if (ast_ari_gabpbx_add_log_parse_body(body, &args)) {
		ast_ari_response_alloc_failed(response);
		goto fin;
	}
	ast_ari_gabpbx_add_log(headers, &args, response);
#if defined(AST_DEVMODE)
	code = response->response_code;

	switch (code) {
	case 0: /* Implementation is still a stub, or the code wasn't set */
		is_valid = response->message == NULL;
		break;
	case 500: /* Internal Server Error */
	case 501: /* Not Implemented */
	case 400: /* Bad request body */
	case 409: /* Log channel could not be created. */
		is_valid = 1;
		break;
	default:
		if (200 <= code && code <= 299) {
			is_valid = ast_ari_validate_void(
				response->message);
		} else {
			ast_log_chan(NULL, LOG_ERROR, "Invalid error response %d for /gabpbx/logging/{logChannelName}\n", code);
			is_valid = 0;
		}
	}

	if (!is_valid) {
		ast_log_chan(NULL, LOG_ERROR, "Response validation failed for /gabpbx/logging/{logChannelName}\n");
		ast_ari_response_error(response, 500,
			"Internal Server Error", "Response validation failed");
	}
#endif /* AST_DEVMODE */

fin: __attribute__((unused))
	return;
}
/*!
 * \brief Parameter parsing callback for /gabpbx/logging/{logChannelName}.
 * \param ser TCP/TLS session object
 * \param get_params GET parameters in the HTTP request.
 * \param path_vars Path variables extracted from the request.
 * \param headers HTTP headers.
 * \param body
 * \param[out] response Response to the HTTP request.
 */
static void ast_ari_gabpbx_delete_log_cb(
	struct ast_tcptls_session_instance *ser,
	struct ast_variable *get_params, struct ast_variable *path_vars,
	struct ast_variable *headers, struct ast_json *body, struct ast_ari_response *response)
{
	struct ast_ari_gabpbx_delete_log_args args = {};
	struct ast_variable *i;
#if defined(AST_DEVMODE)
	int is_valid;
	int code;
#endif /* AST_DEVMODE */

	for (i = path_vars; i; i = i->next) {
		if (strcmp(i->name, "logChannelName") == 0) {
			args.log_channel_name = (i->value);
		} else
		{}
	}
	ast_ari_gabpbx_delete_log(headers, &args, response);
#if defined(AST_DEVMODE)
	code = response->response_code;

	switch (code) {
	case 0: /* Implementation is still a stub, or the code wasn't set */
		is_valid = response->message == NULL;
		break;
	case 500: /* Internal Server Error */
	case 501: /* Not Implemented */
	case 404: /* Log channel does not exist. */
		is_valid = 1;
		break;
	default:
		if (200 <= code && code <= 299) {
			is_valid = ast_ari_validate_void(
				response->message);
		} else {
			ast_log_chan(NULL, LOG_ERROR, "Invalid error response %d for /gabpbx/logging/{logChannelName}\n", code);
			is_valid = 0;
		}
	}

	if (!is_valid) {
		ast_log_chan(NULL, LOG_ERROR, "Response validation failed for /gabpbx/logging/{logChannelName}\n");
		ast_ari_response_error(response, 500,
			"Internal Server Error", "Response validation failed");
	}
#endif /* AST_DEVMODE */

fin: __attribute__((unused))
	return;
}
/*!
 * \brief Parameter parsing callback for /gabpbx/logging/{logChannelName}/rotate.
 * \param ser TCP/TLS session object
 * \param get_params GET parameters in the HTTP request.
 * \param path_vars Path variables extracted from the request.
 * \param headers HTTP headers.
 * \param body
 * \param[out] response Response to the HTTP request.
 */
static void ast_ari_gabpbx_rotate_log_cb(
	struct ast_tcptls_session_instance *ser,
	struct ast_variable *get_params, struct ast_variable *path_vars,
	struct ast_variable *headers, struct ast_json *body, struct ast_ari_response *response)
{
	struct ast_ari_gabpbx_rotate_log_args args = {};
	struct ast_variable *i;
#if defined(AST_DEVMODE)
	int is_valid;
	int code;
#endif /* AST_DEVMODE */

	for (i = path_vars; i; i = i->next) {
		if (strcmp(i->name, "logChannelName") == 0) {
			args.log_channel_name = (i->value);
		} else
		{}
	}
	ast_ari_gabpbx_rotate_log(headers, &args, response);
#if defined(AST_DEVMODE)
	code = response->response_code;

	switch (code) {
	case 0: /* Implementation is still a stub, or the code wasn't set */
		is_valid = response->message == NULL;
		break;
	case 500: /* Internal Server Error */
	case 501: /* Not Implemented */
	case 404: /* Log channel does not exist. */
		is_valid = 1;
		break;
	default:
		if (200 <= code && code <= 299) {
			is_valid = ast_ari_validate_void(
				response->message);
		} else {
			ast_log_chan(NULL, LOG_ERROR, "Invalid error response %d for /gabpbx/logging/{logChannelName}/rotate\n", code);
			is_valid = 0;
		}
	}

	if (!is_valid) {
		ast_log_chan(NULL, LOG_ERROR, "Response validation failed for /gabpbx/logging/{logChannelName}/rotate\n");
		ast_ari_response_error(response, 500,
			"Internal Server Error", "Response validation failed");
	}
#endif /* AST_DEVMODE */

fin: __attribute__((unused))
	return;
}
int ast_ari_gabpbx_get_global_var_parse_body(
	struct ast_json *body,
	struct ast_ari_gabpbx_get_global_var_args *args)
{
	struct ast_json *field;
	/* Parse query parameters out of it */
	field = ast_json_object_get(body, "variable");
	if (field) {
		args->variable = ast_json_string_get(field);
	}
	return 0;
}

/*!
 * \brief Parameter parsing callback for /gabpbx/variable.
 * \param ser TCP/TLS session object
 * \param get_params GET parameters in the HTTP request.
 * \param path_vars Path variables extracted from the request.
 * \param headers HTTP headers.
 * \param body
 * \param[out] response Response to the HTTP request.
 */
static void ast_ari_gabpbx_get_global_var_cb(
	struct ast_tcptls_session_instance *ser,
	struct ast_variable *get_params, struct ast_variable *path_vars,
	struct ast_variable *headers, struct ast_json *body, struct ast_ari_response *response)
{
	struct ast_ari_gabpbx_get_global_var_args args = {};
	struct ast_variable *i;
#if defined(AST_DEVMODE)
	int is_valid;
	int code;
#endif /* AST_DEVMODE */

	for (i = get_params; i; i = i->next) {
		if (strcmp(i->name, "variable") == 0) {
			args.variable = (i->value);
		} else
		{}
	}
	if (ast_ari_gabpbx_get_global_var_parse_body(body, &args)) {
		ast_ari_response_alloc_failed(response);
		goto fin;
	}
	ast_ari_gabpbx_get_global_var(headers, &args, response);
#if defined(AST_DEVMODE)
	code = response->response_code;

	switch (code) {
	case 0: /* Implementation is still a stub, or the code wasn't set */
		is_valid = response->message == NULL;
		break;
	case 500: /* Internal Server Error */
	case 501: /* Not Implemented */
	case 400: /* Missing variable parameter. */
		is_valid = 1;
		break;
	default:
		if (200 <= code && code <= 299) {
			is_valid = ast_ari_validate_variable(
				response->message);
		} else {
			ast_log_chan(NULL, LOG_ERROR, "Invalid error response %d for /gabpbx/variable\n", code);
			is_valid = 0;
		}
	}

	if (!is_valid) {
		ast_log_chan(NULL, LOG_ERROR, "Response validation failed for /gabpbx/variable\n");
		ast_ari_response_error(response, 500,
			"Internal Server Error", "Response validation failed");
	}
#endif /* AST_DEVMODE */

fin: __attribute__((unused))
	return;
}
int ast_ari_gabpbx_set_global_var_parse_body(
	struct ast_json *body,
	struct ast_ari_gabpbx_set_global_var_args *args)
{
	struct ast_json *field;
	/* Parse query parameters out of it */
	field = ast_json_object_get(body, "variable");
	if (field) {
		args->variable = ast_json_string_get(field);
	}
	field = ast_json_object_get(body, "value");
	if (field) {
		args->value = ast_json_string_get(field);
	}
	return 0;
}

/*!
 * \brief Parameter parsing callback for /gabpbx/variable.
 * \param ser TCP/TLS session object
 * \param get_params GET parameters in the HTTP request.
 * \param path_vars Path variables extracted from the request.
 * \param headers HTTP headers.
 * \param body
 * \param[out] response Response to the HTTP request.
 */
static void ast_ari_gabpbx_set_global_var_cb(
	struct ast_tcptls_session_instance *ser,
	struct ast_variable *get_params, struct ast_variable *path_vars,
	struct ast_variable *headers, struct ast_json *body, struct ast_ari_response *response)
{
	struct ast_ari_gabpbx_set_global_var_args args = {};
	struct ast_variable *i;
#if defined(AST_DEVMODE)
	int is_valid;
	int code;
#endif /* AST_DEVMODE */

	for (i = get_params; i; i = i->next) {
		if (strcmp(i->name, "variable") == 0) {
			args.variable = (i->value);
		} else
		if (strcmp(i->name, "value") == 0) {
			args.value = (i->value);
		} else
		{}
	}
	if (ast_ari_gabpbx_set_global_var_parse_body(body, &args)) {
		ast_ari_response_alloc_failed(response);
		goto fin;
	}
	ast_ari_gabpbx_set_global_var(headers, &args, response);
#if defined(AST_DEVMODE)
	code = response->response_code;

	switch (code) {
	case 0: /* Implementation is still a stub, or the code wasn't set */
		is_valid = response->message == NULL;
		break;
	case 500: /* Internal Server Error */
	case 501: /* Not Implemented */
	case 400: /* Missing variable parameter. */
		is_valid = 1;
		break;
	default:
		if (200 <= code && code <= 299) {
			is_valid = ast_ari_validate_void(
				response->message);
		} else {
			ast_log_chan(NULL, LOG_ERROR, "Invalid error response %d for /gabpbx/variable\n", code);
			is_valid = 0;
		}
	}

	if (!is_valid) {
		ast_log_chan(NULL, LOG_ERROR, "Response validation failed for /gabpbx/variable\n");
		ast_ari_response_error(response, 500,
			"Internal Server Error", "Response validation failed");
	}
#endif /* AST_DEVMODE */

fin: __attribute__((unused))
	return;
}

/*! \brief REST handler for /api-docs/gabpbx.json */
static struct stasis_rest_handlers gabpbx_config_dynamic_configClass_objectType_id = {
	.path_segment = "id",
	.is_wildcard = 1,
	.callbacks = {
		[AST_HTTP_GET] = ast_ari_gabpbx_get_object_cb,
		[AST_HTTP_PUT] = ast_ari_gabpbx_update_object_cb,
		[AST_HTTP_DELETE] = ast_ari_gabpbx_delete_object_cb,
	},
	.num_children = 0,
	.children = {  }
};
/*! \brief REST handler for /api-docs/gabpbx.json */
static struct stasis_rest_handlers gabpbx_config_dynamic_configClass_objectType = {
	.path_segment = "objectType",
	.is_wildcard = 1,
	.callbacks = {
	},
	.num_children = 1,
	.children = { &gabpbx_config_dynamic_configClass_objectType_id, }
};
/*! \brief REST handler for /api-docs/gabpbx.json */
static struct stasis_rest_handlers gabpbx_config_dynamic_configClass = {
	.path_segment = "configClass",
	.is_wildcard = 1,
	.callbacks = {
	},
	.num_children = 1,
	.children = { &gabpbx_config_dynamic_configClass_objectType, }
};
/*! \brief REST handler for /api-docs/gabpbx.json */
static struct stasis_rest_handlers gabpbx_config_dynamic = {
	.path_segment = "dynamic",
	.callbacks = {
	},
	.num_children = 1,
	.children = { &gabpbx_config_dynamic_configClass, }
};
/*! \brief REST handler for /api-docs/gabpbx.json */
static struct stasis_rest_handlers gabpbx_config = {
	.path_segment = "config",
	.callbacks = {
	},
	.num_children = 1,
	.children = { &gabpbx_config_dynamic, }
};
/*! \brief REST handler for /api-docs/gabpbx.json */
static struct stasis_rest_handlers gabpbx_info = {
	.path_segment = "info",
	.callbacks = {
		[AST_HTTP_GET] = ast_ari_gabpbx_get_info_cb,
	},
	.num_children = 0,
	.children = {  }
};
/*! \brief REST handler for /api-docs/gabpbx.json */
static struct stasis_rest_handlers gabpbx_ping = {
	.path_segment = "ping",
	.callbacks = {
		[AST_HTTP_GET] = ast_ari_gabpbx_ping_cb,
	},
	.num_children = 0,
	.children = {  }
};
/*! \brief REST handler for /api-docs/gabpbx.json */
static struct stasis_rest_handlers gabpbx_modules_moduleName = {
	.path_segment = "moduleName",
	.is_wildcard = 1,
	.callbacks = {
		[AST_HTTP_GET] = ast_ari_gabpbx_get_module_cb,
		[AST_HTTP_POST] = ast_ari_gabpbx_load_module_cb,
		[AST_HTTP_DELETE] = ast_ari_gabpbx_unload_module_cb,
		[AST_HTTP_PUT] = ast_ari_gabpbx_reload_module_cb,
	},
	.num_children = 0,
	.children = {  }
};
/*! \brief REST handler for /api-docs/gabpbx.json */
static struct stasis_rest_handlers gabpbx_modules = {
	.path_segment = "modules",
	.callbacks = {
		[AST_HTTP_GET] = ast_ari_gabpbx_list_modules_cb,
	},
	.num_children = 1,
	.children = { &gabpbx_modules_moduleName, }
};
/*! \brief REST handler for /api-docs/gabpbx.json */
static struct stasis_rest_handlers gabpbx_logging_logChannelName_rotate = {
	.path_segment = "rotate",
	.callbacks = {
		[AST_HTTP_PUT] = ast_ari_gabpbx_rotate_log_cb,
	},
	.num_children = 0,
	.children = {  }
};
/*! \brief REST handler for /api-docs/gabpbx.json */
static struct stasis_rest_handlers gabpbx_logging_logChannelName = {
	.path_segment = "logChannelName",
	.is_wildcard = 1,
	.callbacks = {
		[AST_HTTP_POST] = ast_ari_gabpbx_add_log_cb,
		[AST_HTTP_DELETE] = ast_ari_gabpbx_delete_log_cb,
	},
	.num_children = 1,
	.children = { &gabpbx_logging_logChannelName_rotate, }
};
/*! \brief REST handler for /api-docs/gabpbx.json */
static struct stasis_rest_handlers gabpbx_logging = {
	.path_segment = "logging",
	.callbacks = {
		[AST_HTTP_GET] = ast_ari_gabpbx_list_log_channels_cb,
	},
	.num_children = 1,
	.children = { &gabpbx_logging_logChannelName, }
};
/*! \brief REST handler for /api-docs/gabpbx.json */
static struct stasis_rest_handlers gabpbx_variable = {
	.path_segment = "variable",
	.callbacks = {
		[AST_HTTP_GET] = ast_ari_gabpbx_get_global_var_cb,
		[AST_HTTP_POST] = ast_ari_gabpbx_set_global_var_cb,
	},
	.num_children = 0,
	.children = {  }
};
/*! \brief REST handler for /api-docs/gabpbx.json */
static struct stasis_rest_handlers gabpbx = {
	.path_segment = "gabpbx",
	.callbacks = {
	},
	.num_children = 6,
	.children = { &gabpbx_config,&gabpbx_info,&gabpbx_ping,&gabpbx_modules,&gabpbx_logging,&gabpbx_variable, }
};

static int unload_module(void)
{
	ast_ari_remove_handler(&gabpbx);
	return 0;
}

static int load_module(void)
{
	int res = 0;


	res |= ast_ari_add_handler(&gabpbx);
	if (res) {
		unload_module();
		return AST_MODULE_LOAD_DECLINE;
	}

	return AST_MODULE_LOAD_SUCCESS;
}

AST_MODULE_INFO(GABPBX_GPL_KEY, AST_MODFLAG_DEFAULT, "RESTful API module - GABpbx resources",
	.support_level = AST_MODULE_SUPPORT_CORE,
	.load = load_module,
	.unload = unload_module,
	.requires = "res_ari,res_ari_model,res_stasis",
);
