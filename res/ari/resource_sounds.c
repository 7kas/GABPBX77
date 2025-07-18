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

/*! \file
 *
 * \brief /api-docs/sounds.{format} implementation- Sound resources
 *
 * \author David M. Lee, II <dlee@digium.com>
 */

#include "gabpbx.h"

#include "resource_sounds.h"
#include "gabpbx/media_index.h"
#include "gabpbx/sounds_index.h"
#include "gabpbx/format.h"
#include "gabpbx/format_cap.h"
#include "gabpbx/json.h"

/*! \brief arguments that are necessary for adding format/lang pairs */
struct lang_format_info {
	struct ast_json *format_list;	/*!< The embedded array to which format/lang pairs should be added */
	const char *filename;		/*!< Name of the file for which to add format/lang pairs */
	const char *format_filter;	/*!< Format filter provided in the request */
};

/*! \brief Add format/lang pairs to the array embedded in the sound object */
static int add_format_information_cb(void *obj, void *arg, void *data, int flags)
{
	char *language = obj;
	struct lang_format_info *args = arg;
	int idx;
	RAII_VAR(struct ast_format_cap *, cap, NULL, ao2_cleanup);
	struct ast_media_index *sounds_index = data;

	if (!sounds_index) {
		return CMP_STOP;
	}

	cap = ast_media_get_format_cap(sounds_index, args->filename, language);
	if (!cap) {
		return CMP_STOP;
	}

	for (idx = 0; idx < ast_format_cap_count(cap); idx++) {
		struct ast_format *format = ast_format_cap_get_format(cap, idx);
		struct ast_json *lang_format_pair;

		if (!ast_strlen_zero(args->format_filter)
			&& strcmp(args->format_filter, ast_format_get_name(format))) {
			ao2_ref(format, -1);
			continue;
		}

		lang_format_pair = ast_json_pack("{s: s, s: s}",
			"language", language,
			"format", ast_format_get_name(format));
		if (!lang_format_pair) {
			ao2_ref(format, -1);
			return CMP_STOP;
		}

		ast_json_array_append(args->format_list, lang_format_pair);
		ao2_ref(format, -1);
	}

	return 0;
}

/*! \brief Filter out all languages not matching the specified language */
static int filter_langs_cb(void *obj, void *arg, int flags)
{
	char *lang_filter = arg;
	char *lang = obj;
	if (strcmp(lang, lang_filter)) {
		return CMP_MATCH;
	}
	return 0;
}

/*! \brief Generate a Sound structure as documented in sounds.json for the specified filename */
static struct ast_json *create_sound_blob(const char *filename,
	struct ast_ari_sounds_list_args *args, struct ast_media_index *sounds_index)
{
	RAII_VAR(struct ast_json *, sound, NULL, ast_json_unref);
	RAII_VAR(struct ao2_container *, languages, NULL, ao2_cleanup);
	const char *description;
	struct ast_json *format_lang_list;
	struct lang_format_info info;

	if (!sounds_index) {
		return NULL;
	}

	description = ast_media_get_description(sounds_index, filename, "en");
	if (ast_strlen_zero(description)) {
		sound = ast_json_pack("{s: s, s: []}",
			"id", filename,
			"formats");
	} else {
		sound = ast_json_pack("{s: s, s: s, s: []}",
			"id", filename,
			"text", description,
			"formats");
	}
	if (!sound) {
		return NULL;
	}

	format_lang_list = ast_json_object_get(sound, "formats");
	if (!format_lang_list) {
		return NULL;
	}

	languages = ast_media_get_variants(sounds_index, filename);
	if (!languages || !ao2_container_count(languages)) {
		return NULL;
	}

	/* filter requested languages */
	if (args && !ast_strlen_zero(args->lang)) {
		char *lang_filter = ast_strdupa(args->lang);
		ao2_callback(languages, OBJ_NODATA | OBJ_MULTIPLE | OBJ_UNLINK, filter_langs_cb, lang_filter);
		if (!languages || !ao2_container_count(languages)) {
			return NULL;
		}
	}

	info.filename = filename;
	info.format_list = format_lang_list;
	info.format_filter = NULL;
	if (args) {
		info.format_filter = args->format;
	}
	ao2_callback_data(languages, OBJ_NODATA, add_format_information_cb, &info, sounds_index);

	/* no format/lang pairs for this sound so nothing to return */
	if (!ast_json_array_size(format_lang_list)) {
		return NULL;
	}

	return ast_json_ref(sound);
}

struct sounds_cb_data {
	struct ast_ari_sounds_list_args *args;
	struct ast_media_index *index;
};

/*! \brief Generate a Sound structure and append it to the output blob */
static int append_sound_cb(void *obj, void *arg, void *data, int flags)
{
	struct ast_json *sounds_array = arg;
	char *filename = obj;
	struct sounds_cb_data *cb_data = data;
	struct ast_json *sound_blob = create_sound_blob(filename, cb_data->args, cb_data->index);
	if (!sound_blob) {
		return 0;
	}

	ast_json_array_append(sounds_array, sound_blob);
	return 0;
}

void ast_ari_sounds_list(struct ast_variable *headers,
	struct ast_ari_sounds_list_args *args,
	struct ast_ari_response *response)
{
	RAII_VAR(struct ao2_container *, sound_files, NULL, ao2_cleanup);
	struct ast_json *sounds_blob;
	RAII_VAR(struct ast_media_index *, sounds_index, ast_sounds_get_index(), ao2_cleanup);
	struct sounds_cb_data cb_data = {
		.args = args,
		.index = sounds_index,
	};

	if (!sounds_index) {
		ast_ari_response_error(response, 500, "Internal Error", "Sounds index not available");
		return;
	}

	sound_files = ast_media_get_media(sounds_index);
	if (!sound_files) {
		ast_ari_response_error(response, 500, "Internal Error", "Allocation Error");
		return;
	}

	sounds_blob = ast_json_array_create();
	if (!sounds_blob) {
		ast_ari_response_error(response, 500, "Internal Error", "Allocation Error");
		return;
	}

	ao2_callback_data(sound_files, OBJ_NODATA, append_sound_cb, sounds_blob, &cb_data);

	if (!ast_json_array_size(sounds_blob)) {
		ast_ari_response_error(response, 404, "Not Found", "No sounds found that matched the query");
		ast_json_unref(sounds_blob);
		return;
	}

	ast_ari_response_ok(response, sounds_blob);
}

void ast_ari_sounds_get(struct ast_variable *headers,
	struct ast_ari_sounds_get_args *args,
	struct ast_ari_response *response)
{
	struct ast_json *sound_blob;
	struct ast_media_index *sounds_index = ast_sounds_get_index_for_file(args->sound_id);

	sound_blob = create_sound_blob(args->sound_id, NULL, sounds_index);
	ao2_cleanup(sounds_index);
	if (!sound_blob) {
		ast_ari_response_error(response, 404, "Not Found", "Sound not found");
		return;
	}

	ast_ari_response_ok(response, sound_blob);
}
