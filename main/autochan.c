/*
 * GABpbx -- An open source telephony toolkit.
 *
 * Copyright (C) 2009, Digium, Inc.
 *
 * Mark Michelson <mmichelson@digium.com>
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
 * \brief "smart" channels
 *
 * \author Mark Michelson <mmichelson@digium.com>
 */

/*** MODULEINFO
	<support_level>core</support_level>
 ***/

#include "gabpbx.h"

#include "gabpbx/autochan.h"
#include "gabpbx/utils.h"
#include "gabpbx/linkedlists.h"
#include "gabpbx/options.h"
#include "gabpbx/channel.h"

struct ast_autochan *ast_autochan_setup(struct ast_channel *chan)
{
	struct ast_autochan *autochan;

	if (!chan) {
		return NULL;
	}

	if (!(autochan = ast_calloc(1, sizeof(*autochan)))) {
		return NULL;
	}
	ast_mutex_init(&autochan->lock);

	autochan->chan = ast_channel_ref(chan);

	ast_debug(1, "Created autochan %p to hold channel %s (%p)\n",
		autochan, ast_channel_name(chan), chan);

	/* autochan is still private, no need for ast_autochan_channel_lock() */
	ast_channel_lock(autochan->chan);
	AST_LIST_INSERT_TAIL(ast_channel_autochans(autochan->chan), autochan, list);
	ast_channel_unlock(autochan->chan);

	return autochan;
}

void ast_autochan_destroy(struct ast_autochan *autochan)
{
	struct ast_autochan *autochan_iter;

	ast_autochan_channel_lock(autochan);
	AST_LIST_TRAVERSE_SAFE_BEGIN(ast_channel_autochans(autochan->chan), autochan_iter, list) {
		if (autochan_iter == autochan) {
			AST_LIST_REMOVE_CURRENT(list);
			ast_debug(1, "Removed autochan %p from the list, about to free it\n", autochan);
			break;
		}
	}
	AST_LIST_TRAVERSE_SAFE_END;
	ast_autochan_channel_unlock(autochan);

	autochan->chan = ast_channel_unref(autochan->chan);

	ast_mutex_destroy(&autochan->lock);

	ast_free(autochan);
}

void ast_autochan_new_channel(struct ast_channel *old_chan, struct ast_channel *new_chan)
{
	struct ast_autochan *autochan;

	AST_LIST_APPEND_LIST(ast_channel_autochans(new_chan), ast_channel_autochans(old_chan), list);

	/* Deadlock avoidance is not needed since the channels are already locked. */
	AST_LIST_TRAVERSE(ast_channel_autochans(new_chan), autochan, list) {
		ast_mutex_lock(&autochan->lock);
		if (autochan->chan == old_chan) {
			autochan->chan = ast_channel_ref(new_chan);
			ast_channel_unref(old_chan);

			ast_debug(1, "Autochan %p used to hold channel %s (%p) but now holds channel %s (%p)\n",
					autochan, ast_channel_name(old_chan), old_chan, ast_channel_name(new_chan), new_chan);
		}
		ast_mutex_unlock(&autochan->lock);
	}
}
