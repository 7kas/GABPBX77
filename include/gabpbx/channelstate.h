/*
 * GABpbx -- An open source telephony toolkit.
 *
 * Copyright (C) 1999 - 2010, Digium, Inc.
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
 * \brief Channel states
 * \par See also:
 *  \arg \ref Def_Channel
 *  \arg \ref channel_drivers
 */

#ifndef __AST_CHANNELSTATE_H__
#define __AST_CHANNELSTATE_H__

#include "gabpbx.h"

/*!
 * \brief ast_channel states
 *
 * \note Bits 0-15 of state are reserved for the state (up/down) of the line
 *       Bits 16-32 of state are reserved for flags
 */
enum ast_channel_state {
	AST_STATE_DOWN,			/*!< Channel is down and available */
	AST_STATE_RESERVED,		/*!< Channel is down, but reserved */
	AST_STATE_OFFHOOK,		/*!< Channel is off hook */
	AST_STATE_DIALING,		/*!< Digits (or equivalent) have been dialed */
	AST_STATE_RING,			/*!< Remote end is ringing (e.g. listening to audible ringback tone). Also often used for initial state for a new channel. */
	AST_STATE_RINGING,		/*!< Line is ringing */
	AST_STATE_UP,			/*!< Line is up */
	AST_STATE_BUSY,			/*!< Line is busy */
	AST_STATE_DIALING_OFFHOOK,	/*!< Digits (or equivalent) have been dialed while offhook */
	AST_STATE_PRERING,		/*!< Channel has detected an incoming call and is waiting for ring */

	AST_STATE_MUTE = (1 << 16),	/*!< Do not transmit voice data */
};

/*!
 * \brief Change the state of a channel
 * \pre chan is locked
 */
int ast_setstate(struct ast_channel *chan, enum ast_channel_state);

#endif /* __AST_CHANNELSTATE_H__ */
