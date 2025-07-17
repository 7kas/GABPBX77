/*
 * GABpbx -- An open source telephony toolkit.
 *
 * Copyright (C) 2019, CyCore Systems, Inc
 *
 * Seán C McCord <scm@cycoresys.com
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
 * \brief AudioSocket support functions
 *
 * \author Seán C McCord <scm@cycoresys.com>
 *
 */

#ifndef _GABPBX_RES_AUDIOSOCKET_H
#define _GABPBX_RES_AUDIOSOCKET_H

#if defined(__cplusplus) || defined(c_plusplus)
extern "C" {
#endif

#include <uuid/uuid.h>

#include "gabpbx/frame.h"
#include "gabpbx/uuid.h"

/*!
 * \brief Send the initial message to an AudioSocket server
 *
 * \param server The server address, including port.
 * \param chan An optional channel which will be put into autoservice during
 * the connection period.  If there is no channel to be autoserviced, pass NULL
 * instead.
 *
 * \retval socket file descriptor for AudioSocket on success
 * \retval -1 on error
 */
const int ast_audiosocket_connect(const char *server, struct ast_channel *chan);

/*!
 * \brief Send the initial message to an AudioSocket server
 *
 * \param svc The file descriptor of the network socket to the AudioSocket server.
 * \param id The UUID to send to the AudioSocket server to uniquely identify this connection.
 *
 * \retval 0 on success
 * \retval -1 on error
 */
const int ast_audiosocket_init(const int svc, const char *id);

/*!
 * \brief Send an GABpbx audio frame to an AudioSocket server
 *
 * \param svc The file descriptor of the network socket to the AudioSocket server.
 * \param f The GABpbx audio frame to send.
 *
 * \retval 0 on success
 * \retval -1 on error
 */
const int ast_audiosocket_send_frame(const int svc, const struct ast_frame *f);

/*!
 * \brief Receive an GABpbx frame from an AudioSocket server
 *
 * This returned object is a pointer to an GABpbx frame which must be
 * manually freed by the caller.
 *
 * \param svc The file descriptor of the network socket to the AudioSocket server.
 *
 * \retval A \ref ast_frame on success
 * \retval NULL on error
 */
struct ast_frame *ast_audiosocket_receive_frame(const int svc);

#endif /* _GABPBX_RES_AUDIOSOCKET_H */
