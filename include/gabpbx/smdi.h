/*
 * GABpbx -- An open source telephony toolkit.
 *
 * Copyright (C) 2005-2008, Digium, Inc.
 *
 * Matthew A. Nicholson <mnicholson@digium.com>
 * Russell Bryant <russell@digium.com>
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
 * \brief SMDI support for GABpbx.
 * \author Matthew A. Nicholson <mnicholson@digium.com>
 * \author Russell Bryant <russell@digium.com>
 */

#ifndef GABPBX_SMDI_H
#define GABPBX_SMDI_H

#include <termios.h>
#include <time.h>

#include "gabpbx/config.h"
#include "gabpbx/module.h"
#include "gabpbx/optional_api.h"

#define SMDI_MESG_NAME_LEN 80
#define SMDI_MESG_DESK_NUM_LEN 3
#define SMDI_MESG_DESK_TERM_LEN 4
#define SMDI_MWI_FAIL_CAUSE_LEN 3
#define SMDI_MAX_STATION_NUM_LEN 10
#define SMDI_MAX_FILENAME_LEN 256

/*!
 * \brief An SMDI message waiting indicator message.
 *
 * The ast_smdi_mwi_message structure contains the parsed out parts of an smdi
 * message.  Each ast_smdi_interface structure has a message queue consisting
 * ast_smdi_mwi_message structures.
 */
struct ast_smdi_mwi_message {
	char name[SMDI_MESG_NAME_LEN];
	char fwd_st[SMDI_MAX_STATION_NUM_LEN + 1];		/* forwarding station number */
	char cause[SMDI_MWI_FAIL_CAUSE_LEN + 1];		/* the type of failure */
	struct timeval timestamp;				/* a timestamp for the message */
};

/*!
 * \brief An SMDI message desk message.
 *
 * The ast_smdi_md_message structure contains the parsed out parts of an smdi
 * message.  Each ast_smdi_interface structure has a message queue consisting
 * ast_smdi_md_message structures.
 */
struct ast_smdi_md_message {
	char name[SMDI_MESG_NAME_LEN];
	char mesg_desk_num[SMDI_MESG_DESK_NUM_LEN + 1];		/* message desk number */
	char mesg_desk_term[SMDI_MESG_DESK_TERM_LEN + 1];	/* message desk terminal */
	char fwd_st[SMDI_MAX_STATION_NUM_LEN + 1];		/* forwarding station number */
	char calling_st[SMDI_MAX_STATION_NUM_LEN + 1];		/* calling station number */
	char type;						/* the type of the call */
	struct timeval timestamp;				/* a timestamp for the message */
};

/*!
 * \brief SMDI interface structure.
 *
 * The ast_smdi_interface structure holds information on a serial port that
 * should be monitored for SMDI activity.  The structure contains a message
 * queue of messages that have been received on the interface.
 */
struct ast_smdi_interface;

/*!
 * \brief Get the next SMDI message from the queue.
 * \param iface a pointer to the interface to use.
 *
 * This function pulls the first unexpired message from the SMDI message queue
 * on the specified interface.  It will purge all expired SMDI messages before
 * returning.
 *
 * \return the next SMDI message, or NULL if there were no pending messages.
 */
AST_OPTIONAL_API(struct ast_smdi_md_message *, ast_smdi_md_message_pop,
		 (struct ast_smdi_interface *iface),
		 { return NULL; });

/*!
 * \brief Get the next SMDI message from the queue.
 * \param iface a pointer to the interface to use.
 * \param timeout the time to wait before returning in milliseconds.
 *
 * This function pulls a message from the SMDI message queue on the specified
 * interface.  If no message is available this function will wait the specified
 * amount of time before returning.
 *
 * \return the next SMDI message, or NULL if there were no pending messages and
 * the timeout has expired.
 */
AST_OPTIONAL_API(struct ast_smdi_md_message *, ast_smdi_md_message_wait,
		 (struct ast_smdi_interface *iface, int timeout),
		 { return NULL; });

/*!
 * \brief Get the next SMDI message from the queue.
 * \param iface a pointer to the interface to use.
 *
 * This function pulls the first unexpired message from the SMDI message queue
 * on the specified interface.  It will purge all expired SMDI messages before
 * returning.
 *
 * \return the next SMDI message, or NULL if there were no pending messages.
 */
AST_OPTIONAL_API(struct ast_smdi_mwi_message *, ast_smdi_mwi_message_pop,
		 (struct ast_smdi_interface *iface),
		 { return NULL; });

/*!
 * \brief Get the next SMDI message from the queue.
 * \param iface a pointer to the interface to use.
 * \param timeout the time to wait before returning in milliseconds.
 *
 * This function pulls a message from the SMDI message queue on the specified
 * interface.  If no message is available this function will wait the specified
 * amount of time before returning.
 *
 * \return the next SMDI message, or NULL if there were no pending messages and
 * the timeout has expired.
 */
AST_OPTIONAL_API(struct ast_smdi_mwi_message *, ast_smdi_mwi_message_wait,
		 (struct ast_smdi_interface *iface, int timeout),
		 { return NULL; });

AST_OPTIONAL_API(struct ast_smdi_mwi_message *, ast_smdi_mwi_message_wait_station,
		 (struct ast_smdi_interface *iface, int	timeout, const char *station),
		 { return NULL; });

/*!
 * \brief Find an SMDI interface with the specified name.
 * \param iface_name the name/port of the interface to search for.
 *
 * \return an ao2 reference to the interface located or NULL if none was found.
 */
AST_OPTIONAL_API(struct ast_smdi_interface *, ast_smdi_interface_find,
		 (const char *iface_name),
		 { return NULL; });

/*!
 * \brief Set the MWI indicator for a mailbox.
 * \param iface the interface to use.
 * \param mailbox the mailbox to use.
 */
AST_OPTIONAL_API(int, ast_smdi_mwi_set,
		 (struct ast_smdi_interface *iface, const char *mailbox),
		 { return -1; });

/*!
 * \brief Unset the MWI indicator for a mailbox.
 * \param iface the interface to use.
 * \param mailbox the mailbox to use.
 */
AST_OPTIONAL_API(int, ast_smdi_mwi_unset,
		 (struct ast_smdi_interface *iface, const char *mailbox),
		 { return -1; });

#endif /* !GABPBX_SMDI_H */
