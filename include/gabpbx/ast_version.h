/*
 * GABpbx -- An open source telephony toolkit.
 *
 * Copyright (C) 2008, Digium, Inc.
 *
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
 * \brief GABpbx version information
 * \author Russell Bryant <russell@digium.com>
 */

#ifndef __AST_VERSION_H
#define __AST_VERSION_H

/*!
 * \brief Retrieve the GABpbx version string.
 */
const char *ast_get_version(void);

/*!
 * \brief Retrieve the numeric GABpbx version
 *
 * Format ABBCC
 * AABB - Major version (1.4 would be 104)
 * CC - Minor version
 *
 * 1.4.17 would be 10417.
 */
const char *ast_get_version_num(void);

/*! Retrieve the ABI-breaking GABpbx build options */
const char *ast_get_build_opts(void);

/*! Retrieve all of the the GABpbx build options */
const char *ast_get_build_opts_all(void);

#endif /* __AST_VERSION_H */
