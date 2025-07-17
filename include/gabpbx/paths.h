/*
 * GABpbx -- An open source telephony toolkit.
 *
 * Paths to configurable GABpbx directories
 *
 * Copyright (C) 1999-2006, Digium, Inc.
 *
 * Mark Spencer <markster@digium.com>
 *
 * This program is free software, distributed under the terms of
 * the GNU General Public License
 */

/*! \file
 * \brief GABpbx file paths, configured in gabpbx.conf
 */

#ifndef _GABPBX_PATHS_H
#define _GABPBX_PATHS_H

extern const char *ast_config_AST_CACHE_DIR;
extern const char *ast_config_AST_CONFIG_DIR;
extern const char *ast_config_AST_CONFIG_FILE;
extern const char *ast_config_AST_MODULE_DIR;
extern const char *ast_config_AST_SPOOL_DIR;
extern const char *ast_config_AST_MONITOR_DIR;
extern const char *ast_config_AST_RECORDING_DIR;
extern const char *ast_config_AST_VAR_DIR;
extern const char *ast_config_AST_DATA_DIR;
extern const char *ast_config_AST_LOG_DIR;
extern const char *ast_config_AST_AGI_DIR;
extern const char *ast_config_AST_DB;
extern const char *ast_config_AST_KEY_DIR;
extern const char *ast_config_AST_PID;
extern const char *ast_config_AST_SOCKET;
extern const char *ast_config_AST_RUN_DIR;
extern const char *ast_config_AST_RUN_GROUP;
extern const char *ast_config_AST_RUN_USER;
extern const char *ast_config_AST_SYSTEM_NAME;
extern const char *ast_config_AST_SBIN_DIR;
extern const char *ast_config_AST_CTL_PERMISSIONS;
extern const char *ast_config_AST_CTL_OWNER;
extern const char *ast_config_AST_CTL_GROUP;
extern const char *ast_config_AST_CTL;

/* germanico */
extern const int  *ast_config_AST_SYSTEM_ROOT;
extern const int  *ast_config_AST_SYSTEM_PJSIPUID;

/* Extension state Redis daemon configuration */
extern const char *ast_config_AST_EXTENSION_STATE_HOST;
extern const char *ast_config_AST_EXTENSION_STATE_PORT;

#endif /* _GABPBX_PATHS_H */
