/*
 * GABpbx -- An open source telephony toolkit.
 *
 * Copyright (c) 2005, 2006 Tilghman Lesher
 * Copyright (c) 2008, 2009 Digium, Inc.
 *
 * Tilghman Lesher <func_odbc__200508@the-tilghman.com>
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
 * \brief ODBC lookups
 *
 * \author Tilghman Lesher <func_odbc__200508@the-tilghman.com>
 *
 * \ingroup functions
 */

/*** MODULEINFO
	<depend>res_odbc</depend>
	<depend>generic_odbc</depend>
	<support_level>core</support_level>
 ***/

#include "gabpbx.h"

#include "gabpbx/module.h"
#include "gabpbx/file.h"
#include "gabpbx/channel.h"
#include "gabpbx/pbx.h"
#include "gabpbx/config.h"
#include "gabpbx/res_odbc.h"
#include "gabpbx/res_odbc_transaction.h"
#include "gabpbx/app.h"
#include "gabpbx/cli.h"
#include "gabpbx/strings.h"

/*** DOCUMENTATION
	<function name="ODBC_FETCH" language="en_US">
		<since>
			<version>1.6.0</version>
		</since>
		<synopsis>
			Fetch a row from a multirow query.
		</synopsis>
		<syntax>
			<parameter name="result-id" required="true" />
		</syntax>
		<description>
			<para>For queries which are marked as mode=multirow, the original
			query returns a <replaceable>result-id</replaceable> from which results
			may be fetched.  This function implements the actual fetch of the results.</para>
			<para>This also sets <variable>ODBC_FETCH_STATUS</variable>.</para>
			<variablelist>
				<variable name="ODBC_FETCH_STATUS">
					<value name="SUCESS">
						If rows are available.
					</value>
					<value name="FAILURE">
						If no rows are available.
					</value>
				</variable>
			</variablelist>
		</description>
	</function>
	<application name="ODBCFinish" language="en_US">
		<since>
			<version>1.6.0</version>
		</since>
		<synopsis>
			Clear the resultset of a sucessful multirow query.
		</synopsis>
		<syntax>
			<parameter name="result-id" required="true" />
		</syntax>
		<description>
			<para>For queries which are marked as mode=multirow, this will clear
			any remaining rows of the specified resultset.</para>
		</description>
	</application>
	<function name="SQL_ESC" language="en_US">
		<since>
			<version>1.4.0</version>
		</since>
		<synopsis>
			Escapes single ticks for use in SQL statements.
		</synopsis>
		<syntax>
			<parameter name="string" required="true" />
		</syntax>
		<description>
			<para>Used in SQL templates to escape data which may contain single ticks
			<literal>'</literal> which are otherwise used to delimit data.</para>
			<example title="Escape example">
			 SELECT foo FROM bar WHERE baz='${SQL_ESC(${ARG1})}'
			</example>
		</description>
	</function>
	<function name="SQL_ESC_BACKSLASHES" language="en_US">
		<since>
			<version>16.26.0</version>
			<version>18.12.0</version>
			<version>19.4.0</version>
		</since>
		<synopsis>
			Escapes backslashes for use in SQL statements.
		</synopsis>
		<syntax>
			<parameter name="string" required="true" />
		</syntax>
		<description>
			<para>Used in SQL templates to escape data which may contain backslashes
			<literal>\</literal> which are otherwise used to escape data.</para>
			<example title="Escape with backslashes example">
			SELECT foo FROM bar WHERE baz='${SQL_ESC(${SQL_ESC_BACKSLASHES(${ARG1})})}'
			</example>
		</description>
	</function>
 ***/

static char *config = "func_odbc.conf";

#define DEFAULT_SINGLE_DB_CONNECTION 0

static int single_db_connection;

AST_RWLOCK_DEFINE_STATIC(single_db_connection_lock);

enum odbc_option_flags {
	OPT_ESCAPECOMMAS =	(1 << 0),
	OPT_MULTIROW     =	(1 << 1),
};

struct acf_odbc_query {
	AST_RWLIST_ENTRY(acf_odbc_query) list;
	char readhandle[5][30];
	char writehandle[5][30];
	char *sql_read;
	char *sql_write;
	char *sql_insert;
	unsigned int flags;
	int rowlimit;
	int minargs;
	struct ast_custom_function *acf;
};

static void odbc_datastore_free(void *data);

static const struct ast_datastore_info odbc_info = {
	.type = "FUNC_ODBC",
	.destroy = odbc_datastore_free,
};

/* For storing each result row */
struct odbc_datastore_row {
	AST_LIST_ENTRY(odbc_datastore_row) list;
	char data[0];
};

/* For storing each result set */
struct odbc_datastore {
	AST_LIST_HEAD(, odbc_datastore_row);
	char names[0];
};

/*! \brief Data source name
 *
 * This holds data that pertains to a DSN
 */
struct dsn {
	/*! A connection to the database */
	struct odbc_obj *connection;
	/*! The name of the DSN as defined in res_odbc.conf */
	char name[0];
};

#define DSN_BUCKETS 37

struct ao2_container *dsns;

static int dsn_hash(const void *obj, const int flags)
{
	const struct dsn *object;
	const char *key;

	switch (flags & OBJ_SEARCH_MASK) {
	case OBJ_SEARCH_KEY:
		key = obj;
		break;
	case OBJ_SEARCH_OBJECT:
		object = obj;
		key = object->name;
		break;
	default:
		ast_assert(0);
		return 0;
	}
	return ast_str_hash(key);
}

static int dsn_cmp(void *obj, void *arg, int flags)
{
	const struct dsn *object_left = obj;
	const struct dsn *object_right = arg;
	const char *right_key = arg;
	int cmp;

	switch (flags & OBJ_SEARCH_MASK) {
	case OBJ_SEARCH_OBJECT:
		right_key = object_right->name;
		/* Fall through */
	case OBJ_SEARCH_KEY:
		cmp = strcmp(object_left->name, right_key);
		break;
	case OBJ_SEARCH_PARTIAL_KEY:
		cmp = strncmp(object_left->name, right_key, strlen(right_key));
		break;
	default:
		cmp = 0;
		break;
	}

	if (cmp) {
		return 0;
	}

	return CMP_MATCH;
}

static void dsn_destructor(void *obj)
{
	struct dsn *dsn = obj;

	if (dsn->connection) {
		ast_odbc_release_obj(dsn->connection);
	}
}

/*!
 * \brief Create a DSN and connect to the database
 *
 * \param name The name of the DSN as found in res_odbc.conf
 * \retval NULL Fail
 * \retval non-NULL The newly-created structure
 */
static struct dsn *create_dsn(const char *name)
{
	struct dsn *dsn;

	if (!dsns) {
		return NULL;
	}

	dsn = ao2_alloc(sizeof(*dsn) + strlen(name) + 1, dsn_destructor);
	if (!dsn) {
		return NULL;
	}

	/* Safe */
	strcpy(dsn->name, name);

	dsn->connection = ast_odbc_request_obj(name, 0);
	if (!dsn->connection) {
		ao2_ref(dsn, -1);
		return NULL;
	}

	if (!ao2_link_flags(dsns, dsn, OBJ_NOLOCK)) {
		ao2_ref(dsn, -1);
		return NULL;
	}

	return dsn;
}

static SQLHSTMT silent_execute(struct odbc_obj *obj, void *data);

/*!
 * \brief Determine if the connection has died.
 *
 * \param connection The connection to check
 * \retval 1 Yep, it's dead
 * \retval 0 It's alive and well
 */
static int connection_dead(struct odbc_obj *connection)
{
	SQLINTEGER dead;
	SQLRETURN res;
	SQLHSTMT stmt;

	if (!connection) {
		return 1;
	}

	res = SQLGetConnectAttr(connection->con, SQL_ATTR_CONNECTION_DEAD, &dead, 0, 0);
	if (SQL_SUCCEEDED(res)) {
		return dead == SQL_CD_TRUE ? 1 : 0;
	}

	/* If the Driver doesn't support SQL_ATTR_CONNECTION_DEAD do a direct
	 * execute of a probing statement and see if that succeeds instead
	 */
	stmt = ast_odbc_direct_execute(connection, silent_execute, "SELECT 1");
	if (!stmt) {
		return 1;
	}

	SQLFreeHandle(SQL_HANDLE_STMT, stmt);
	return 0;
}

/*!
 * \brief Retrieve a DSN, or create it if it does not exist.
 *
 * The created DSN is returned locked. This should be inconsequential
 * to callers in most cases.
 *
 * When finished with the returned structure, the caller must call
 * \ref release_obj_or_dsn
 *
 * \param name Name of the DSN as found in res_odbc.conf
 * \retval NULL Unable to retrieve or create the DSN
 * \retval non-NULL The retrieved/created locked DSN
 */
static struct dsn *get_dsn(const char *name)
{
	struct dsn *dsn;

	if (!dsns) {
		return NULL;
	}

	ao2_lock(dsns);
	dsn = ao2_find(dsns, name, OBJ_SEARCH_KEY | OBJ_NOLOCK);
	if (!dsn) {
		dsn = create_dsn(name);
	}
	ao2_unlock(dsns);

	if (!dsn) {
		return NULL;
	}

	ao2_lock(dsn);
	if (!dsn->connection) {
		dsn->connection = ast_odbc_request_obj(name, 0);
		if (!dsn->connection) {
			ao2_unlock(dsn);
			ao2_ref(dsn, -1);
			return NULL;
		}
		return dsn;
	}

	if (connection_dead(dsn->connection)) {
		ast_odbc_release_obj(dsn->connection);
		dsn->connection = ast_odbc_request_obj(name, 0);
		if (!dsn->connection) {
			ao2_unlock(dsn);
			ao2_ref(dsn, -1);
			return NULL;
		}
	}

	return dsn;
}

/*!
 * \brief Get a DB handle via a DSN or directly
 *
 * If single db connection then get the DB handle via DSN
 * else by requesting a connection directly
 *
 * \param dsn_name Name of the DSN as found in res_odbc.conf
 * \param dsn The pointer to the DSN
 * \retval NULL Unable to retrieve the DB handle
 * \retval non-NULL The retrieved DB handle
 */
static struct odbc_obj *get_odbc_obj(const char *dsn_name, struct dsn **dsn)
{
	struct odbc_obj *obj = NULL;

	ast_rwlock_rdlock(&single_db_connection_lock);
	if (single_db_connection) {
		if (dsn) {
			*dsn = get_dsn(dsn_name);
			if (*dsn) {
				obj = (*dsn)->connection;
			}
		}
	} else {
		obj = ast_odbc_request_obj(dsn_name, 0);
	}
	ast_rwlock_unlock(&single_db_connection_lock);

	return obj;
}

/*!
 * \brief Release an ODBC obj or a DSN
 *
 * If single db connection then unlock and unreference the DSN
 * else release the ODBC obj
 *
 * \param obj The pointer to the ODBC obj to release
 * \param dsn The pointer to the dsn to unlock and unreference
 */
static inline void release_obj_or_dsn(struct odbc_obj **obj, struct dsn **dsn)
{
	if (dsn && *dsn) {
		/* If multiple connections are not enabled then the guarantee
		 * of a single connection already exists and holding on to the
		 * connection would prevent any other user from acquiring it
		 * indefinitely.
		 */
		if (ast_odbc_get_max_connections((*dsn)->name) < 2) {
			ast_odbc_release_obj((*dsn)->connection);
			(*dsn)->connection = NULL;
		}
		ao2_unlock(*dsn);
		ao2_ref(*dsn, -1);
		*dsn = NULL;
		/* Some callers may provide both an obj and dsn. To ensure that
		 * the connection is not released twice we set it to NULL here if
		 * present.
		 */
		if (obj) {
			*obj = NULL;
		}
	} else if (obj && *obj) {
		ast_odbc_release_obj(*obj);
		*obj = NULL;
	}
}

static AST_RWLIST_HEAD_STATIC(queries, acf_odbc_query);

static int resultcount = 0;

AST_THREADSTORAGE(sql_buf);
AST_THREADSTORAGE(sql2_buf);
AST_THREADSTORAGE(coldata_buf);
AST_THREADSTORAGE(colnames_buf);

static int acf_fetch(struct ast_channel *chan, const char *cmd, char *data, char *buf, size_t len);

static void odbc_datastore_free(void *data)
{
	struct odbc_datastore *result = data;
	struct odbc_datastore_row *row;

	if (!result) {
		return;
	}

	AST_LIST_LOCK(result);
	while ((row = AST_LIST_REMOVE_HEAD(result, list))) {
		ast_free(row);
	}
	AST_LIST_UNLOCK(result);
	AST_LIST_HEAD_DESTROY(result);
	ast_free(result);
}

/*!
 * \brief Common execution function for SQL queries.
 *
 * \param obj DB connection
 * \param data The query to execute
 * \param silent If true, do not print warnings on failure
 * \retval NULL Failed to execute query
 * \retval non-NULL The executed statement
 */
static SQLHSTMT execute(struct odbc_obj *obj, void *data, int silent)
{
	int res;
	char *sql = data;
	SQLHSTMT stmt;

	res = SQLAllocHandle (SQL_HANDLE_STMT, obj->con, &stmt);
	if ((res != SQL_SUCCESS) && (res != SQL_SUCCESS_WITH_INFO)) {
		ast_log_chan(NULL, LOG_WARNING, "SQL Alloc Handle failed (%d)!\n", res);
		return NULL;
	}

	res = ast_odbc_execute_sql(obj, stmt, sql);
	if ((res != SQL_SUCCESS) && (res != SQL_SUCCESS_WITH_INFO) && (res != SQL_NO_DATA)) {
		if (res == SQL_ERROR && !silent) {
			int i;
			SQLINTEGER nativeerror=0, numfields=0;
			SQLSMALLINT diagbytes=0;
			unsigned char state[10], diagnostic[256];

			SQLGetDiagField(SQL_HANDLE_STMT, stmt, 1, SQL_DIAG_NUMBER, &numfields, SQL_IS_INTEGER, &diagbytes);
			for (i = 0; i < numfields; i++) {
				SQLGetDiagRec(SQL_HANDLE_STMT, stmt, i + 1, state, &nativeerror, diagnostic, sizeof(diagnostic), &diagbytes);
				ast_log_chan(NULL, LOG_WARNING, "SQL Execute returned an error %d: %s: %s (%d)\n", res, state, diagnostic, diagbytes);
				if (i > 10) {
					ast_log_chan(NULL, LOG_WARNING, "Oh, that was good.  There are really %d diagnostics?\n", (int)numfields);
					break;
				}
			}
		}

		if (!silent) {
			ast_log_chan(NULL, LOG_WARNING, "SQL Exec Direct failed (%d)![%s]\n", res, sql);
		}
		SQLCloseCursor(stmt);
		SQLFreeHandle(SQL_HANDLE_STMT, stmt);
		return NULL;
	}

	return stmt;
}

static SQLHSTMT generic_execute(struct odbc_obj *obj, void *data)
{
	return execute(obj, data, 0);
}

static SQLHSTMT silent_execute(struct odbc_obj *obj, void *data)
{
	return execute(obj, data, 1);
}

/*
 * Master control routine
 */
static int acf_odbc_write(struct ast_channel *chan, const char *cmd, char *s, const char *value)
{
	struct odbc_obj *obj = NULL;
	struct acf_odbc_query *query;
	char *t, varname[15];
	int i, dsn_num, bogus_chan = 0;
	int transactional = 0;
	AST_DECLARE_APP_ARGS(values,
		AST_APP_ARG(field)[100];
	);
	AST_DECLARE_APP_ARGS(args,
		AST_APP_ARG(field)[100];
	);
	SQLHSTMT stmt = NULL;
	SQLLEN rows=0;
	struct ast_str *buf = ast_str_thread_get(&sql_buf, 16);
	struct ast_str *insertbuf = ast_str_thread_get(&sql2_buf, 16);
	const char *status = "FAILURE";
	struct dsn *dsn = NULL;

	if (!buf || !insertbuf) {
		return -1;
	}

	AST_RWLIST_RDLOCK(&queries);
	AST_RWLIST_TRAVERSE(&queries, query, list) {
		if (!strcmp(query->acf->name, cmd)) {
			break;
		}
	}

	if (!query) {
		ast_log_chan(NULL, LOG_ERROR, "No such function '%s'\n", cmd);
		AST_RWLIST_UNLOCK(&queries);
		if (chan) {
			pbx_builtin_setvar_helper(chan, "ODBCSTATUS", status);
		}
		return -1;
	}

	AST_STANDARD_APP_ARGS(args, s);
	if (args.argc < query->minargs) {
		ast_log_chan(NULL, LOG_ERROR, "%d arguments supplied to '%s' requiring minimum %d\n",
				args.argc, cmd, query->minargs);
		AST_RWLIST_UNLOCK(&queries);
		return -1;
	}

	if (!chan) {
		if (!(chan = ast_dummy_channel_alloc())) {
			AST_RWLIST_UNLOCK(&queries);
			return -1;
		}
		bogus_chan = 1;
	}

	if (!bogus_chan) {
		ast_autoservice_start(chan);
	}

	ast_str_make_space(&buf, strlen(query->sql_write) * 2 + 300);
	/* We only get here if sql_write is set. sql_insert is optional however. */
	if (query->sql_insert) {
		ast_str_make_space(&insertbuf, strlen(query->sql_insert) * 2 + 300);
	}

	/* Parse our arguments */
	t = value ? ast_strdupa(value) : "";

	if (!s || !t) {
		ast_log_chan(NULL, LOG_ERROR, "Out of memory\n");
		AST_RWLIST_UNLOCK(&queries);
		if (!bogus_chan) {
			ast_autoservice_stop(chan);
			pbx_builtin_setvar_helper(chan, "ODBCSTATUS", status);
		} else {
			ast_channel_unref(chan);
		}
		return -1;
	}

	snprintf(varname, sizeof(varname), "%u", args.argc);
	pbx_builtin_pushvar_helper(chan, "ARGC", varname);
	for (i = 0; i < args.argc; i++) {
		snprintf(varname, sizeof(varname), "ARG%d", i + 1);
		pbx_builtin_pushvar_helper(chan, varname, args.field[i]);
	}

	/* Parse values, just like arguments */
	AST_STANDARD_APP_ARGS(values, t);
	for (i = 0; i < values.argc; i++) {
		snprintf(varname, sizeof(varname), "VAL%d", i + 1);
		pbx_builtin_pushvar_helper(chan, varname, values.field[i]);
	}

	/* Additionally set the value as a whole (but push an empty string if value is NULL) */
	pbx_builtin_pushvar_helper(chan, "VALUE", value ? value : "");

	ast_str_substitute_variables(&buf, 0, chan, query->sql_write);
	if (query->sql_insert) {
		ast_str_substitute_variables(&insertbuf, 0, chan, query->sql_insert);
	}

	if (bogus_chan) {
		chan = ast_channel_unref(chan);
	} else {
		/* Restore prior values */
		pbx_builtin_setvar_helper(chan, "ARGC", NULL);

		for (i = 0; i < args.argc; i++) {
			snprintf(varname, sizeof(varname), "ARG%d", i + 1);
			pbx_builtin_setvar_helper(chan, varname, NULL);
		}

		for (i = 0; i < values.argc; i++) {
			snprintf(varname, sizeof(varname), "VAL%d", i + 1);
			pbx_builtin_setvar_helper(chan, varname, NULL);
		}
		pbx_builtin_setvar_helper(chan, "VALUE", NULL);
	}

	/*!\note
	 * Okay, this part is confusing.  Transactions belong to a single database
	 * handle.  Therefore, when working with transactions, we CANNOT failover
	 * to multiple DSNs.  We MUST have a single handle all the way through the
	 * transaction, or else we CANNOT enforce atomicity.
	 */
	for (dsn_num = 0; dsn_num < 5; dsn_num++) {
		if (!ast_strlen_zero(query->writehandle[dsn_num])) {
			if (transactional) {
				/* This can only happen second time through or greater. */
				ast_log_chan(NULL, LOG_WARNING, "Transactions do not work well with multiple DSNs for 'writehandle'\n");
			}

			if ((obj = ast_odbc_retrieve_transaction_obj(chan, query->writehandle[dsn_num]))) {
				transactional = 1;
			} else {
				obj = get_odbc_obj(query->writehandle[dsn_num], &dsn);
				transactional = 0;
			}

			if (obj && (stmt = ast_odbc_direct_execute(obj, generic_execute, ast_str_buffer(buf)))) {
				break;
			}
			if (!transactional) {
				release_obj_or_dsn (&obj, &dsn);
			}
		}
	}

	if (stmt) {
		SQLRowCount(stmt, &rows);
		SQLCloseCursor(stmt);
		SQLFreeHandle(SQL_HANDLE_STMT, stmt);

		if (rows != 0) {
			status = "SUCCESS";

		} else if (query->sql_insert) {
			if (!transactional) {
				release_obj_or_dsn (&obj, &dsn);
			}

			for (transactional = 0, dsn_num = 0; dsn_num < 5; dsn_num++) {
				if (!ast_strlen_zero(query->writehandle[dsn_num])) {
					if (transactional) {
						/* This can only happen second time through or greater. */
						ast_log_chan(NULL, LOG_WARNING, "Transactions do not work well with multiple DSNs for 'writehandle'\n");
					} else {
						release_obj_or_dsn (&obj, &dsn);
					}

					if ((obj = ast_odbc_retrieve_transaction_obj(chan, query->writehandle[dsn_num]))) {
						transactional = 1;
					} else {
						obj = get_odbc_obj(query->writehandle[dsn_num], &dsn);
						transactional = 0;
					}
					if (obj) {
						stmt = ast_odbc_direct_execute(obj, generic_execute, ast_str_buffer(insertbuf));
					}
				}
				if (stmt) {
					status = "FAILOVER";
					SQLRowCount(stmt, &rows);
					SQLCloseCursor(stmt);
					SQLFreeHandle(SQL_HANDLE_STMT, stmt);
					break;
				}
			}
		}
	}

	AST_RWLIST_UNLOCK(&queries);

	/* Output the affected rows, for all cases.  In the event of failure, we
	 * flag this as -1 rows.  Note that this is different from 0 affected rows
	 * which would be the case if we succeeded in our query, but the values did
	 * not change. */
	if (!bogus_chan) {
		snprintf(varname, sizeof(varname), "%d", (int)rows);
		pbx_builtin_setvar_helper(chan, "ODBCROWS", varname);
		pbx_builtin_setvar_helper(chan, "ODBCSTATUS", status);
	}

	if (!transactional) {
		release_obj_or_dsn (&obj, &dsn);
	}

	if (!bogus_chan) {
		ast_autoservice_stop(chan);
	}

	return 0;
}

static int acf_odbc_read(struct ast_channel *chan, const char *cmd, char *s, char *buf, size_t len)
{
	struct odbc_obj *obj = NULL;
	struct acf_odbc_query *query;
	char varname[15], rowcount[12] = "-1";
	struct ast_str *colnames = ast_str_thread_get(&colnames_buf, 16);
	int res, x, y, buflen = 0, escapecommas, rowlimit = 1, multirow = 0, dsn_num, bogus_chan = 0;
	AST_DECLARE_APP_ARGS(args,
		AST_APP_ARG(field)[100];
	);
	SQLHSTMT stmt = NULL;
	SQLSMALLINT colcount=0;
	SQLLEN indicator;
	SQLSMALLINT collength;
	struct odbc_datastore *resultset = NULL;
	struct odbc_datastore_row *row = NULL;
	struct ast_str *sql = ast_str_thread_get(&sql_buf, 16);
	const char *status = "FAILURE";
	struct dsn *dsn = NULL;

	if (!sql || !colnames) {
		if (chan) {
			pbx_builtin_setvar_helper(chan, "ODBCSTATUS", status);
		}
		return -1;
	}

	ast_str_reset(colnames);

	AST_RWLIST_RDLOCK(&queries);
	AST_RWLIST_TRAVERSE(&queries, query, list) {
		if (!strcmp(query->acf->name, cmd)) {
			break;
		}
	}

	if (!query) {
		ast_log_chan(NULL, LOG_ERROR, "No such function '%s'\n", cmd);
		AST_RWLIST_UNLOCK(&queries);
		if (chan) {
			pbx_builtin_setvar_helper(chan, "ODBCROWS", rowcount);
			pbx_builtin_setvar_helper(chan, "ODBCSTATUS", status);
		}
		return -1;
	}

	AST_STANDARD_APP_ARGS(args, s);
	if (args.argc < query->minargs) {
		ast_log_chan(NULL, LOG_ERROR, "%d arguments supplied to '%s' requiring minimum %d\n",
				args.argc, cmd, query->minargs);
		AST_RWLIST_UNLOCK(&queries);
		return -1;
	}

	if (!chan) {
		if (!(chan = ast_dummy_channel_alloc())) {
			AST_RWLIST_UNLOCK(&queries);
			return -1;
		}
		bogus_chan = 1;
	}

	if (!bogus_chan) {
		ast_autoservice_start(chan);
	}

	snprintf(varname, sizeof(varname), "%u", args.argc);
	pbx_builtin_pushvar_helper(chan, "ARGC", varname);
	for (x = 0; x < args.argc; x++) {
		snprintf(varname, sizeof(varname), "ARG%d", x + 1);
		pbx_builtin_pushvar_helper(chan, varname, args.field[x]);
	}

	ast_str_substitute_variables(&sql, 0, chan, query->sql_read);

	if (bogus_chan) {
		chan = ast_channel_unref(chan);
	} else {
		/* Restore prior values */
		pbx_builtin_setvar_helper(chan, "ARGC", NULL);

		for (x = 0; x < args.argc; x++) {
			snprintf(varname, sizeof(varname), "ARG%d", x + 1);
			pbx_builtin_setvar_helper(chan, varname, NULL);
		}
	}

	/* Save these flags, so we can release the lock */
	escapecommas = ast_test_flag(query, OPT_ESCAPECOMMAS);
	if (!bogus_chan && ast_test_flag(query, OPT_MULTIROW)) {
		if (!(resultset = ast_calloc(1, sizeof(*resultset)))) {
			pbx_builtin_setvar_helper(chan, "ODBCROWS", rowcount);
			pbx_builtin_setvar_helper(chan, "ODBCSTATUS", status);
			AST_RWLIST_UNLOCK(&queries);
			ast_autoservice_stop(chan);
			return -1;
		}
		AST_LIST_HEAD_INIT(resultset);
		if (query->rowlimit) {
			rowlimit = query->rowlimit;
		} else {
			rowlimit = INT_MAX;
		}
		multirow = 1;
	} else if (!bogus_chan) {
		if (query->rowlimit > 1) {
			rowlimit = query->rowlimit;
			if (!(resultset = ast_calloc(1, sizeof(*resultset)))) {
				pbx_builtin_setvar_helper(chan, "ODBCROWS", rowcount);
				pbx_builtin_setvar_helper(chan, "ODBCSTATUS", status);
				AST_RWLIST_UNLOCK(&queries);
				ast_autoservice_stop(chan);
				return -1;
			}
			AST_LIST_HEAD_INIT(resultset);
		}
	}
	AST_RWLIST_UNLOCK(&queries);

	for (dsn_num = 0; dsn_num < 5; dsn_num++) {
		if (!ast_strlen_zero(query->readhandle[dsn_num])) {
			obj = get_odbc_obj(query->readhandle[dsn_num], &dsn);
			if (!obj) {
				continue;
			}
			stmt = ast_odbc_direct_execute(obj, generic_execute, ast_str_buffer(sql));
		}
		if (stmt) {
			break;
		}
		release_obj_or_dsn (&obj, &dsn);
	}

	if (!stmt) {
		ast_log_chan(NULL, LOG_ERROR, "Unable to execute query [%s]\n", ast_str_buffer(sql));
		release_obj_or_dsn (&obj, &dsn);
		if (!bogus_chan) {
			pbx_builtin_setvar_helper(chan, "ODBCROWS", rowcount);
			ast_autoservice_stop(chan);
		}
		odbc_datastore_free(resultset);
		return -1;
	}

	res = SQLNumResultCols(stmt, &colcount);
	if ((res != SQL_SUCCESS) && (res != SQL_SUCCESS_WITH_INFO)) {
		ast_log_chan(NULL, LOG_WARNING, "SQL Column Count error!\n[%s]\n\n", ast_str_buffer(sql));
		SQLCloseCursor(stmt);
		SQLFreeHandle (SQL_HANDLE_STMT, stmt);
		release_obj_or_dsn (&obj, &dsn);
		if (!bogus_chan) {
			pbx_builtin_setvar_helper(chan, "ODBCROWS", rowcount);
			ast_autoservice_stop(chan);
		}
		odbc_datastore_free(resultset);
		return -1;
	}

	if (colcount <= 0) {
		ast_verb_chan(NULL, 4, "Returned %d columns [%s]\n", colcount, ast_str_buffer(sql));
		buf[0] = '\0';
		SQLCloseCursor(stmt);
		SQLFreeHandle (SQL_HANDLE_STMT, stmt);
		release_obj_or_dsn (&obj, &dsn);
		if (!bogus_chan) {
			pbx_builtin_setvar_helper(chan, "ODBCROWS", "0");
			pbx_builtin_setvar_helper(chan, "ODBCSTATUS", "NODATA");
			ast_autoservice_stop(chan);
		}
		odbc_datastore_free(resultset);
		return 0;
	}

	res = SQLFetch(stmt);
	if ((res != SQL_SUCCESS) && (res != SQL_SUCCESS_WITH_INFO)) {
		int res1 = -1;
		if (res == SQL_NO_DATA) {
			ast_verb_chan(NULL, 4, "Found no rows [%s]\n", ast_str_buffer(sql));
			res1 = 0;
			buf[0] = '\0';
			ast_copy_string(rowcount, "0", sizeof(rowcount));
			status = "NODATA";
		} else {
			ast_log_chan(NULL, LOG_WARNING, "Error %d in FETCH [%s]\n", res, ast_str_buffer(sql));
			status = "FETCHERROR";
		}
		SQLCloseCursor(stmt);
		SQLFreeHandle(SQL_HANDLE_STMT, stmt);
		release_obj_or_dsn (&obj, &dsn);
		if (!bogus_chan) {
			pbx_builtin_setvar_helper(chan, "ODBCROWS", rowcount);
			pbx_builtin_setvar_helper(chan, "ODBCSTATUS", status);
			ast_autoservice_stop(chan);
		}
		odbc_datastore_free(resultset);
		return res1;
	}

	status = "SUCCESS";

	for (y = 0; y < rowlimit; y++) {
		buf[0] = '\0';
		for (x = 0; x < colcount; x++) {
			int i;
			struct ast_str *coldata = ast_str_thread_get(&coldata_buf, 16);
			char *ptrcoldata;

			if (!coldata) {
				odbc_datastore_free(resultset);
				SQLCloseCursor(stmt);
				SQLFreeHandle(SQL_HANDLE_STMT, stmt);
				release_obj_or_dsn (&obj, &dsn);
				if (!bogus_chan) {
					pbx_builtin_setvar_helper(chan, "ODBCSTATUS", "MEMERROR");
					ast_autoservice_stop(chan);
				}
				return -1;
			}

			if (y == 0) {
				char colname[256];
				SQLLEN octetlength = 0;

				res = SQLDescribeCol(stmt, x + 1, (unsigned char *)colname, sizeof(colname), &collength, NULL, NULL, NULL, NULL);
				ast_debug(3, "Got collength of %d for column '%s' (offset %d)\n", (int)collength, colname, x);
				if (((res != SQL_SUCCESS) && (res != SQL_SUCCESS_WITH_INFO)) || collength == 0) {
					snprintf(colname, sizeof(colname), "field%d", x);
				}

				SQLColAttribute(stmt, x + 1, SQL_DESC_OCTET_LENGTH, NULL, 0, NULL, &octetlength);

				ast_str_make_space(&coldata, octetlength + 1);

				if (ast_str_strlen(colnames)) {
					ast_str_append(&colnames, 0, ",");
				}
				ast_str_append_escapecommas(&colnames, 0, colname, sizeof(colname));

				if (resultset) {
					void *tmp = ast_realloc(resultset, sizeof(*resultset) + ast_str_strlen(colnames) + 1);
					if (!tmp) {
						ast_log_chan(NULL, LOG_ERROR, "No space for a new resultset?\n");
						odbc_datastore_free(resultset);
						SQLCloseCursor(stmt);
						SQLFreeHandle(SQL_HANDLE_STMT, stmt);
						release_obj_or_dsn (&obj, &dsn);
						if (!bogus_chan) {
							pbx_builtin_setvar_helper(chan, "ODBCROWS", rowcount);
							pbx_builtin_setvar_helper(chan, "ODBCSTATUS", "MEMERROR");
							ast_autoservice_stop(chan);
						}
						return -1;
					}
					resultset = tmp;
					strcpy((char *)resultset + sizeof(*resultset), ast_str_buffer(colnames));
				}
			}

			buflen = strlen(buf);
			res = ast_odbc_ast_str_SQLGetData(&coldata, -1, stmt, x + 1, SQL_CHAR, &indicator);
			if (indicator == SQL_NULL_DATA) {
				ast_debug(3, "Got NULL data\n");
				ast_str_reset(coldata);
				res = SQL_SUCCESS;
			}

			if ((res != SQL_SUCCESS) && (res != SQL_SUCCESS_WITH_INFO)) {
				ast_log_chan(NULL, LOG_WARNING, "SQL Get Data error!\n[%s]\n\n", ast_str_buffer(sql));
				y = -1;
				buf[0] = '\0';
				goto end_acf_read;
			}

			ast_debug(2, "Got coldata of '%s'\n", ast_str_buffer(coldata));

			if (x) {
				buf[buflen++] = ',';
			}

			/* Copy data, encoding '\' and ',' for the argument parser */
			ptrcoldata = ast_str_buffer(coldata);
			for (i = 0; i < ast_str_strlen(coldata); i++) {
				if (escapecommas && (ptrcoldata[i] == '\\' || ptrcoldata[i] == ',')) {
					buf[buflen++] = '\\';
				}
				buf[buflen++] = ptrcoldata[i];

				if (buflen >= len - 2) {
					break;
				}

				if (ptrcoldata[i] == '\0') {
					break;
				}
			}

			buf[buflen] = '\0';
			ast_debug(2, "buf is now set to '%s'\n", buf);
		}
		ast_debug(2, "buf is now set to '%s'\n", buf);

		if (resultset) {
			row = ast_calloc(1, sizeof(*row) + buflen + 1);
			if (!row) {
				ast_log_chan(NULL, LOG_ERROR, "Unable to allocate space for more rows in this resultset.\n");
				status = "MEMERROR";
				goto end_acf_read;
			}
			strcpy((char *)row + sizeof(*row), buf);
			AST_LIST_INSERT_TAIL(resultset, row, list);

			/* Get next row */
			res = SQLFetch(stmt);
			if ((res != SQL_SUCCESS) && (res != SQL_SUCCESS_WITH_INFO)) {
				if (res != SQL_NO_DATA) {
					ast_log_chan(NULL, LOG_WARNING, "Error %d in FETCH [%s]\n", res, ast_str_buffer(sql));
				}
				/* Number of rows in the resultset */
				y++;
				break;
			}
		}
	}

end_acf_read:
	if (!bogus_chan) {
		snprintf(rowcount, sizeof(rowcount), "%d", y);
		pbx_builtin_setvar_helper(chan, "ODBCROWS", rowcount);
		pbx_builtin_setvar_helper(chan, "ODBCSTATUS", status);
		pbx_builtin_setvar_helper(chan, "~ODBCFIELDS~", ast_str_buffer(colnames));
		if (resultset) {
			struct ast_datastore *odbc_store;
			if (multirow) {
				int uid;
				uid = ast_atomic_fetchadd_int(&resultcount, +1) + 1;
				snprintf(buf, len, "%d", uid);
			} else {
				/* Name of the query is name of the resultset */
				ast_copy_string(buf, cmd, len);

				/* If there's one with the same name already, free it */
				ast_channel_lock(chan);
				if ((odbc_store = ast_channel_datastore_find(chan, &odbc_info, buf))) {
					ast_channel_datastore_remove(chan, odbc_store);
					ast_datastore_free(odbc_store);
				}
				ast_channel_unlock(chan);
			}
			odbc_store = ast_datastore_alloc(&odbc_info, buf);
			if (!odbc_store) {
				ast_log_chan(NULL, LOG_ERROR, "Rows retrieved, but unable to store it in the channel.  Results fail.\n");
				odbc_datastore_free(resultset);
				SQLCloseCursor(stmt);
				SQLFreeHandle(SQL_HANDLE_STMT, stmt);
				release_obj_or_dsn (&obj, &dsn);
				pbx_builtin_setvar_helper(chan, "ODBCSTATUS", "MEMERROR");
				ast_autoservice_stop(chan);
				return -1;
			}
			odbc_store->data = resultset;
			ast_channel_lock(chan);
			ast_channel_datastore_add(chan, odbc_store);
			ast_channel_unlock(chan);
		}
	}
	SQLCloseCursor(stmt);
	SQLFreeHandle(SQL_HANDLE_STMT, stmt);
	release_obj_or_dsn (&obj, &dsn);
	if (resultset && !multirow) {
		/* Fetch the first resultset */
		if (!acf_fetch(chan, "", buf, buf, len)) {
			buf[0] = '\0';
		}
	}
	if (!bogus_chan) {
		ast_autoservice_stop(chan);
	}
	return 0;
}

static int acf_escape(struct ast_channel *chan, const char *cmd, char *data, char *buf, size_t len, char character)
{
	char *out = buf;

	for (; *data && out - buf < len; data++) {
		if (*data == character) {
			*out = character;
			out++;
		}
		*out++ = *data;
	}
	*out = '\0';

	return 0;
}

static int acf_escape_ticks(struct ast_channel *chan, const char *cmd, char *data, char *buf, size_t len)
{
	return acf_escape(chan, cmd, data, buf, len, '\'');
}

static struct ast_custom_function escape_function = {
	.name = "SQL_ESC",
	.read = acf_escape_ticks,
	.write = NULL,
};

static int acf_escape_backslashes(struct ast_channel *chan, const char *cmd, char *data, char *buf, size_t len)
{
	return acf_escape(chan, cmd, data, buf, len, '\\');
}

static struct ast_custom_function escape_backslashes_function = {
	.name = "SQL_ESC_BACKSLASHES",
	.read = acf_escape_backslashes,
	.write = NULL,
};

static int acf_fetch(struct ast_channel *chan, const char *cmd, char *data, char *buf, size_t len)
{
	struct ast_datastore *store;
	struct odbc_datastore *resultset;
	struct odbc_datastore_row *row;

	if (!chan) {
		ast_log_chan(NULL, LOG_WARNING, "No channel was provided to %s function.\n", cmd);
		return -1;
	}

	ast_channel_lock(chan);
	store = ast_channel_datastore_find(chan, &odbc_info, data);
	if (!store) {
		ast_channel_unlock(chan);
		pbx_builtin_setvar_helper(chan, "ODBC_FETCH_STATUS", "FAILURE");
		return -1;
	}
	resultset = store->data;
	AST_LIST_LOCK(resultset);
	row = AST_LIST_REMOVE_HEAD(resultset, list);
	AST_LIST_UNLOCK(resultset);
	if (!row) {
		/* Cleanup datastore */
		ast_channel_datastore_remove(chan, store);
		ast_datastore_free(store);
		ast_channel_unlock(chan);
		pbx_builtin_setvar_helper(chan, "ODBC_FETCH_STATUS", "FAILURE");
		return -1;
	}
	pbx_builtin_setvar_helper(chan, "~ODBCFIELDS~", resultset->names);
	ast_channel_unlock(chan);
	ast_copy_string(buf, row->data, len);
	ast_free(row);
	pbx_builtin_setvar_helper(chan, "ODBC_FETCH_STATUS", "SUCCESS");
	return 0;
}

static struct ast_custom_function fetch_function = {
	.name = "ODBC_FETCH",
	.read = acf_fetch,
	.write = NULL,
};

static char *app_odbcfinish = "ODBCFinish";

static int exec_odbcfinish(struct ast_channel *chan, const char *data)
{
	struct ast_datastore *store;

	ast_channel_lock(chan);
	store = ast_channel_datastore_find(chan, &odbc_info, data);
	if (store) {
		ast_channel_datastore_remove(chan, store);
		ast_datastore_free(store);
	}
	ast_channel_unlock(chan);
	return 0;
}

static int free_acf_query(struct acf_odbc_query *query)
{
	if (query) {
		if (query->acf) {
			if (query->acf->name)
				ast_free((char *)query->acf->name);
			ast_string_field_free_memory(query->acf);
			ast_free(query->acf);
		}
		ast_free(query->sql_read);
		ast_free(query->sql_write);
		ast_free(query->sql_insert);
		ast_free(query);
	}
	return 0;
}

static int init_acf_query(struct ast_config *cfg, char *catg, struct acf_odbc_query **query)
{
	const char *tmp;
	const char *tmp2 = NULL;
	int i;

	if (!cfg || !catg) {
		return EINVAL;
	}

	if (!(*query = ast_calloc(1, sizeof(**query)))) {
		return ENOMEM;
	}

	if (((tmp = ast_variable_retrieve(cfg, catg, "writehandle"))) || ((tmp = ast_variable_retrieve(cfg, catg, "dsn")))) {
		char *tmp2 = ast_strdupa(tmp);
		AST_DECLARE_APP_ARGS(writeconf,
			AST_APP_ARG(dsn)[5];
		);
		AST_STANDARD_APP_ARGS(writeconf, tmp2);
		for (i = 0; i < 5; i++) {
			if (!ast_strlen_zero(writeconf.dsn[i]))
				ast_copy_string((*query)->writehandle[i], writeconf.dsn[i], sizeof((*query)->writehandle[i]));
		}
	}

	if ((tmp = ast_variable_retrieve(cfg, catg, "readhandle"))) {
		char *tmp2 = ast_strdupa(tmp);
		AST_DECLARE_APP_ARGS(readconf,
			AST_APP_ARG(dsn)[5];
		);
		AST_STANDARD_APP_ARGS(readconf, tmp2);
		for (i = 0; i < 5; i++) {
			if (!ast_strlen_zero(readconf.dsn[i]))
				ast_copy_string((*query)->readhandle[i], readconf.dsn[i], sizeof((*query)->readhandle[i]));
		}
	} else {
		/* If no separate readhandle, then use the writehandle for reading */
		for (i = 0; i < 5; i++) {
			if (!ast_strlen_zero((*query)->writehandle[i]))
				ast_copy_string((*query)->readhandle[i], (*query)->writehandle[i], sizeof((*query)->readhandle[i]));
		}
	}

	if ((tmp = ast_variable_retrieve(cfg, catg, "readsql")) ||
			(tmp2 = ast_variable_retrieve(cfg, catg, "read"))) {
		if (!tmp) {
			ast_log_chan(NULL, LOG_WARNING, "Parameter 'read' is deprecated for category %s.  Please use 'readsql' instead.\n", catg);
			tmp = tmp2;
		}
		if (*tmp != '\0') { /* non-empty string */
			if (!((*query)->sql_read = ast_strdup(tmp))) {
				free_acf_query(*query);
				*query = NULL;
				return ENOMEM;
			}
		}
	}

	if ((*query)->sql_read && ast_strlen_zero((*query)->readhandle[0])) {
		free_acf_query(*query);
		*query = NULL;
		ast_log_chan(NULL, LOG_ERROR, "There is SQL, but no ODBC class to be used for reading: %s\n", catg);
		return EINVAL;
	}

	if ((tmp = ast_variable_retrieve(cfg, catg, "writesql")) ||
			(tmp2 = ast_variable_retrieve(cfg, catg, "write"))) {
		if (!tmp) {
			ast_log_chan(NULL, LOG_WARNING, "Parameter 'write' is deprecated for category %s.  Please use 'writesql' instead.\n", catg);
			tmp = tmp2;
		}
		if (*tmp != '\0') { /* non-empty string */
			if (!((*query)->sql_write = ast_strdup(tmp))) {
				free_acf_query(*query);
				*query = NULL;
				return ENOMEM;
			}
		}
	}

	if ((*query)->sql_write && ast_strlen_zero((*query)->writehandle[0])) {
		free_acf_query(*query);
		*query = NULL;
		ast_log_chan(NULL, LOG_ERROR, "There is SQL, but no ODBC class to be used for writing: %s\n", catg);
		return EINVAL;
	}

	if ((tmp = ast_variable_retrieve(cfg, catg, "insertsql"))) {
		if (*tmp != '\0') { /* non-empty string */
			if (!((*query)->sql_insert = ast_strdup(tmp))) {
				free_acf_query(*query);
				*query = NULL;
				return ENOMEM;
			}
		}
	}

	/* Allow escaping of embedded commas in fields to be turned off */
	ast_set_flag((*query), OPT_ESCAPECOMMAS);
	if ((tmp = ast_variable_retrieve(cfg, catg, "escapecommas"))) {
		if (ast_false(tmp))
			ast_clear_flag((*query), OPT_ESCAPECOMMAS);
	}

	if ((tmp = ast_variable_retrieve(cfg, catg, "mode"))) {
		if (strcasecmp(tmp, "multirow") == 0)
			ast_set_flag((*query), OPT_MULTIROW);
		if ((tmp = ast_variable_retrieve(cfg, catg, "rowlimit")))
			sscanf(tmp, "%30d", &((*query)->rowlimit));
	}

	if ((tmp = ast_variable_retrieve(cfg, catg, "minargs"))) {
		sscanf(tmp, "%30d", &((*query)->minargs));
	}

	(*query)->acf = ast_calloc(1, sizeof(struct ast_custom_function));
	if (!(*query)->acf) {
		free_acf_query(*query);
		*query = NULL;
		return ENOMEM;
	}
	if (ast_string_field_init((*query)->acf, 128)) {
		free_acf_query(*query);
		*query = NULL;
		return ENOMEM;
	}

	if ((tmp = ast_variable_retrieve(cfg, catg, "prefix")) && !ast_strlen_zero(tmp)) {
		if (ast_asprintf((char **)&((*query)->acf->name), "%s_%s", tmp, catg) < 0) {
			(*query)->acf->name = NULL;
		}
	} else {
		if (ast_asprintf((char **)&((*query)->acf->name), "ODBC_%s", catg) < 0) {
			(*query)->acf->name = NULL;
		}
	}

	if (!(*query)->acf->name) {
		free_acf_query(*query);
		*query = NULL;
		return ENOMEM;
	}

	if ((tmp = ast_variable_retrieve(cfg, catg, "syntax")) && !ast_strlen_zero(tmp)) {
		ast_string_field_build((*query)->acf, syntax, "%s(%s)", (*query)->acf->name, tmp);
	} else {
		ast_string_field_build((*query)->acf, syntax, "%s(<arg1>[...[,<argN>]])", (*query)->acf->name);
	}

	if (ast_strlen_zero((*query)->acf->syntax)) {
		free_acf_query(*query);
		*query = NULL;
		return ENOMEM;
	}

	if ((tmp = ast_variable_retrieve(cfg, catg, "synopsis")) && !ast_strlen_zero(tmp)) {
		ast_string_field_set((*query)->acf, synopsis, tmp);
	} else {
		ast_string_field_set((*query)->acf, synopsis, "Runs the referenced query with the specified arguments");
	}

	if (ast_strlen_zero((*query)->acf->synopsis)) {
		free_acf_query(*query);
		*query = NULL;
		return ENOMEM;
	}

	if ((*query)->sql_read && (*query)->sql_write) {
		ast_string_field_build((*query)->acf, desc,
					"Runs the following query, as defined in func_odbc.conf, performing\n"
					"substitution of the arguments into the query as specified by ${ARG1},\n"
					"${ARG2}, ... ${ARGn}.  When setting the function, the values are provided\n"
					"either in whole as ${VALUE} or parsed as ${VAL1}, ${VAL2}, ... ${VALn}.\n"
					"%s"
					"\nRead:\n%s\n\nWrite:\n%s%s%s",
					(*query)->sql_insert ?
						"If the write query affects no rows, the insert query will be\n"
						"performed.\n" : "",
					(*query)->sql_read,
					(*query)->sql_write,
					(*query)->sql_insert ? "\n\nInsert:\n" : "",
					(*query)->sql_insert ? (*query)->sql_insert : "");
	} else if ((*query)->sql_read) {
		ast_string_field_build((*query)->acf, desc,
					"Runs the following query, as defined in func_odbc.conf, performing\n"
					"substitution of the arguments into the query as specified by ${ARG1},\n"
					"${ARG2}, ... ${ARGn}.  This function may only be read, not set.\n\nSQL:\n%s",
					(*query)->sql_read);
	} else if ((*query)->sql_write) {
		ast_string_field_build((*query)->acf, desc,
					"Runs the following query, as defined in func_odbc.conf, performing\n"
					"substitution of the arguments into the query as specified by ${ARG1},\n"
					"${ARG2}, ... ${ARGn}.  The values are provided either in whole as\n"
					"${VALUE} or parsed as ${VAL1}, ${VAL2}, ... ${VALn}.\n"
					"This function may only be set.\n%s\nSQL:\n%s%s%s",
					(*query)->sql_insert ?
						"If the write query affects no rows, the insert query will be\n"
						"performed.\n" : "",
					(*query)->sql_write,
					(*query)->sql_insert ? "\n\nInsert:\n" : "",
					(*query)->sql_insert ? (*query)->sql_insert : "");
	} else {
		free_acf_query(*query);
		*query = NULL;
		ast_log_chan(NULL, LOG_WARNING, "Section '%s' was found, but there was no SQL to execute.  Ignoring.\n", catg);
		return EINVAL;
	}

	if (ast_strlen_zero((*query)->acf->desc)) {
		free_acf_query(*query);
		*query = NULL;
		return ENOMEM;
	}

	if ((*query)->sql_read) {
		(*query)->acf->read = acf_odbc_read;
	}

	if ((*query)->sql_write) {
		(*query)->acf->write = acf_odbc_write;
	}

	return 0;
}

static char *cli_odbc_read(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
{
	AST_DECLARE_APP_ARGS(args,
		AST_APP_ARG(field)[100];
	);
	struct ast_str *sql;
	char *char_args, varname[15];
	struct acf_odbc_query *query;
	struct ast_channel *chan;
	int i;

	switch (cmd) {
	case CLI_INIT:
		e->command = "odbc read";
		e->usage =
			"Usage: odbc read <name> <args> [exec]\n"
			"       Evaluates the SQL provided in the ODBC function <name>, and\n"
			"       optionally executes the function.  This function is intended for\n"
			"       testing purposes.  Remember to quote arguments containing spaces.\n";
		return NULL;
	case CLI_GENERATE:
		if (a->pos == 2) {
			int wordlen = strlen(a->word), which = 0;
			/* Complete function name */
			AST_RWLIST_RDLOCK(&queries);
			AST_RWLIST_TRAVERSE(&queries, query, list) {
				if (!strncasecmp(query->acf->name, a->word, wordlen)) {
					if (++which > a->n) {
						char *res = ast_strdup(query->acf->name);
						AST_RWLIST_UNLOCK(&queries);
						return res;
					}
				}
			}
			AST_RWLIST_UNLOCK(&queries);
			return NULL;
		} else if (a->pos == 4) {
			static const char * const completions[] = { "exec", NULL };
			return ast_cli_complete(a->word, completions, a->n);
		} else {
			return NULL;
		}
	}

	if (a->argc < 4 || a->argc > 5) {
		return CLI_SHOWUSAGE;
	}

	sql = ast_str_thread_get(&sql_buf, 16);
	if (!sql) {
		return CLI_FAILURE;
	}

	AST_RWLIST_RDLOCK(&queries);
	AST_RWLIST_TRAVERSE(&queries, query, list) {
		if (!strcmp(query->acf->name, a->argv[2])) {
			break;
		}
	}

	if (!query) {
		ast_cli(a->fd, "No such query '%s'\n", a->argv[2]);
		AST_RWLIST_UNLOCK(&queries);
		return CLI_SHOWUSAGE;
	}

	if (!query->sql_read) {
		ast_cli(a->fd, "The function %s has no readsql parameter.\n", a->argv[2]);
		AST_RWLIST_UNLOCK(&queries);
		return CLI_SUCCESS;
	}

	ast_str_make_space(&sql, strlen(query->sql_read) * 2 + 300);

	/* Evaluate function */
	char_args = ast_strdupa(a->argv[3]);

	chan = ast_dummy_channel_alloc();
	if (!chan) {
		AST_RWLIST_UNLOCK(&queries);
		return CLI_FAILURE;
	}

	AST_STANDARD_APP_ARGS(args, char_args);
	for (i = 0; i < args.argc; i++) {
		snprintf(varname, sizeof(varname), "ARG%d", i + 1);
		pbx_builtin_pushvar_helper(chan, varname, args.field[i]);
	}

	ast_str_substitute_variables(&sql, 0, chan, query->sql_read);
	chan = ast_channel_unref(chan);

	if (a->argc == 5 && !strcmp(a->argv[4], "exec")) {
		/* Execute the query */
		struct odbc_obj *obj = NULL;
		struct dsn *dsn = NULL;
		int dsn_num, executed = 0;
		SQLHSTMT stmt;
		int rows = 0, res, x;
		SQLSMALLINT colcount = 0, collength;
		SQLLEN indicator, octetlength;
		struct ast_str *coldata = ast_str_thread_get(&coldata_buf, 16);
		char colname[256];

		if (!coldata) {
			AST_RWLIST_UNLOCK(&queries);
			return CLI_SUCCESS;
		}

		for (dsn_num = 0; dsn_num < 5; dsn_num++) {
			if (ast_strlen_zero(query->readhandle[dsn_num])) {
				continue;
			}
			obj = get_odbc_obj(query->readhandle[dsn_num], &dsn);
			if (!obj) {
				continue;
			}
			ast_debug(1, "Found handle %s\n", query->readhandle[dsn_num]);

			if (!(stmt = ast_odbc_direct_execute(obj, generic_execute, ast_str_buffer(sql)))) {
				release_obj_or_dsn (&obj, &dsn);
				continue;
			}

			executed = 1;

			res = SQLNumResultCols(stmt, &colcount);
			if ((res != SQL_SUCCESS) && (res != SQL_SUCCESS_WITH_INFO)) {
				ast_cli(a->fd, "SQL Column Count error!\n[%s]\n\n", ast_str_buffer(sql));
				SQLCloseCursor(stmt);
				SQLFreeHandle (SQL_HANDLE_STMT, stmt);
				release_obj_or_dsn (&obj, &dsn);
				AST_RWLIST_UNLOCK(&queries);
				return CLI_SUCCESS;
			}

			if (colcount <= 0) {
				SQLCloseCursor(stmt);
				SQLFreeHandle (SQL_HANDLE_STMT, stmt);
				release_obj_or_dsn (&obj, &dsn);
				ast_cli(a->fd, "Returned %d columns.  Query executed on handle %d:%s [%s]\n", colcount, dsn_num, query->readhandle[dsn_num], ast_str_buffer(sql));
				AST_RWLIST_UNLOCK(&queries);
				return CLI_SUCCESS;
			}

			res = SQLFetch(stmt);
			if ((res != SQL_SUCCESS) && (res != SQL_SUCCESS_WITH_INFO)) {
				SQLCloseCursor(stmt);
				SQLFreeHandle(SQL_HANDLE_STMT, stmt);
				release_obj_or_dsn (&obj, &dsn);
				if (res == SQL_NO_DATA) {
					ast_cli(a->fd, "Returned %d rows.  Query executed on handle %d:%s [%s]\n", rows, dsn_num, query->readhandle[dsn_num], ast_str_buffer(sql));
					break;
				} else {
					ast_cli(a->fd, "Error %d in FETCH [%s]\n", res, ast_str_buffer(sql));
				}
				AST_RWLIST_UNLOCK(&queries);
				return CLI_SUCCESS;
			}
			for (;;) {
				for (x = 0; x < colcount; x++) {
					res = SQLDescribeCol(stmt, x + 1, (unsigned char *)colname, sizeof(colname), &collength, NULL, NULL, NULL, NULL);
					if (((res != SQL_SUCCESS) && (res != SQL_SUCCESS_WITH_INFO)) || collength == 0) {
						snprintf(colname, sizeof(colname), "field%d", x);
					}

					octetlength = 0;
					SQLColAttribute(stmt, x + 1, SQL_DESC_OCTET_LENGTH, NULL, 0, NULL, &octetlength);

					res = ast_odbc_ast_str_SQLGetData(&coldata, octetlength + 1, stmt, x + 1, SQL_CHAR, &indicator);
					if (indicator == SQL_NULL_DATA) {
						ast_str_set(&coldata, 0, "(nil)");
						res = SQL_SUCCESS;
					}

					if ((res != SQL_SUCCESS) && (res != SQL_SUCCESS_WITH_INFO)) {
						ast_cli(a->fd, "SQL Get Data error %d!\n[%s]\n\n", res, ast_str_buffer(sql));
						SQLCloseCursor(stmt);
						SQLFreeHandle(SQL_HANDLE_STMT, stmt);
						release_obj_or_dsn (&obj, &dsn);
						AST_RWLIST_UNLOCK(&queries);
						return CLI_SUCCESS;
					}

					ast_cli(a->fd, "%-20.20s  %s\n", colname, ast_str_buffer(coldata));
				}
				rows++;

				/* Get next row */
				res = SQLFetch(stmt);
				if ((res != SQL_SUCCESS) && (res != SQL_SUCCESS_WITH_INFO)) {
					break;
				}
				ast_cli(a->fd, "%-20.20s  %s\n", "----------", "----------");
			}
			SQLCloseCursor(stmt);
			SQLFreeHandle(SQL_HANDLE_STMT, stmt);
			release_obj_or_dsn (&obj, &dsn);
			ast_cli(a->fd, "Returned %d row%s.  Query executed on handle %d [%s]\n", rows, rows == 1 ? "" : "s", dsn_num, query->readhandle[dsn_num]);
			break;
		}
		release_obj_or_dsn (&obj, &dsn);

		if (!executed) {
			ast_cli(a->fd, "Failed to execute query. [%s]\n", ast_str_buffer(sql));
		}
	} else { /* No execution, just print out the resulting SQL */
		ast_cli(a->fd, "%s\n", ast_str_buffer(sql));
	}
	AST_RWLIST_UNLOCK(&queries);
	return CLI_SUCCESS;
}

static char *cli_odbc_write(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
{
	AST_DECLARE_APP_ARGS(values,
		AST_APP_ARG(field)[100];
	);
	AST_DECLARE_APP_ARGS(args,
		AST_APP_ARG(field)[100];
	);
	struct ast_str *sql;
	char *char_args, *char_values, varname[15];
	struct acf_odbc_query *query;
	struct ast_channel *chan;
	int i;

	switch (cmd) {
	case CLI_INIT:
		e->command = "odbc write";
		e->usage =
			"Usage: odbc write <name> <args> <value> [exec]\n"
			"       Evaluates the SQL provided in the ODBC function <name>, and\n"
			"       optionally executes the function.  This function is intended for\n"
			"       testing purposes.  Remember to quote arguments containing spaces.\n";
		return NULL;
	case CLI_GENERATE:
		if (a->pos == 2) {
			int wordlen = strlen(a->word), which = 0;
			/* Complete function name */
			AST_RWLIST_RDLOCK(&queries);
			AST_RWLIST_TRAVERSE(&queries, query, list) {
				if (!strncasecmp(query->acf->name, a->word, wordlen)) {
					if (++which > a->n) {
						char *res = ast_strdup(query->acf->name);
						AST_RWLIST_UNLOCK(&queries);
						return res;
					}
				}
			}
			AST_RWLIST_UNLOCK(&queries);
			return NULL;
		} else if (a->pos == 5) {
			static const char * const completions[] = { "exec", NULL };
			return ast_cli_complete(a->word, completions, a->n);
		} else {
			return NULL;
		}
	}

	if (a->argc < 5 || a->argc > 6) {
		return CLI_SHOWUSAGE;
	}

	sql = ast_str_thread_get(&sql_buf, 16);
	if (!sql) {
		return CLI_FAILURE;
	}

	AST_RWLIST_RDLOCK(&queries);
	AST_RWLIST_TRAVERSE(&queries, query, list) {
		if (!strcmp(query->acf->name, a->argv[2])) {
			break;
		}
	}

	if (!query) {
		ast_cli(a->fd, "No such query '%s'\n", a->argv[2]);
		AST_RWLIST_UNLOCK(&queries);
		return CLI_SHOWUSAGE;
	}

	if (!query->sql_write) {
		ast_cli(a->fd, "The function %s has no writesql parameter.\n", a->argv[2]);
		AST_RWLIST_UNLOCK(&queries);
		return CLI_SUCCESS;
	}

	/* FIXME: The code below duplicates code found in acf_odbc_write but
	 * lacks the newer sql_insert additions. */

	ast_str_make_space(&sql, strlen(query->sql_write) * 2 + 300);

	/* Evaluate function */
	char_args = ast_strdupa(a->argv[3]);
	char_values = ast_strdupa(a->argv[4]);

	chan = ast_dummy_channel_alloc();
	if (!chan) {
		AST_RWLIST_UNLOCK(&queries);
		return CLI_FAILURE;
	}

	AST_STANDARD_APP_ARGS(args, char_args);
	for (i = 0; i < args.argc; i++) {
		snprintf(varname, sizeof(varname), "ARG%d", i + 1);
		pbx_builtin_pushvar_helper(chan, varname, args.field[i]);
	}

	/* Parse values, just like arguments */
	AST_STANDARD_APP_ARGS(values, char_values);
	for (i = 0; i < values.argc; i++) {
		snprintf(varname, sizeof(varname), "VAL%d", i + 1);
		pbx_builtin_pushvar_helper(chan, varname, values.field[i]);
	}

	/* Additionally set the value as a whole (but push an empty string if value is NULL) */
	pbx_builtin_pushvar_helper(chan, "VALUE", S_OR(a->argv[4], ""));
	ast_str_substitute_variables(&sql, 0, chan, query->sql_write);
	ast_debug(1, "SQL is %s\n", ast_str_buffer(sql));

	chan = ast_channel_unref(chan);

	if (a->argc == 6 && !strcmp(a->argv[5], "exec")) {
		/* Execute the query */
		struct odbc_obj *obj = NULL;
		struct dsn *dsn = NULL;
		int dsn_num, executed = 0;
		SQLHSTMT stmt;
		SQLLEN rows = -1;

		for (dsn_num = 0; dsn_num < 5; dsn_num++) {
			if (ast_strlen_zero(query->writehandle[dsn_num])) {
				continue;
			}
			obj = get_odbc_obj(query->writehandle[dsn_num], &dsn);
			if (!obj) {
				continue;
			}
			if (!(stmt = ast_odbc_direct_execute(obj, generic_execute, ast_str_buffer(sql)))) {
				release_obj_or_dsn (&obj, &dsn);
				continue;
			}

			SQLRowCount(stmt, &rows);
			SQLCloseCursor(stmt);
			SQLFreeHandle(SQL_HANDLE_STMT, stmt);
			release_obj_or_dsn (&obj, &dsn);
			ast_cli(a->fd, "Affected %d rows.  Query executed on handle %d [%s]\n", (int)rows, dsn_num, query->writehandle[dsn_num]);
			executed = 1;
			break;
		}

		if (!executed) {
			ast_cli(a->fd, "Failed to execute query.\n");
		}
	} else { /* No execution, just print out the resulting SQL */
		ast_cli(a->fd, "%s\n", ast_str_buffer(sql));
	}
	AST_RWLIST_UNLOCK(&queries);
	return CLI_SUCCESS;
}

static struct ast_cli_entry cli_func_odbc[] = {
	AST_CLI_DEFINE(cli_odbc_write, "Test setting a func_odbc function"),
	AST_CLI_DEFINE(cli_odbc_read, "Test reading a func_odbc function"),
};

static int load_module(void)
{
	int res = 0;
	struct ast_config *cfg;
	char *catg;
	const char *s;
	struct ast_flags config_flags = { 0 };

	res |= ast_custom_function_register(&fetch_function);
	res |= ast_register_application_xml(app_odbcfinish, exec_odbcfinish);

	cfg = ast_config_load(config, config_flags);
	if (!cfg || cfg == CONFIG_STATUS_FILEINVALID) {
		ast_log_chan(NULL, LOG_NOTICE, "Unable to load config for func_odbc: %s\n", config);
		return AST_MODULE_LOAD_DECLINE;
	}

	ast_rwlock_wrlock(&single_db_connection_lock);
	if ((s = ast_variable_retrieve(cfg, "general", "single_db_connection"))) {
		single_db_connection = ast_true(s);
	} else {
		single_db_connection = DEFAULT_SINGLE_DB_CONNECTION;
	}

	dsns = NULL;

	if (single_db_connection) {
		dsns = ao2_container_alloc_hash(AO2_ALLOC_OPT_LOCK_MUTEX, 0, DSN_BUCKETS,
			dsn_hash, NULL, dsn_cmp);
		if (!dsns) {
			ast_log_chan(NULL, LOG_ERROR, "Could not initialize DSN container\n");
			ast_rwlock_unlock(&single_db_connection_lock);
			return AST_MODULE_LOAD_DECLINE;
		}
	}
	ast_rwlock_unlock(&single_db_connection_lock);

	AST_RWLIST_WRLOCK(&queries);
	for (catg = ast_category_browse(cfg, NULL);
	     catg;
	     catg = ast_category_browse(cfg, catg)) {
		struct acf_odbc_query *query = NULL;
		int err;

		if (!strcasecmp(catg, "general")) {
			continue;
		}

		if ((err = init_acf_query(cfg, catg, &query))) {
			if (err == ENOMEM)
				ast_log_chan(NULL, LOG_ERROR, "Out of memory\n");
			else if (err == EINVAL)
				ast_log_chan(NULL, LOG_ERROR, "Invalid parameters for category %s\n", catg);
			else
				ast_log_chan(NULL, LOG_ERROR, "%s (%d)\n", strerror(err), err);
		} else {
			AST_RWLIST_INSERT_HEAD(&queries, query, list);
			ast_custom_function_register(query->acf);
		}
	}

	ast_config_destroy(cfg);
	res |= ast_custom_function_register(&escape_function);
	res |= ast_custom_function_register(&escape_backslashes_function);
	ast_cli_register_multiple(cli_func_odbc, ARRAY_LEN(cli_func_odbc));

	AST_RWLIST_UNLOCK(&queries);
	return res;
}

static int unload_module(void)
{
	struct acf_odbc_query *query;
	int res = 0;

	AST_RWLIST_WRLOCK(&queries);
	while (!AST_RWLIST_EMPTY(&queries)) {
		query = AST_RWLIST_REMOVE_HEAD(&queries, list);
		ast_custom_function_unregister(query->acf);
		free_acf_query(query);
	}

	res |= ast_custom_function_unregister(&escape_function);
	res |= ast_custom_function_unregister(&escape_backslashes_function);
	res |= ast_custom_function_unregister(&fetch_function);
	res |= ast_unregister_application(app_odbcfinish);
	ast_cli_unregister_multiple(cli_func_odbc, ARRAY_LEN(cli_func_odbc));

	/* Allow any threads waiting for this lock to pass (avoids a race) */
	AST_RWLIST_UNLOCK(&queries);
	usleep(1);
	AST_RWLIST_WRLOCK(&queries);

	AST_RWLIST_UNLOCK(&queries);

	if (dsns) {
		ao2_ref(dsns, -1);
	}
	return res;
}

static int reload(void)
{
	int res = 0;
	struct ast_config *cfg;
	struct acf_odbc_query *oldquery;
	char *catg;
	const char *s;
	struct ast_flags config_flags = { CONFIG_FLAG_FILEUNCHANGED };

	cfg = ast_config_load(config, config_flags);
	if (cfg == CONFIG_STATUS_FILEUNCHANGED || cfg == CONFIG_STATUS_FILEINVALID)
		return 0;

	ast_rwlock_wrlock(&single_db_connection_lock);

	if (dsns) {
		ao2_ref(dsns, -1);
		dsns = NULL;
	}

	if (cfg && (s = ast_variable_retrieve(cfg, "general", "single_db_connection"))) {
		single_db_connection = ast_true(s);
	} else {
		single_db_connection = DEFAULT_SINGLE_DB_CONNECTION;
	}

	if (single_db_connection) {
		dsns = ao2_container_alloc_hash(AO2_ALLOC_OPT_LOCK_MUTEX, 0, DSN_BUCKETS,
			dsn_hash, NULL, dsn_cmp);
		if (!dsns) {
			ast_log_chan(NULL, LOG_ERROR, "Could not initialize DSN container\n");
			ast_rwlock_unlock(&single_db_connection_lock);
			return 0;
		}
	}
	ast_rwlock_unlock(&single_db_connection_lock);

	AST_RWLIST_WRLOCK(&queries);

	while (!AST_RWLIST_EMPTY(&queries)) {
		oldquery = AST_RWLIST_REMOVE_HEAD(&queries, list);
		ast_custom_function_unregister(oldquery->acf);
		free_acf_query(oldquery);
	}

	if (!cfg) {
		ast_log_chan(NULL, LOG_WARNING, "Unable to load config for func_odbc: %s\n", config);
		goto reload_out;
	}

	for (catg = ast_category_browse(cfg, NULL);
	     catg;
	     catg = ast_category_browse(cfg, catg)) {
		struct acf_odbc_query *query = NULL;

		if (!strcasecmp(catg, "general")) {
			continue;
		}

		if (init_acf_query(cfg, catg, &query)) {
			ast_log_chan(NULL, LOG_ERROR, "Cannot initialize query %s\n", catg);
		} else {
			AST_RWLIST_INSERT_HEAD(&queries, query, list);
			ast_custom_function_register(query->acf);
		}
	}

	ast_config_destroy(cfg);
reload_out:
	AST_RWLIST_UNLOCK(&queries);
	return res;
}

/* XXX need to revise usecount - set if query_lock is set */

AST_MODULE_INFO(GABPBX_GPL_KEY, AST_MODFLAG_DEFAULT, "ODBC lookups",
	.support_level = AST_MODULE_SUPPORT_CORE,
	.load = load_module,
	.unload = unload_module,
	.reload = reload,
	.requires = "res_odbc",
);
