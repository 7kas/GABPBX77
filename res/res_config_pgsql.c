/*
 * GABpbx -- An open source telephony toolkit.
 *
 * Copyright (C) 1999 - 2017, Digium, Inc.
 *
 * Manuel Guesdon <mguesdon@oxymium.net> - PostgreSQL RealTime Driver Author/Adaptor
 * Mark Spencer <markster@digium.com>  - GABpbx Author
 * Matthew Boehm <mboehm@cytelcom.com> - MySQL RealTime Driver Author
 *
 * res_config_pgsql.c <PostgreSQL plugin for RealTime configuration engine>
 *
 * v1.0   - (07-11-05) - Initial version based on res_config_mysql v2.0
 */

/*! \file
 *
 * \brief PostgreSQL plugin for GABpbx RealTime Architecture
 *
 * \author Mark Spencer <markster@digium.com>
 * \author Manuel Guesdon <mguesdon@oxymium.net> - PostgreSQL RealTime Driver Author/Adaptor
 *
 * PostgreSQL http://www.postgresql.org
 */

/*** MODULEINFO
	<depend>pgsql</depend>
	<support_level>extended</support_level>
 ***/

#include "gabpbx.h"

#include <libpq-fe.h>			/* PostgreSQL */

#include "gabpbx/file.h"
#include "gabpbx/channel.h"
#include "gabpbx/pbx.h"
#include "gabpbx/config.h"
#include "gabpbx/module.h"
#include "gabpbx/lock.h"
#include "gabpbx/utils.h"
#include "gabpbx/cli.h"
#include "gabpbx/paths.h"

AST_MUTEX_DEFINE_STATIC(pgsql_pool);
AST_THREADSTORAGE(sql_buf);
AST_THREADSTORAGE(findtable_buf);
AST_THREADSTORAGE(where_buf);
AST_THREADSTORAGE(escapebuf_buf);
AST_THREADSTORAGE(semibuf_buf);

#define RES_CONFIG_PGSQL_CONF "res_pgsql.conf"

/* germanico */
#define PGSQL_MAX_POOL_CONN 32
static int pgsqlCurrent = 0;

static PGconn *pgsqlConn[PGSQL_MAX_POOL_CONN];
static int pgsqlFlag[PGSQL_MAX_POOL_CONN];
static int pgsqlTime[PGSQL_MAX_POOL_CONN];
static unsigned long long pgsqlUseCount[PGSQL_MAX_POOL_CONN];

static int version;
#define has_schema_support	(version > 70300 ? 1 : 0)
#define USE_BACKSLASH_AS_STRING	(version >= 90100 ? 1 : 0)

#define MAX_DB_OPTION_SIZE 64

struct columns {
	char *name;
	char *type;
	int len;
	unsigned int notnull:1;
	unsigned int hasdefault:1;
	AST_LIST_ENTRY(columns) list;
};

struct tables {
	ast_rwlock_t lock;
	AST_LIST_HEAD_NOLOCK(psql_columns, columns) columns;
	AST_LIST_ENTRY(tables) list;
	char name[0];
};

static AST_LIST_HEAD_STATIC(psql_tables, tables);

static char dbhost[MAX_DB_OPTION_SIZE]    = "";
static char dbuser[MAX_DB_OPTION_SIZE]    = "";
static char dbpass[MAX_DB_OPTION_SIZE]    = "";
static char dbname[MAX_DB_OPTION_SIZE]    = "";
static char dbappname[MAX_DB_OPTION_SIZE] = "";
static char dbsock[MAX_DB_OPTION_SIZE]    = "";
static int dbport = 5432;
static int order_multi_row_results_by_initial_column = 1;

static struct ast_config *pgsql_tablefunc;

AST_MUTEX_DEFINE_STATIC(pgsql_cache_flag);
static pthread_t pgsql_cache_update_thread = AST_PTHREADT_NULL;

struct ast_pgsql_cache {
	char *sql;
	PGresult *res;
	time_t last;
	int update;
	int autokillid; // Auto-kill ID (scheduler)
	uint64_t hash;
};

/* Variables para estadísticas de tráfico UDP */
static unsigned int pgsql_packets_current_minute = 0;
static unsigned int pgsql_packets_last_minute = 0;
static unsigned int pgsql_packets_total = 0;
static time_t pgsql_packets_last_update = 0;
static time_t pgsql_service_start_time = 0;  /* Tiempo de inicio del servicio */
static unsigned int pgsql_cache_updates = 0;
AST_MUTEX_DEFINE_STATIC(pgsql_stats_lock);

static int cache_port;

static struct ast_pgsql_cache *pgsql_cache = NULL;
static int pgsql_cache_items = 0;
static long unsigned pgsql_cache_size = 0;
static int pgsql_cache_max_items = 8000;
static long unsigned pgsql_cache_max_size = 5120000;

static char *rep_quotation(const char *s);
static void *do_pgsql_cache_update(void *data);
static int _pgsql_cache_add(struct ast_pgsql_cache *item);
static int pgsql_cache_add(char *sql, PGresult *res);
static int pgsql_cache_pgresult(int pgsqlC, char *sql, char *func, PGresult **result);
static void pgsql_cache_clear(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a);

static int parse_config(int reload);
static int pgsql_getConn(void);
static int pgsql_reconnect(int pgsqlC);
static char *handle_cli_realtime_pgsql_status(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a);
static char *handle_cli_realtime_pgsql_cache(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a);

static char *handle_cli_realtime_pgsql_cache_clear(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a);

static enum { RQ_WARN, RQ_CREATECLOSE, RQ_CREATECHAR } requirements;

static struct ast_cli_entry cli_realtime[] = {
	AST_CLI_DEFINE(handle_cli_realtime_pgsql_status, "Shows connection information for the PostgreSQL RealTime driver"),
	AST_CLI_DEFINE(handle_cli_realtime_pgsql_cache, "Shows cached tables within the PostgreSQL realtime driver"),
	AST_CLI_DEFINE(handle_cli_realtime_pgsql_cache_clear, "Clear realtime advanced pgsql cache from ram"),
};

/* Variables para estadísticas de caché */
static unsigned long long pgsql_cache_attempts = 0;   /* Total de intentos de consulta a través de caché */
static unsigned long long pgsql_cache_hits = 0;       /* Consultas exitosas desde caché (DB evitada) */
static unsigned long long pgsql_total_db_queries = 0; /* Total consultas reales a la base de datos */

#define ESCAPE_STRING(buffer, stringname, pgsqlC) \
	do { \
		if (!pgsqlConn[pgsqlC]) { \
			ast_log(LOG_ERROR, "ESCAPE_STRING: conexión NULL detectada.\n"); \
			break; \
		} \
		int len = strlen(stringname); \
		struct ast_str *semi = ast_str_thread_get(&semibuf_buf, len * 3 + 1); \
		const char *chunk = stringname; \
		ast_str_reset(semi); \
		for (; *chunk; chunk++) { \
			if (strchr(";^", *chunk)) { \
				ast_str_append(&semi, 0, "^%02hhX", *chunk); \
			} else { \
				ast_str_append(&semi, 0, "%c", *chunk); \
			} \
		} \
		if (ast_str_strlen(semi) > (ast_str_size(buffer) - 1) / 2) { \
			ast_str_make_space(&buffer, ast_str_strlen(semi) * 2 + 1); \
		} \
		PQescapeStringConn(pgsqlConn[pgsqlC], ast_str_buffer(buffer), ast_str_buffer(semi), ast_str_size(buffer), &pgresult); \
	} while (0)

static uint64_t rotl64(uint64_t x, int r) {
    return (x << r) | (x >> (64 - r));
}

static uint64_t XXH64(const void *input, size_t len, uint64_t seed) {
    const uint64_t PRIME64_1 = 11400714785074694791ULL;
    const uint64_t PRIME64_2 = 14029467366897019727ULL;
    const uint64_t PRIME64_3 =  1609587929392839161ULL;
    const uint64_t PRIME64_4 =  9650029242287828579ULL;
    const uint64_t PRIME64_5 =  2870177450012600261ULL;

    const uint8_t* p = (const uint8_t*)input;
    const uint8_t* bEnd = p + len;
    uint64_t h64;

    if (len >= 32) {
        const uint8_t* const limit = bEnd - 32;
        uint64_t v1 = seed + PRIME64_1 + PRIME64_2;
        uint64_t v2 = seed + PRIME64_2;
        uint64_t v3 = seed + 0;
        uint64_t v4 = seed - PRIME64_1;

        do {
            v1 += (*(uint64_t*)p) * PRIME64_2;
            v1 = rotl64(v1, 31);
            v1 *= PRIME64_1;
            p += 8;

            v2 += (*(uint64_t*)p) * PRIME64_2;
            v2 = rotl64(v2, 31);
            v2 *= PRIME64_1;
            p += 8;

            v3 += (*(uint64_t*)p) * PRIME64_2;
            v3 = rotl64(v3, 31);
            v3 *= PRIME64_1;
            p += 8;

            v4 += (*(uint64_t*)p) * PRIME64_2;
            v4 = rotl64(v4, 31);
            v4 *= PRIME64_1;
            p += 8;
        } while (p <= limit);

        h64 = rotl64(v1, 1) + rotl64(v2, 7) + rotl64(v3, 12) + rotl64(v4, 18);
    } else {
        h64 = seed + PRIME64_5;
    }

    h64 += (uint64_t)len;

    while (p + 8 <= bEnd) {
        uint64_t k1 = (*(uint64_t*)p) * PRIME64_2;
        k1 = rotl64(k1, 31);
        k1 *= PRIME64_1;
        h64 ^= k1;
        h64 = rotl64(h64, 27) * PRIME64_1 + PRIME64_4;
        p += 8;
    }

    if (p + 4 <= bEnd) {
        h64 ^= (*(uint32_t*)p) * PRIME64_1;
        h64 = rotl64(h64, 23) * PRIME64_2 + PRIME64_3;
        p += 4;
    }

    while (p < bEnd) {
        h64 ^= (*p) * PRIME64_5;
        h64 = rotl64(h64, 11) * PRIME64_1;
        p++;
    }

    h64 ^= h64 >> 33;
    h64 *= PRIME64_2;
    h64 ^= h64 >> 29;
    h64 *= PRIME64_3;
    h64 ^= h64 >> 32;

    return h64;
}

char *rep_quotation(const char *s)
{
	if (!s) {
		return NULL;
	}

	size_t len = 0;
	const char *p = s;

	while (*p) {
		switch (*p) {
			case '\'':
				len += 2; /* // -> \' */
				break;
			case '"':
				len += 2; /* // -> \" */
				break;
			case '_':
				len += 2; /* // -> \_ */
				break;
			case '\\':
				len += 2; /* // -> \\ */
				break;
			default:
				len++;
		}
		p++;
	}

	char *dst = ast_malloc(len + 1);
	if (!dst) {
		return NULL;
	}

	char *q = dst;
	while (*s) {
		switch (*s) {
			case '\'':
				*q++ = '\\';
				*q++ = '\'';
				break;
			case '"':
				*q++ = '\\';
				*q++ = '"';
				break;
			case '_':
				*q++ = '\\';
				*q++ = '_';
				break;
			case '\\':
				*q++ = '\\';
				*q++ = '\\';
				break;
			default:
				*q++ = *s;
		}
		s++;
	}
	*q = '\0';

	return dst;
}

static void destroy_table(struct tables *table)
{
	struct columns *column;
	ast_rwlock_wrlock(&table->lock);
	while ((column = AST_LIST_REMOVE_HEAD(&table->columns, list))) {
		ast_free(column);
	}
	ast_rwlock_unlock(&table->lock);
	ast_rwlock_destroy(&table->lock);
	ast_free(table);
}

/*! \brief Helper function for pgsql_exec.  For running queries, use pgsql_exec()
 *
 *  Connect if not currently connected.  Run the given query.
 *
 *  \param database   database name we are connected to (used for error logging)
 *  \param tablename  table  name we are connected to (used for error logging)
 *  \param sql        sql query string to execute
 *  \param result     pointer for where to store the result handle
 *
 *  \return -1 on fatal query error
 *  \return -2 on query failure that resulted in disconnection
 *  \return 0 on success
 *
 *  \note see pgsql_exec for full example
 */
static int _pgsql_exec(const int pgsqlC, const char *sql, const char *func, const char *keyfield, PGresult **result)
{
	ExecStatusType result_status;
	char cmd[1024];
	char *sql2 = NULL;

	pgsqlUseCount[pgsqlC]++;

	if (!pgsqlConn[pgsqlC]) {
		ast_debug(1, "PostgreSQL connection not defined, connecting\n");

		if (pgsql_reconnect(pgsqlC) != 1) {
			ast_log_chan(NULL, LOG_NOTICE, "reconnect failed\n");
			*result = NULL;
			return -1;
		}

		ast_debug(1, "PostgreSQL connection successful\n");
	}

	if (func) {
		sql2 = rep_quotation(sql);
		if (!keyfield) {
			snprintf(cmd, sizeof(cmd), "SELECT * FROM %s(E'%s', '%s')", func, sql2, ast_config_AST_SYSTEM_NAME);
		} else {
			snprintf(cmd, sizeof(cmd), "SELECT * FROM %s(E'%s', '%s', %i, '%s')", func, sql2, \
				ast_config_AST_SYSTEM_NAME, *ast_config_AST_SYSTEM_ROOT, keyfield);
		}
	} else {
		ast_copy_string(cmd, sql, sizeof(cmd));
	}

	if (option_debug > 3)
		ast_log_chan(NULL, LOG_DEBUG, "Postgresql Realtime pgsql pool %i\n", pgsqlC);

	*result = PQexec(pgsqlConn[pgsqlC], cmd);
	result_status = PQresultStatus(*result);
	if (result_status != PGRES_COMMAND_OK
		&& result_status != PGRES_TUPLES_OK
		&& result_status != PGRES_NONFATAL_ERROR) {

		ast_log_chan(NULL, LOG_ERROR, "PostgreSQL RealTime: Query Failed: %s\n", sql);
		ast_log_chan(NULL, LOG_ERROR, "PostgreSQL RealTime: Query Failed because: %s (%s)\n",
			PQresultErrorMessage(*result),
			PQresStatus(result_status));

		/* we may have tried to run a command on a disconnected/disconnecting handle */
		/* are we no longer connected to the database... if not try again */
		if (PQstatus(pgsqlConn[pgsqlC]) != CONNECTION_OK) {
			PQfinish(pgsqlConn[pgsqlC]);
			pgsqlConn[pgsqlC] = NULL;
			if (sql2) {
				ast_free(sql2);
			}
			return -2;
		}

		/* connection still okay, which means the query is just plain bad */
		if (sql2) {
			ast_free(sql2);
		}
		return -1;
	}

	ast_debug(1, "PostgreSQL query successful: %s\n", cmd);
	if (sql2) {
		ast_free(sql2);
	}
	return 0;
}

/*! \brief Do a postgres query, with reconnection support
 *
 *  Connect if not currently connected.  Run the given query
 *  and if we're disconnected afterwards, reconnect and query again.
 *
 *  \param database   database name we are connected to (used for error logging)
 *  \param tablename  table  name we are connected to (used for error logging)
 *  \param sql        sql query string to execute
 *  \param result     pointer for where to store the result handle
 *
 *  \return -1 on query failure
 *  \return 0 on success
 *
 *  \code
 *	int i, rows;
 *	PGresult *result;
 *	char *field_name, *field_type, *field_len, *field_notnull, *field_default;
 *
 *	pgsql_exec("db", "table", "SELECT 1", &result)
 *
 *	rows = PQntuples(result);
 *	for (i = 0; i < rows; i++) {
 *		field_name    = PQgetvalue(result, i, 0);
 *		field_type    = PQgetvalue(result, i, 1);
 *		field_len     = PQgetvalue(result, i, 2);
 *		field_notnull = PQgetvalue(result, i, 3);
 *		field_default = PQgetvalue(result, i, 4);
 *	}
 *  \endcode
 */
static int pgsql_getConn(void)
{
	int res;

	ast_mutex_lock(&pgsql_pool);
	pgsqlCurrent++;
	if (pgsqlCurrent >= PGSQL_MAX_POOL_CONN) {
		pgsqlCurrent = 0;
	}

	// Buscar conexión libre
	int start = pgsqlCurrent;
	while (pgsqlFlag[pgsqlCurrent]) {
		pgsqlCurrent++;
		if (pgsqlCurrent >= PGSQL_MAX_POOL_CONN) {
			pgsqlCurrent = 0;
		}
		if (pgsqlCurrent == start) {
			// No hay conexiones libres
			ast_mutex_unlock(&pgsql_pool);
			ast_log(LOG_ERROR, "No available PostgreSQL connection slots\n");
			return -1;
		}
	}
	pgsqlFlag[pgsqlCurrent] = 1;
	res = pgsqlCurrent;
	ast_mutex_unlock(&pgsql_pool);

	// Si no existe la conexión, intenta conectar
	if (!pgsqlConn[res]) {
		ast_debug(1, "PostgreSQL connection not defined, connecting\n");
		if (pgsql_reconnect(res) != 1) {
			ast_log_chan(NULL, LOG_NOTICE, "reconnect failed\n");
			pgsqlFlag[res] = 0; // liberar el slot
			return -1;
		}
		ast_debug(1, "PostgreSQL connection successful\n");
	}

	// Validar que la conexión esté realmente viva
	if (PQstatus(pgsqlConn[res]) != CONNECTION_OK) {
		ast_log_chan(NULL, LOG_ERROR, "PostgreSQL connection is not OK after reconnect\n");
		PQfinish(pgsqlConn[res]);
		pgsqlConn[res] = NULL;
		pgsqlFlag[res] = 0;
		return -1;
	}

	return res;
}

static int pgsql_exec(const int pgsqlC, const char *sql, const char *func, const char *keyfield, PGresult **result)
{
	int res;

	/* Incrementar contador de consultas reales a la DB */
	ast_mutex_lock(&pgsql_stats_lock);
	pgsql_total_db_queries++;
	ast_mutex_unlock(&pgsql_stats_lock);


	res = _pgsql_exec(pgsqlC, sql, func, keyfield, result);

	return res;
}

static void *do_pgsql_cache_update(void *data)
{
	int sock, ret, flags, batch_size = 0;
	int udp_processed = 0;
	socklen_t fromlen;
	struct sockaddr_in server, from;
	char buf[16384]; /* Buffer más grande para mejor rendimiento */
	struct timeval tv;
	
	/* Guardar el tiempo de inicio del servicio */
	pgsql_service_start_time = time(NULL);
	
	/* Crear socket */
	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0) {
		ast_log_chan(NULL, LOG_ERROR, "Realtime PostgreSQL: Error creating socket\n");
		return NULL;
	}
	
	/* Configurar socket como no bloqueante */
	flags = fcntl(sock, F_GETFL, 0);
	fcntl(sock, F_SETFL, flags | O_NONBLOCK);
	
	/* Aumentar el buffer de recepción */
	int rcvbuf_size = 1024 * 1024; /* 1MB buffer */
	setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &rcvbuf_size, sizeof(rcvbuf_size));
	
	/* Permitir reutilización del puerto */
	int reuse = 1;
	setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
	
	/* Configurar servidor */
	memset(&server, 0, sizeof(server));
	server.sin_family = AF_INET;
	server.sin_addr.s_addr = INADDR_ANY;
	server.sin_port = htons(cache_port);
	
	if (bind(sock, (struct sockaddr *)&server, sizeof(server)) < 0) {
		ast_log_chan(NULL, LOG_ERROR, "Realtime PostgreSQL: Error binding to port %u\n", cache_port);
		close(sock);
		return NULL;
	}
	
	fromlen = sizeof(struct sockaddr_in);
	
	while (1) {
		/* Inicialización manual de fd_set para evitar warning de buffer overflow */
		tv.tv_sec = 0;
		tv.tv_usec = 1000;
		
		/* Preparar manualmente la estructura fd_set */
		fd_set rfds;
		memset(&rfds, 0, sizeof(rfds));  /* Inicialización segura */
		
		/* Establecer el bit correspondiente al socket */
		if (sock < FD_SETSIZE) {
			FD_SET(sock, &rfds);
			ret = select(sock + 1, &rfds, NULL, NULL, &tv);
		} else {
			ast_log_chan(NULL, LOG_ERROR, "Socket descriptor %d exceeds FD_SETSIZE\n", sock);
			sleep(1);
			continue;
		}
		
		if (ret < 0) {
			if (errno != EINTR) {
				ast_log_chan(NULL, LOG_ERROR, "Realtime PostgreSQL: Error in select(): %s\n", strerror(errno));
				sleep(1); /* Evitar CPU spinning en caso de error persistente */
			}
			continue;
		}
		
		if (ret == 0) {
			/* Timeout - no hay datagramas para procesar */
			continue;
		}
		
		/* Procesar en lote para mejor rendimiento */
		batch_size = 0;
		udp_processed = 0;
		
		while (batch_size < 1000) { /* Procesar hasta 1000 mensajes por lote */
			int n = recvfrom(sock, buf, sizeof(buf) - 1, 0, (struct sockaddr *)&from, &fromlen);
			
			if (n <= 0) {
				if (errno == EAGAIN || errno == EWOULDBLOCK) {
					/* No hay más datagramas disponibles */
					break;
				}
				/* Error en recvfrom */
				if (errno != EINTR) {
					ast_log_chan(NULL, LOG_WARNING, "PostgreSQL RealTime: recvfrom error: %s\n", strerror(errno));
				}
				break;
			}
			
			buf[n] = '\0'; /* Asegurar null-terminación */
			batch_size++;
			
			/* Actualizar caché */
			ast_mutex_lock(&pgsql_cache_flag);
			
			if (pgsql_cache && pgsql_cache_items > 0) {
				uint64_t hash = XXH64(buf, strlen(buf), 0);
				
				/* Búsqueda binaria en línea */
				int inicio = 0;
				int fin = pgsql_cache_items - 1;
				int medio;
				
				while (inicio <= fin) {
					medio = (inicio + fin) / 2;
					
					if (hash < pgsql_cache[medio].hash) {
						fin = medio - 1;
					} else if (hash > pgsql_cache[medio].hash) {
						inicio = medio + 1;
					} else {
						/* Encontramos el hash, marcar para actualización */
						pgsql_cache[medio].update = 1;
						udp_processed++;
						break;
					}
				}
			}
			
			ast_mutex_unlock(&pgsql_cache_flag);
		}
		
		/* Actualizar estadísticas */
		if (batch_size > 0) {
			ast_mutex_lock(&pgsql_stats_lock);
			pgsql_packets_current_minute += batch_size;
			pgsql_packets_total += batch_size;
			pgsql_cache_updates += udp_processed;
			
			/* Actualizar contadores cada minuto */
			time_t now = time(NULL);
			if (now - pgsql_packets_last_update >= 60) {
				pgsql_packets_last_minute = pgsql_packets_current_minute;
				pgsql_packets_current_minute = 0;
				pgsql_packets_last_update = now;
			}
			ast_mutex_unlock(&pgsql_stats_lock);
		}
		
		/* Estadísticas de debug si es necesario */
		if (option_verbose > 4 && batch_size > 1) {
			ast_verbose(VERBOSE_PREFIX_2 "PostgreSQL cache: processed %d UDP packets (%d cache updates) in batch\n", 
					   batch_size, udp_processed);
		}
	}
	
	close(sock);
	return NULL;
}

static int _pgsql_cache_add(struct ast_pgsql_cache *item)
{
	int medio = 0;
	int inicio = 0;
	int fin = pgsql_cache_items - 1;

	/* El bloqueo del mutex debe estar fuera de esta función,
	   en la función pgsql_cache_add que llama a ésta */
	
	if (pgsql_cache) {
		while (inicio <= fin) {
			medio = (inicio + fin) / 2;

			if (item->hash < pgsql_cache[medio].hash) {
				fin = medio - 1;
			} else {
				inicio = medio + 1;
			}
		}
		// El índice de inserción es donde quedó 'inicio'
		medio = inicio;
	} else {
		medio = 0;
	}

	struct ast_pgsql_cache *new_cache = ast_realloc(pgsql_cache, (pgsql_cache_items + 1) * sizeof(struct ast_pgsql_cache));
	if (!new_cache)
	{
		/* No liberamos el mutex aquí, debe ser manejado por la función que nos llama */
		return 0;
	}

	pgsql_cache = new_cache;

	if (medio < pgsql_cache_items) {
		memmove(&pgsql_cache[medio + 1],
			&pgsql_cache[medio],
			(pgsql_cache_items - medio) * sizeof(struct ast_pgsql_cache));
	}

	/* No liberamos el mutex aquí, debe ser manejado por la función que nos llama */

	// Inicialización de campos de control
	item->last = time(NULL);
	item->update = 0;
	item->autokillid = 0;

	// Copiar el item completo
	pgsql_cache[medio] = *item;

	// Calcular tamaño total estimado en memoria
	int tuples = PQntuples(item->res);
	int numFields = PQnfields(item->res);
	int i, a;

	for (i = 0; i < numFields; i++)
		pgsql_cache_size += strlen(PQfname(item->res, i)) + 1;

	for (a = 0; a < tuples; a++)
		for (i = 0; i < numFields; i++)
			pgsql_cache_size += strlen(PQgetvalue(item->res, a, i)) + 1;

	pgsql_cache_items++;
	return 1;
}

static int pgsql_cache_add(char *sql, PGresult *res)
{
	struct ast_pgsql_cache *item = NULL;

	/* Verificar límites antes de adquirir el mutex para evitar bloqueos innecesarios */
	if (pgsql_cache_size >= pgsql_cache_max_size) {
		ast_log_chan(NULL, LOG_ERROR, "CACHE FULL: memory full\n");
		return 0;
	}

	if (pgsql_cache_items >= pgsql_cache_max_items) {
		ast_log_chan(NULL, LOG_ERROR, "CACHE FULL: max items\n");
		return 0;
	}

	item = ast_malloc(sizeof(*item));
	if (!item) {
		return 0;
	}

	item->sql = ast_strdup(sql);
	if (!item->sql) {
		ast_free(item);
		return 0;
	}

	item->res = res;  // ⚠️ Ownership del PGresult pasa al cache
	item->hash = XXH64(sql, strlen(sql), 0);

	if (option_verbose > 5) {
		ast_log_chan(NULL, LOG_NOTICE, "Cache added: %s (hash: 0x%016llx)\n",
		sql, (unsigned long long)item->hash);
	}

	/* Adquirir el mutex antes de modificar la caché */
	ast_mutex_lock(&pgsql_cache_flag);
	int result = _pgsql_cache_add(item);
	ast_mutex_unlock(&pgsql_cache_flag);

	/* Si falló la inserción, liberar la memoria asignada */
	if (!result) {
		ast_free(item->sql);
		ast_free(item);
	}

	return result;
}

static int pgsql_cache_pgresult(int pgsqlC, char *sql, char *func, PGresult **result)
{
	if (!pgsql_cache || !sql) {
		return -1;
	}

	uint64_t hash = XXH64(sql, strlen(sql), 0);
	struct ast_pgsql_cache *found = NULL;
	
	/* Proteger el acceso a la caché y estadísticas con mutex */
	ast_mutex_lock(&pgsql_cache_flag);
	ast_mutex_lock(&pgsql_stats_lock);
	pgsql_cache_attempts++;  /* Incrementar contador de intentos */
	ast_mutex_unlock(&pgsql_stats_lock);

	/* Búsqueda binaria directamente en línea */
	int inicio = 0;
	int fin = pgsql_cache_items - 1;
	int medio;
	
	while (inicio <= fin) {
		medio = (inicio + fin) / 2;
		
		if (hash < pgsql_cache[medio].hash) {
			fin = medio - 1;
		} else if (hash > pgsql_cache[medio].hash) {
			inicio = medio + 1;
		} else {
			/* Encontramos el hash */
			found = &pgsql_cache[medio];
			break;
		}
	}

	if (found) {
		int update_needed = found->update;
		found->last = time(NULL);
		
		/* Si no necesitamos actualizar, podemos liberar el mutex antes de retornar */
		if (!update_needed) {
			ast_mutex_lock(&pgsql_stats_lock);
			pgsql_cache_hits++;  /* Incrementar contador de hits */
			ast_mutex_unlock(&pgsql_stats_lock);

			*result = found->res;
			ast_mutex_unlock(&pgsql_cache_flag);
			return 0;
		}
		
		if (option_verbose > 5) {
			ast_verbose(VERBOSE_PREFIX_1 "Updating cache item\n");
		}

		/* Liberar el mutex mientras hacemos la consulta a la base de datos */
		ast_mutex_unlock(&pgsql_cache_flag);
		
		PGresult *r = NULL;

		ast_mutex_lock(&pgsql_stats_lock);
		pgsql_total_db_queries++;  /* Incrementar contador de consultas reales */
		ast_mutex_unlock(&pgsql_stats_lock);

		if ((pgsql_exec(pgsqlC, sql, func, NULL, &r) != 0) || (r == NULL)) {
			ast_log_chan(NULL, LOG_WARNING, "Postgresql RealTime: Failed to update cached result\n");
			if (r) PQclear(r);
			return -1;
		}

		/* Volver a bloquear para actualizar la caché */
		ast_mutex_lock(&pgsql_cache_flag);
		
		/* Verificar que el elemento sigue existiendo en la caché */
		found = NULL;
		inicio = 0;
		fin = pgsql_cache_items - 1;
		
		while (inicio <= fin) {
			medio = (inicio + fin) / 2;
			
			if (hash < pgsql_cache[medio].hash) {
				fin = medio - 1;
			} else if (hash > pgsql_cache[medio].hash) {
				inicio = medio + 1;
			} else {
				found = &pgsql_cache[medio];
				break;
			}
		}
		
		if (found) {
			// Restar tamaño anterior
			int tuples = PQntuples(found->res);
			int fields = PQnfields(found->res);
			for (int i = 0; i < fields; i++) {
				pgsql_cache_size -= strlen(PQfname(found->res, i)) + 1;
			}

			for (int a = 0; a < tuples; a++) {
				for (int i = 0; i < fields; i++) {
					pgsql_cache_size -= strlen(PQgetvalue(found->res, a, i)) + 1;
				}
			}

			PQclear(found->res);
			found->res = r;

			// Sumar nuevo tamaño
			tuples = PQntuples(r);
			fields = PQnfields(r);
			for (int i = 0; i < fields; i++) {
				pgsql_cache_size += strlen(PQfname(r, i)) + 1;
			}
			for (int a = 0; a < tuples; a++) {
				for (int i = 0; i < fields; i++) {
					pgsql_cache_size += strlen(PQgetvalue(r, a, i)) + 1;
				}
			}

			found->update = (tuples == 0) ? 1 : 0;
			*result = found->res;
			ast_mutex_unlock(&pgsql_cache_flag);
			return 0;
		} else {
			/* No se encontró el elemento después de la consulta */
			ast_mutex_unlock(&pgsql_cache_flag);
			PQclear(r);
			return -1;
		}
	}

	ast_mutex_unlock(&pgsql_cache_flag);
	return -1;
}

static void pgsql_cache_clear(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
{
        int i;

        ast_mutex_lock(&pgsql_cache_flag);
        for (i = 0;i < pgsql_cache_items; i++)
        {
                PQclear(pgsql_cache[i].res);
                ast_free(pgsql_cache[i].sql);
        }
        ast_free(pgsql_cache);
        pgsql_cache = NULL;
        pgsql_cache_items = 0;
        pgsql_cache_size  = 0;
        ast_mutex_unlock(&pgsql_cache_flag);

 	return;
}

static struct tables *find_table(const char *database, const char *orig_tablename)
{
	struct columns *column;
	struct tables *table;
	struct ast_str *sql = ast_str_thread_get(&findtable_buf, 330);
	RAII_VAR(PGresult *, result, NULL, PQclear);
	int exec_result;
	char *fname, *ftype, *flen, *fnotnull, *fdef;
	int i, rows;
	int pgsqlC;

	AST_LIST_LOCK(&psql_tables);
	AST_LIST_TRAVERSE(&psql_tables, table, list) {
		if (!strcasecmp(table->name, orig_tablename)) {
			ast_debug(1, "Found table in cache; now locking\n");
			ast_rwlock_rdlock(&table->lock);
			ast_debug(1, "Lock cached table; now returning\n");
			AST_LIST_UNLOCK(&psql_tables);
			return table;
		}
	}

	if (database == NULL) {
		AST_LIST_UNLOCK(&psql_tables);
		return NULL;
	}

	ast_debug(1, "Table '%s' not found in cache, querying now\n", orig_tablename);

	pgsqlC = pgsql_getConn();

	if (pgsqlC < 0 || !pgsqlConn[pgsqlC]) {
		AST_LIST_UNLOCK(&psql_tables);
		ast_log(LOG_ERROR, "PostgreSQL RealTime: no hay conexión activa para escape.\n");
		return NULL;
	}

	/* Not found, scan the table */
	if (has_schema_support) {
		char *schemaname, *tablename, *tmp_schemaname, *tmp_tablename;
		if (strchr(orig_tablename, '.')) {
			tmp_schemaname = ast_strdupa(orig_tablename);
			tmp_tablename = strchr(tmp_schemaname, '.');
			*tmp_tablename++ = '\0';
		} else {
			tmp_schemaname = "";
			tmp_tablename = ast_strdupa(orig_tablename);
		}

		tablename = ast_alloca(strlen(tmp_tablename) * 2 + 1);
		PQescapeStringConn(pgsqlConn[pgsqlC], tablename, tmp_tablename, strlen(tmp_tablename), NULL);
		schemaname = ast_alloca(strlen(tmp_schemaname) * 2 + 1);
		PQescapeStringConn(pgsqlConn[pgsqlC], schemaname, tmp_schemaname, strlen(tmp_schemaname), NULL);

		ast_str_set(&sql, 0, "SELECT a.attname, t.typname, a.attlen, a.attnotnull, pg_catalog.pg_get_expr(d.adbin, d.adrelid) adsrc, a.atttypmod FROM (((pg_catalog.pg_class c INNER JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace AND c.relname = '%s' AND n.nspname = %s%s%s) INNER JOIN pg_catalog.pg_attribute a ON (NOT a.attisdropped) AND a.attnum > 0 AND a.attrelid = c.oid) INNER JOIN pg_catalog.pg_type t ON t.oid = a.atttypid) LEFT OUTER JOIN pg_attrdef d ON a.atthasdef AND d.adrelid = a.attrelid AND d.adnum = a.attnum ORDER BY n.nspname, c.relname, attnum",
			tablename,
			ast_strlen_zero(schemaname) ? "" : "'", ast_strlen_zero(schemaname) ? "current_schema()" : schemaname, ast_strlen_zero(schemaname) ? "" : "'");
	} else {
		char *tablename;
		tablename = ast_alloca(strlen(orig_tablename) * 2 + 1);
		PQescapeStringConn(pgsqlConn[pgsqlC], tablename, orig_tablename, strlen(orig_tablename), NULL);

		ast_str_set(&sql, 0, "SELECT a.attname, t.typname, a.attlen, a.attnotnull, d.adsrc, a.atttypmod FROM pg_class c, pg_type t, pg_attribute a LEFT OUTER JOIN pg_attrdef d ON a.atthasdef AND d.adrelid = a.attrelid AND d.adnum = a.attnum WHERE c.oid = a.attrelid AND a.atttypid = t.oid AND (a.attnum > 0) AND c.relname = '%s' ORDER BY c.relname, attnum", tablename);
	}

	exec_result = pgsql_exec(pgsqlC, ast_str_buffer(sql), NULL, NULL, &result);

	pgsqlFlag[pgsqlC] = 0;

	ast_debug(1, "Query of table structure complete.  Now retrieving results.\n");
	if (exec_result != 0) {
		ast_log_chan(NULL, LOG_ERROR, "Failed to query database columns for table %s\n", orig_tablename);
		AST_LIST_UNLOCK(&psql_tables);
		return NULL;
	}

	if (!(table = ast_calloc(1, sizeof(*table) + strlen(orig_tablename) + 1))) {
		ast_log_chan(NULL, LOG_ERROR, "Unable to allocate memory for new table structure\n");
		AST_LIST_UNLOCK(&psql_tables);
		return NULL;
	}
	strcpy(table->name, orig_tablename); /* SAFE */
	ast_rwlock_init(&table->lock);
	AST_LIST_HEAD_INIT_NOLOCK(&table->columns);

	rows = PQntuples(result);
	for (i = 0; i < rows; i++) {
		fname = PQgetvalue(result, i, 0);
		ftype = PQgetvalue(result, i, 1);
		flen = PQgetvalue(result, i, 2);
		fnotnull = PQgetvalue(result, i, 3);
		fdef = PQgetvalue(result, i, 4);
		ast_verb_chan(NULL, 4, "Found column '%s' of type '%s'\n", fname, ftype);

		if (!(column = ast_calloc(1, sizeof(*column) + strlen(fname) + strlen(ftype) + 2))) {
			ast_log_chan(NULL, LOG_ERROR, "Unable to allocate column element for %s, %s\n", orig_tablename, fname);
			destroy_table(table);
			AST_LIST_UNLOCK(&psql_tables);
			return NULL;
		}

		if (strcmp(flen, "-1") == 0) {
			/* Some types, like chars, have the length stored in a different field */
			flen = PQgetvalue(result, i, 5);
			sscanf(flen, "%30d", &column->len);
			column->len -= 4;
		} else {
			sscanf(flen, "%30d", &column->len);
		}
		column->name = (char *)column + sizeof(*column);
		column->type = (char *)column + sizeof(*column) + strlen(fname) + 1;
		strcpy(column->name, fname);
		strcpy(column->type, ftype);
		if (*fnotnull == 't') {
			column->notnull = 1;
		} else {
			column->notnull = 0;
		}
		if (!ast_strlen_zero(fdef)) {
			column->hasdefault = 1;
		} else {
			column->hasdefault = 0;
		}
		AST_LIST_INSERT_TAIL(&table->columns, column, list);
	}

	AST_LIST_INSERT_TAIL(&psql_tables, table, list);
	ast_rwlock_rdlock(&table->lock);
	AST_LIST_UNLOCK(&psql_tables);
	return table;
}

#define release_table(table) ast_rwlock_unlock(&(table)->lock);

static struct columns *find_column(struct tables *t, const char *colname)
{
	struct columns *column;

	/* Check that the column exists in the table */
	AST_LIST_TRAVERSE(&t->columns, column, list) {
		if (strcmp(column->name, colname) == 0) {
			return column;
		}
	}
	return NULL;
}

#define IS_SQL_LIKE_CLAUSE(x) ((x) && ast_ends_with(x, " LIKE"))
#define ESCAPE_CLAUSE (USE_BACKSLASH_AS_STRING ? " ESCAPE '\\\\'" : " ESCAPE '\\\\'")

static struct ast_variable *realtime_pgsql(const char *database, const char *tablename, const struct ast_variable *fields)
{
	PGresult *result = NULL;
	int freeresult = 0;
	int pgresult = 1;
	struct ast_str *sql = ast_str_thread_get(&sql_buf, 100);
	struct ast_str *escapebuf = ast_str_thread_get(&escapebuf_buf, 100);
	char *stringp;
	char *chunk;
	char *op;
	char *escape = "";
	const struct ast_variable *field = fields;
	struct ast_variable *var = NULL, *prev = NULL;
	char *func = NULL;
	int pgsqlC;

	/*
	 * Ignore database from the extconfig.conf since it was
	 * configured by res_pgsql.conf.
	 */
	database = dbname;

	if (!tablename) {
		ast_log_chan(NULL, LOG_WARNING, "PostgreSQL RealTime: No table specified.\n");
		return NULL;
	}

	if (pgsql_tablefunc) {
		func = (char*) ast_variable_retrieve(pgsql_tablefunc, "selectfunc", tablename);
	}

	/*
	 * Must connect to the server before anything else as ESCAPE_STRING()
	 * uses pgsqlConn
	 */
	/* Get the first parameter and first value in our list of passed paramater/value pairs */
	if (!field) {
		ast_log_chan(NULL, LOG_WARNING,
				"PostgreSQL RealTime: Realtime retrieval requires at least 1 parameter and 1 value to search on.\n");
		return NULL;
	}

	/* Create the first part of the query using the first parameter/value pairs we just extracted
	   If there is only 1 set, then we have our query. Otherwise, loop thru the list and concat */
	if (!strchr(field->name, ' ')) {
		op = " =";
	} else {
		op = "";
		if (IS_SQL_LIKE_CLAUSE(field->name)) {
			escape = ESCAPE_CLAUSE;
		}
	}

	pgsqlC = pgsql_getConn();

	if (pgsqlC < 0 || !pgsqlConn[pgsqlC]) {
		ast_log(LOG_ERROR, "PostgreSQL RealTime: no hay conexión activa para escape.\n");
		return NULL;
	}

	ESCAPE_STRING(escapebuf, field->value, pgsqlC);
	if (pgresult) {
		pgsqlFlag[pgsqlC] = 0;
		ast_log_chan(NULL, LOG_ERROR, "PostgreSQL RealTime: detected invalid input: '%s'\n", field->value);
		return NULL;
	}

	if (strstr(tablename, "ps_") != NULL) {
		ast_str_set(&sql, 0, "SELECT * FROM %s WHERE (root = %i AND pjsipuid = %i) AND %s%s '%s'%s", \
			tablename, *ast_config_AST_SYSTEM_ROOT, *ast_config_AST_SYSTEM_PJSIPUID, field->name, op, ast_str_buffer(escapebuf), escape);
	} else {
		ast_str_set(&sql, 0, "SELECT * FROM %s WHERE (root = %i) AND %s%s '%s'%s", \
					tablename, *ast_config_AST_SYSTEM_ROOT, field->name, op, ast_str_buffer(escapebuf), escape);
	}

	while ((field = field->next)) {
		escape = "";
		if (!strchr(field->name, ' ')) {
			op = " =";
		} else {
			op = "";
			if (IS_SQL_LIKE_CLAUSE(field->name)) {
				escape = ESCAPE_CLAUSE;
			}
		}

		ESCAPE_STRING(escapebuf, field->value, pgsqlC);
		if (pgresult) {
			pgsqlFlag[pgsqlC] = 0;
			ast_log_chan(NULL, LOG_ERROR, "PostgreSQL RealTime: detected invalid input: '%s'\n", field->value);
			return NULL;
		}

		ast_str_append(&sql, 0, " AND %s%s '%s'%s", field->name, op, ast_str_buffer(escapebuf), escape);
	}
	ast_str_append(&sql, 0, " LIMIT 1");

	if ((func) && (pgsql_cache_pgresult(pgsqlC, ast_str_buffer(sql), func, &result) != 0)) {
		/* We now have our complete statement; Lets connect to the server and execute it. */
		if (pgsql_exec(pgsqlC, ast_str_buffer(sql), func, NULL, &result) != 0) {
			pgsqlFlag[pgsqlC] = 0;
			return NULL;
		}
		pgsql_cache_add(ast_str_buffer(sql), result);
		freeresult = 0;
	} else {
		if (pgsql_exec(pgsqlC, ast_str_buffer(sql), func, NULL, &result) != 0) {
			pgsqlFlag[pgsqlC] = 0;
			return NULL;
		}
		freeresult = 1;
	}

	pgsqlFlag[pgsqlC] = 0;

	ast_debug(1, "PostgreSQL RealTime: Result=%p Query: %s\n", result, ast_str_buffer(sql));

	if (PQntuples(result) > 0) {
		int i = 0;
		int numFields = PQnfields(result);
		char **fieldnames = NULL;

		ast_debug(1, "PostgreSQL RealTime: Found a row.\n");

		if (!(fieldnames = ast_calloc(1, numFields * sizeof(char *)))) {
			return NULL;
		}
		for (i = 0; i < numFields; i++)
			fieldnames[i] = PQfname(result, i);
		for (i = 0; i < numFields; i++) {
			stringp = PQgetvalue(result, 0, i);
			while (stringp) {
				chunk = strsep(&stringp, ";");
				if (chunk && !ast_strlen_zero(ast_realtime_decode_chunk(ast_strip(chunk)))) {
					if (prev) {
						prev->next = ast_variable_new(fieldnames[i], chunk, "");
						if (prev->next) {
							prev = prev->next;
						}
					} else {
						prev = var = ast_variable_new(fieldnames[i], chunk, "");
					}
				}
			}
		}
		ast_free(fieldnames);
	} else {
		ast_debug(1, "Postgresql RealTime: Could not find any rows in table %s@%s.\n", tablename, database);
	}

	if (freeresult == 1) {
		PQclear(result);
	}

	return var;
}

static struct ast_config *realtime_multi_pgsql(const char *database, const char *table, const struct ast_variable *fields)
{
	PGresult *result = NULL;
        int freeresult = 0;
	int num_rows = 0, pgresult = 1;
	struct ast_str *sql = ast_str_thread_get(&sql_buf, 100);
	struct ast_str *escapebuf = ast_str_thread_get(&escapebuf_buf, 100);
	const struct ast_variable *field = fields;
	const char *initfield = NULL;
	char *stringp;
	char *chunk;
	char *op;
	char *escape = "";
	struct ast_variable *var = NULL;
	struct ast_config *cfg = NULL;
	struct ast_category *cat = NULL;
	char *func = NULL;
	int pgsqlC;

	/*
	 * Ignore database from the extconfig.conf since it was
	 * configured by res_pgsql.conf.
	 */
	database = dbname;

	if (!table) {
		ast_log_chan(NULL, LOG_WARNING, "PostgreSQL RealTime: No table specified.\n");
		return NULL;
	}

	if (pgsql_tablefunc) {
		func = (char*) ast_variable_retrieve(pgsql_tablefunc, "selectfunc", table);
	}

	if (!(cfg = ast_config_new())) {
		return NULL;
	}

	/*
	 * Must connect to the server before anything else as ESCAPE_STRING()
	 * uses pgsqlConn
	 */

	/* Get the first parameter and first value in our list of passed paramater/value pairs */
	if (!field) {
		ast_log_chan(NULL, LOG_WARNING,
				"PostgreSQL RealTime: Realtime retrieval requires at least 1 parameter and 1 value to search on.\n");
		ast_config_destroy(cfg);
		return NULL;
	}


	initfield = ast_strdupa(field->name);
	if ((op = strchr(initfield, ' '))) {
		*op = '\0';
	}


	/* Create the first part of the query using the first parameter/value pairs we just extracted
	   If there is only 1 set, then we have our query. Otherwise, loop thru the list and concat */

	if (!strchr(field->name, ' ')) {
		op = " =";
		escape = "";
	} else {
		op = "";
		if (IS_SQL_LIKE_CLAUSE(field->name)) {
			escape = ESCAPE_CLAUSE;
		}
	}

	pgsqlC = pgsql_getConn();

	if (pgsqlC < 0 || !pgsqlConn[pgsqlC]) {
		ast_config_destroy(cfg);
		ast_log(LOG_ERROR, "PostgreSQL RealTime: no hay conexión activa para escape.\n");
		return NULL;
	}

	ESCAPE_STRING(escapebuf, field->value, pgsqlC);
	if (pgresult) {
		pgsqlFlag[pgsqlC] = 0;
		ast_log_chan(NULL, LOG_ERROR, "PostgreSQL RealTime: detected invalid input: '%s'\n", field->value);
		ast_config_destroy(cfg);
		return NULL;
	}

	if (strstr(table, "ps_") != NULL) {
		ast_str_set(&sql, 0, "SELECT * FROM %s WHERE (root = %i AND pjsipuid = %i) AND %s%s '%s'%s", \
			table, *ast_config_AST_SYSTEM_ROOT, *ast_config_AST_SYSTEM_PJSIPUID, field->name, op, ast_str_buffer(escapebuf), escape);
	} else {
		ast_str_set(&sql, 0, "SELECT * FROM %s WHERE (root = %i) AND %s%s '%s'%s", \
					table, *ast_config_AST_SYSTEM_ROOT, field->name, op, ast_str_buffer(escapebuf), escape);
	}

	while ((field = field->next)) {
		if (!field->value) {
		        initfield = ast_strdupa(field->name);
		        if ((op = strchr(initfield, ' '))) {
		                *op = '\0';
		        }

			break;
		}
		escape = "";
		if (!strchr(field->name, ' ')) {
			op = " =";
			escape = "";
		} else {
			op = "";
			if (IS_SQL_LIKE_CLAUSE(field->name)) {
				escape = ESCAPE_CLAUSE;
			}
		}

		ESCAPE_STRING(escapebuf, field->value, pgsqlC);
		if (pgresult) {
			pgsqlFlag[pgsqlC] = 0;
			ast_log_chan(NULL, LOG_ERROR, "PostgreSQL RealTime: detected invalid input: '%s'\n", field->value);
			ast_config_destroy(cfg);
			return NULL;
		}

		ast_str_append(&sql, 0, " AND %s%s '%s'%s", field->name, op, ast_str_buffer(escapebuf), escape);
	}

	if (initfield && order_multi_row_results_by_initial_column) {
		ast_str_append(&sql, 0, " ORDER BY %s", initfield);
	}

	/* ast_verb_chan(NULL, 3, "SQL %s\n", ast_str_buffer(sql)); */

        if ((func) && (pgsql_cache_pgresult(pgsqlC, ast_str_buffer(sql), func, &result) != 0)) {
                /* We now have our complete statement; Lets connect to the server and execute it. */
                if (pgsql_exec(pgsqlC, ast_str_buffer(sql), func, NULL, &result) != 0) {
                        pgsqlFlag[pgsqlC] = 0;
                        return NULL;
                }
                pgsql_cache_add(ast_str_buffer(sql), result);
		freeresult = 0;
        } else {
                if (pgsql_exec(pgsqlC, ast_str_buffer(sql), func, NULL, &result) != 0) {
                        pgsqlFlag[pgsqlC] = 0;
                        return NULL;
                }
                freeresult = 1;
        }

	pgsqlFlag[pgsqlC] = 0;

	ast_debug(1, "PostgreSQL RealTime: Result=%p Query: %s\n", result, ast_str_buffer(sql));

	if ((num_rows = PQntuples(result)) > 0) {
		int numFields = PQnfields(result);
		int i = 0;
		int rowIndex = 0;
		char **fieldnames = NULL;

		ast_debug(1, "PostgreSQL RealTime: Found %d rows.\n", num_rows);

		if (!(fieldnames = ast_calloc(1, numFields * sizeof(char *)))) {
			ast_config_destroy(cfg);
			return NULL;
		}
		for (i = 0; i < numFields; i++)
			fieldnames[i] = PQfname(result, i);

		for (rowIndex = 0; rowIndex < num_rows; rowIndex++) {
			var = NULL;
			cat = ast_category_new_anonymous();
			if (!cat) {
				continue;
			}
			for (i = 0; i < numFields; i++) {
				stringp = PQgetvalue(result, rowIndex, i);
				while (stringp) {
					chunk = strsep(&stringp, ";");
					if (chunk && !ast_strlen_zero(ast_realtime_decode_chunk(ast_strip(chunk)))) {
						if (initfield && !strcmp(initfield, fieldnames[i])) {
							ast_category_rename(cat, chunk);
						}
						var = ast_variable_new(fieldnames[i], chunk, "");
						ast_variable_append(cat, var);
					}
				}
			}
			ast_category_append(cfg, cat);
		}
		ast_free(fieldnames);
	} else {
		ast_debug(1, "PostgreSQL RealTime: Could not find any rows in table %s.\n", table);
	}

	if (freeresult == 1) {
                PQclear(result);
	}

	return cfg;
}

static int update_pgsql(const char *database, const char *tablename, const char *keyfield,
						const char *lookup, const struct ast_variable *fields)
{
	RAII_VAR(PGresult *, result, NULL, PQclear);
	int numrows = 0, pgresult;
	const struct ast_variable *field = fields;
	struct ast_str *sql = ast_str_thread_get(&sql_buf, 100);
	struct ast_str *escapebuf = ast_str_thread_get(&escapebuf_buf, 100);
	struct tables *table;
	struct columns *column = NULL;
	int pgsqlC;

	/*
	 * Ignore database from the extconfig.conf since it was
	 * configured by res_pgsql.conf.
	 */
	database = dbname;

	if (!tablename) {
		ast_log_chan(NULL, LOG_WARNING, "PostgreSQL RealTime: No table specified.\n");
		return -1;
	}

	if (!(table = find_table(database, tablename))) {
		ast_log_chan(NULL, LOG_ERROR, "Table '%s' does not exist!!\n", tablename);
		return -1;
	}

	/*
	 * Must connect to the server before anything else as ESCAPE_STRING()
	 * uses pgsqlConn
	 */

	/* Get the first parameter and first value in our list of passed paramater/value pairs */
	if (!field) {
		ast_log_chan(NULL, LOG_WARNING,
				"PostgreSQL RealTime: Realtime retrieval requires at least 1 parameter and 1 value to search on.\n");
		release_table(table);
		return -1;
	}

	/* Check that the column exists in the table */
	AST_LIST_TRAVERSE(&table->columns, column, list) {
		if (strcmp(column->name, field->name) == 0) {
			break;
		}
	}

	if (!column) {
		ast_log_chan(NULL, LOG_ERROR, "PostgreSQL RealTime: Updating on column '%s', but that column does not exist within the table '%s'!\n", field->name, tablename);
		release_table(table);
		return -1;
	}

	/* Create the first part of the query using the first parameter/value pairs we just extracted
	   If there is only 1 set, then we have our query. Otherwise, loop thru the list and concat */

	pgsqlC = pgsql_getConn();

	if (pgsqlC < 0 || !pgsqlConn[pgsqlC]) {
		ast_log(LOG_ERROR, "PostgreSQL RealTime: no hay conexión activa para escape.\n");
		release_table(table);
		return NULL;
	}

	ESCAPE_STRING(escapebuf, field->value, pgsqlC);
	if (pgresult) {
		pgsqlFlag[pgsqlC] = 0;
		ast_log_chan(NULL, LOG_ERROR, "PostgreSQL RealTime: detected invalid input: '%s'\n", field->value);
		release_table(table);
		return -1;
	}
	ast_str_set(&sql, 0, "UPDATE %s SET %s = '%s'", tablename, field->name, ast_str_buffer(escapebuf));

	while ((field = field->next)) {
		if (!find_column(table, field->name)) {
			ast_log_chan(NULL, LOG_NOTICE, "Attempted to update column '%s' in table '%s', but column does not exist!\n", field->name, tablename);
			continue;
		}

		ESCAPE_STRING(escapebuf, field->value, pgsqlC);
		if (pgresult) {
			pgsqlFlag[pgsqlC] = 0;
			ast_log_chan(NULL, LOG_ERROR, "PostgreSQL RealTime: detected invalid input: '%s'\n", field->value);
			release_table(table);
			return -1;
		}

		ast_str_append(&sql, 0, ", %s = '%s'", field->name, ast_str_buffer(escapebuf));
	}
	release_table(table);

	ESCAPE_STRING(escapebuf, lookup, pgsqlC);
	if (pgresult) {
		pgsqlFlag[pgsqlC] = 0;
		ast_log_chan(NULL, LOG_ERROR, "PostgreSQL RealTime: detected invalid input: '%s'\n", lookup);
		return -1;
	}

	ast_str_append(&sql, 0, " WHERE (%s = '%s') AND (root = %i)", keyfield, ast_str_buffer(escapebuf), *ast_config_AST_SYSTEM_ROOT);

	ast_debug(1, "PostgreSQL RealTime: Update SQL: %s\n", ast_str_buffer(sql));

	/* We now have our complete statement; Lets connect to the server and execute it. */
	if (pgsql_exec(pgsqlC, ast_str_buffer(sql), NULL, NULL, &result) != 0) {
		pgsqlFlag[pgsqlC] = 0;
		return -1;
	} else {
		pgsqlFlag[pgsqlC] = 0;
		ExecStatusType result_status = PQresultStatus(result);
		if (result_status != PGRES_COMMAND_OK
			&& result_status != PGRES_TUPLES_OK
			&& result_status != PGRES_NONFATAL_ERROR) {
			ast_log_chan(NULL, LOG_WARNING,
					"PostgreSQL RealTime: Failed to query database. Check debug for more info.\n");
			ast_debug(1, "PostgreSQL RealTime: Query: %s\n", ast_str_buffer(sql));
			ast_debug(1, "PostgreSQL RealTime: Query Failed because: %s (%s)\n",
						PQresultErrorMessage(result), PQresStatus(result_status));
			return -1;
		}
	}

	pgsqlFlag[pgsqlC] = 0;

	numrows = atoi(PQcmdTuples(result));

	ast_debug(1, "PostgreSQL RealTime: Updated %d rows on table: %s\n", numrows, tablename);

	/* From http://dev.pgsql.com/doc/pgsql/en/pgsql-affected-rows.html
	 * An integer greater than zero indicates the number of rows affected
	 * Zero indicates that no records were updated
	 * -1 indicates that the query returned an error (although, if the query failed, it should have been caught above.)
	 */

	if (numrows >= 0)
		return (int) numrows;

	return -1;
}

static int update2_pgsql(const char *database, const char *tablename, const struct ast_variable *lookup_fields, const struct ast_variable *update_fields)
{
	RAII_VAR(PGresult *, result, NULL, PQclear);
	int numrows = 0, pgresult, first = 1;
	struct ast_str *escapebuf = ast_str_thread_get(&escapebuf_buf, 16);
	const struct ast_variable *field;
	struct ast_str *sql = ast_str_thread_get(&sql_buf, 100);
	struct ast_str *where = ast_str_thread_get(&where_buf, 100);
	struct tables *table;
	int pgsqlC;

	/*
	 * Ignore database from the extconfig.conf since it was
	 * configured by res_pgsql.conf.
	 */
	database = dbname;

	if (!tablename) {
		ast_log_chan(NULL, LOG_WARNING, "PostgreSQL RealTime: No table specified.\n");
		return -1;
	}

	if (!escapebuf || !sql || !where) {
		/* Memory error, already handled */
		return -1;
	}

	if (!(table = find_table(database, tablename))) {
		ast_log_chan(NULL, LOG_ERROR, "Table '%s' does not exist!!\n", tablename);
		return -1;
	}

	/*
	 * Must connect to the server before anything else as ESCAPE_STRING()
	 * uses pgsqlConn
	 */

	ast_str_set(&sql, 0, "UPDATE %s SET", tablename);
	ast_str_set(&where, 0, "WHERE (root = %i) AND ", *ast_config_AST_SYSTEM_ROOT);

	pgsqlC = pgsql_getConn();

	if (pgsqlC < 0 || !pgsqlConn[pgsqlC]) {
		ast_log(LOG_ERROR, "PostgreSQL RealTime: no hay conexión activa para escape.\n");
		return NULL;
	}

	for (field = lookup_fields; field; field = field->next) {
		if (!find_column(table, field->name)) {
			pgsqlFlag[pgsqlC] = 0;
			ast_log_chan(NULL, LOG_ERROR, "Attempted to update based on criteria column '%s' (%s@%s), but that column does not exist!\n", field->name, tablename, database);
			release_table(table);
			return -1;
		}

		ESCAPE_STRING(escapebuf, field->value, pgsqlC);
		if (pgresult) {
			pgsqlFlag[pgsqlC] = 0;
			ast_log_chan(NULL, LOG_ERROR, "PostgreSQL RealTime: detected invalid input: '%s'\n", field->value);
			release_table(table);
			return -1;
		}
		ast_str_append(&where, 0, "%s %s='%s'", first ? "" : " AND", field->name, ast_str_buffer(escapebuf));
		first = 0;
	}

	if (first) {
		pgsqlFlag[pgsqlC] = 0;
		ast_log_chan(NULL, LOG_WARNING,
				"PostgreSQL RealTime: Realtime update requires at least 1 parameter and 1 value to search on.\n");
		release_table(table);
		return -1;
	}

	/* Now retrieve the columns to update */
	first = 1;
	for (field = update_fields; field; field = field->next) {
		/* If the column is not within the table, then skip it */
		if (!find_column(table, field->name)) {
			ast_log_chan(NULL, LOG_NOTICE, "Attempted to update column '%s' in table '%s@%s', but column does not exist!\n", field->name, tablename, database);
			continue;
		}

		ESCAPE_STRING(escapebuf, field->value, pgsqlC);
		if (pgresult) {
			pgsqlFlag[pgsqlC] = 0;
			ast_log_chan(NULL, LOG_ERROR, "PostgreSQL RealTime: detected invalid input: '%s'\n", field->value);
			release_table(table);
			return -1;
		}

		ast_str_append(&sql, 0, "%s %s='%s'", first ? "" : ",", field->name, ast_str_buffer(escapebuf));
		first = 0;
	}
	release_table(table);

	ast_str_append(&sql, 0, "%s", ast_str_buffer(where));

	ast_debug(1, "PostgreSQL RealTime: Update SQL: %s\n", ast_str_buffer(sql));

	/* We now have our complete statement; Lets connect to the server and execute it. */
	if (pgsql_exec(pgsqlC, ast_str_buffer(sql), NULL, NULL, &result) != 0) {
		pgsqlFlag[pgsqlC] = 0;
		return -1;
	}

	pgsqlFlag[pgsqlC] = 0;

	numrows = atoi(PQcmdTuples(result));

	ast_debug(1, "PostgreSQL RealTime: Updated %d rows on table: %s\n", numrows, tablename);

	/* From http://dev.pgsql.com/doc/pgsql/en/pgsql-affected-rows.html
	 * An integer greater than zero indicates the number of rows affected
	 * Zero indicates that no records were updated
	 * -1 indicates that the query returned an error (although, if the query failed, it should have been caught above.)
	 */

	if (numrows >= 0) {
		return (int) numrows;
	}

	return -1;
}

static int store_pgsql(const char *database, const char *table, const struct ast_variable *fields)
{
	RAII_VAR(PGresult *, result, NULL, PQclear);
	int numrows;
	struct ast_str *buf = ast_str_thread_get(&escapebuf_buf, 256);
	struct ast_str *sql1 = ast_str_thread_get(&sql_buf, 256);
	struct ast_str *sql2 = ast_str_thread_get(&where_buf, 256);
	int pgresult;
	const struct ast_variable *field = fields;
	int pgsqlC;

	/*
	 * Ignore database from the extconfig.conf since it was
	 * configured by res_pgsql.conf.
	 */
	database = dbname;

	if (!table) {
		ast_log_chan(NULL, LOG_WARNING, "PostgreSQL RealTime: No table specified.\n");
		return -1;
	}

	/*
	 * Must connect to the server before anything else as ESCAPE_STRING()
	 * uses pgsqlConn
	 */

	/* Get the first parameter and first value in our list of passed paramater/value pairs */
	if (!field) {
		ast_log_chan(NULL, LOG_WARNING,
				"PostgreSQL RealTime: Realtime storage requires at least 1 parameter and 1 value to store.\n");
		return -1;
	}

	pgsqlC = pgsql_getConn();

	if (pgsqlC < 0 || !pgsqlConn[pgsqlC]) {
		ast_log(LOG_ERROR, "PostgreSQL RealTime: no hay conexión activa para escape.\n");
		return NULL;
	}

	/* Create the first part of the query using the first parameter/value pairs we just extracted
	   If there is only 1 set, then we have our query. Otherwise, loop thru the list and concat */
	ESCAPE_STRING(buf, field->name, pgsqlC);
	ast_str_set(&sql1, 0, "INSERT INTO %s (root, %s", table, ast_str_buffer(buf));
	ESCAPE_STRING(buf, field->value, pgsqlC);
	ast_str_set(&sql2, 0, ") VALUES (%i, '%s'", *ast_config_AST_SYSTEM_ROOT, ast_str_buffer(buf));
	while ((field = field->next)) {
		ESCAPE_STRING(buf, field->name, pgsqlC);
		ast_str_append(&sql1, 0, ", %s", ast_str_buffer(buf));
		ESCAPE_STRING(buf, field->value, pgsqlC);
		ast_str_append(&sql2, 0, ", '%s'", ast_str_buffer(buf));
	}
	ast_str_append(&sql1, 0, "%s)", ast_str_buffer(sql2));

	ast_debug(1, "PostgreSQL RealTime: Insert SQL: %s\n", ast_str_buffer(sql1));

	/* We now have our complete statement; Lets connect to the server and execute it. */
	if (pgsql_exec(pgsqlC, ast_str_buffer(sql1), NULL, NULL, &result) != 0) {
		pgsqlFlag[pgsqlC] = 0;
		return -1;
	}

	pgsqlFlag[pgsqlC] = 0;

	numrows = atoi(PQcmdTuples(result));

	ast_debug(1, "PostgreSQL RealTime: row inserted on table: %s.\n", table);

	/* From http://dev.pgsql.com/doc/pgsql/en/pgsql-affected-rows.html
	 * An integer greater than zero indicates the number of rows affected
	 * Zero indicates that no records were updated
	 * -1 indicates that the query returned an error (although, if the query failed, it should have been caught above.)
	 */

	if (numrows >= 0) {
		return numrows;
	}

	return -1;
}

static int destroy_pgsql(const char *database, const char *table, const char *keyfield, const char *lookup, const struct ast_variable *fields)
{
	RAII_VAR(PGresult *, result, NULL, PQclear);
	int numrows = 0;
	int pgresult;
	struct ast_str *sql = ast_str_thread_get(&sql_buf, 256);
	struct ast_str *buf1 = ast_str_thread_get(&where_buf, 60), *buf2 = ast_str_thread_get(&escapebuf_buf, 60);
	const struct ast_variable *field;
	int pgsqlC;

	/*
	 * Ignore database from the extconfig.conf since it was
	 * configured by res_pgsql.conf.
	 */
	database = dbname;

	if (!table) {
		ast_log_chan(NULL, LOG_WARNING, "PostgreSQL RealTime: No table specified.\n");
		return -1;
	}

	/*
	 * Must connect to the server before anything else as ESCAPE_STRING()
	 * uses pgsqlConn
	 */

	/* Get the first parameter and first value in our list of passed paramater/value pairs */
	if (ast_strlen_zero(keyfield) || ast_strlen_zero(lookup))  {
		ast_log_chan(NULL, LOG_WARNING,
				"PostgreSQL RealTime: Realtime destroy requires at least 1 parameter and 1 value to search on.\n");
		return -1;
	}

	pgsqlC = pgsql_getConn();

	if (pgsqlC < 0 || !pgsqlConn[pgsqlC]) {
		ast_log(LOG_ERROR, "PostgreSQL RealTime: no hay conexión activa para escape.\n");
		return NULL;
	}

	/* Create the first part of the query using the first parameter/value pairs we just extracted
	   If there is only 1 set, then we have our query. Otherwise, loop thru the list and concat */

	ESCAPE_STRING(buf1, keyfield, pgsqlC);
	ESCAPE_STRING(buf2, lookup, pgsqlC);
	ast_str_set(&sql, 0, "DELETE FROM %s WHERE (root = %i) AND %s = '%s'", table, *ast_config_AST_SYSTEM_ROOT, 
								ast_str_buffer(buf1), ast_str_buffer(buf2));
	for (field = fields; field; field = field->next) {
		ESCAPE_STRING(buf1, field->name, pgsqlC);
		ESCAPE_STRING(buf2, field->value, pgsqlC);
		ast_str_append(&sql, 0, " AND %s = '%s'", ast_str_buffer(buf1), ast_str_buffer(buf2));
	}

	ast_debug(1, "PostgreSQL RealTime: Delete SQL: %s\n", ast_str_buffer(sql));

	/* We now have our complete statement; Lets connect to the server and execute it. */
	if (pgsql_exec(pgsqlC, ast_str_buffer(sql), NULL, NULL, &result) != 0) {
		pgsqlFlag[pgsqlC] = 0;
		return -1;
	}
	pgsqlFlag[pgsqlC] = 0;

	numrows = atoi(PQcmdTuples(result));

	ast_debug(1, "PostgreSQL RealTime: Deleted %d rows on table: %s\n", numrows, table);

	/* From http://dev.pgsql.com/doc/pgsql/en/pgsql-affected-rows.html
	 * An integer greater than zero indicates the number of rows affected
	 * Zero indicates that no records were updated
	 * -1 indicates that the query returned an error (although, if the query failed, it should have been caught above.)
	 */

	if (numrows >= 0)
		return (int) numrows;

	return -1;
}


static struct ast_config *config_pgsql(const char *database, const char *table,
	const char *file, struct ast_config *cfg,
	struct ast_flags flags, const char *suggested_incl, const char *who_asked)
{
	RAII_VAR(PGresult *, result, NULL, PQclear);
	long num_rows;
	struct ast_variable *new_v;
	struct ast_category *cur_cat = NULL;
	struct ast_str *sql = ast_str_thread_get(&sql_buf, 100);
	char last[80];
	int last_cat_metric = 0;
	int pgsqlC;

	last[0] = '\0';

	/*
	 * Ignore database from the extconfig.conf since it is
	 * configured by res_pgsql.conf.
	 */
	database = dbname;

	if (!file || !strcmp(file, RES_CONFIG_PGSQL_CONF)) {
		ast_log_chan(NULL, LOG_WARNING, "PostgreSQL RealTime: Cannot configure myself.\n");
		return NULL;
	}

	ast_str_set(&sql, 0, "SELECT category, var_name, var_val, cat_metric FROM %s "
			"WHERE (root = %i) AND filename='%s' and commented=0 "
			"ORDER BY cat_metric DESC, var_metric ASC, category, var_name ", table, *ast_config_AST_SYSTEM_ROOT, file);

	ast_debug(1, "PostgreSQL RealTime: Static SQL: %s\n", ast_str_buffer(sql));

	pgsqlC = pgsql_getConn();

	if (pgsqlC < 0 || !pgsqlConn[pgsqlC]) {
		ast_log(LOG_ERROR, "PostgreSQL RealTime: no hay conexión activa para escape.\n");
		return NULL;
	}

	/* We now have our complete statement; Lets connect to the server and execute it. */
	if (pgsql_exec(pgsqlC, ast_str_buffer(sql), NULL, NULL, &result) != 0) {
		pgsqlFlag[pgsqlC] = 0;
		return NULL;
	}
	pgsqlFlag[pgsqlC] = 0;

	if ((num_rows = PQntuples(result)) > 0) {
		int rowIndex = 0;

		ast_debug(1, "PostgreSQL RealTime: Found %ld rows.\n", num_rows);

		for (rowIndex = 0; rowIndex < num_rows; rowIndex++) {
			char *field_category = PQgetvalue(result, rowIndex, 0);
			char *field_var_name = PQgetvalue(result, rowIndex, 1);
			char *field_var_val = PQgetvalue(result, rowIndex, 2);
			char *field_cat_metric = PQgetvalue(result, rowIndex, 3);
			if (!strcmp(field_var_name, "#include")) {
				if (!ast_config_internal_load(field_var_val, cfg, flags, "", who_asked)) {
					return NULL;
				}
				continue;
			}

			if (strcmp(last, field_category) || last_cat_metric != atoi(field_cat_metric)) {
				cur_cat = ast_category_new_dynamic(field_category);
				if (!cur_cat) {
					break;
				}
				ast_copy_string(last, field_category, sizeof(last));
				last_cat_metric = atoi(field_cat_metric);
				ast_category_append(cfg, cur_cat);
			}
			new_v = ast_variable_new(field_var_name, field_var_val, "");
			ast_variable_append(cur_cat, new_v);
		}
	} else {
		ast_log_chan(NULL, LOG_WARNING,
				"PostgreSQL RealTime: Could not find config '%s' in database.\n", file);
	}


	return cfg;
}

static int require_pgsql(const char *database, const char *tablename, va_list ap)
{
	struct columns *column;
	struct tables *table;
	char *elm;
	int type, res = 0;
	unsigned int size;
	int pgsqlC;

	/*
	 * Ignore database from the extconfig.conf since it was
	 * configured by res_pgsql.conf.
	 */
	database = dbname;

	table = find_table(database, tablename);
	if (!table) {
		ast_log_chan(NULL, LOG_WARNING, "Table %s not found in database.  This table should exist if you're using realtime.\n", tablename);
		return -1;
	}

	while ((elm = va_arg(ap, char *))) {
		type = va_arg(ap, require_type);
		size = va_arg(ap, unsigned int);
		AST_LIST_TRAVERSE(&table->columns, column, list) {
			if (strcmp(column->name, elm) == 0) {
				/* Char can hold anything, as long as it is large enough */
				if ((strncmp(column->type, "char", 4) == 0 || strncmp(column->type, "varchar", 7) == 0 || strcmp(column->type, "bpchar") == 0 || strncmp(column->type, "text", 4) == 0)) {
					if (column->len != -1 && (size > column->len)) {
						ast_log_chan(NULL, LOG_WARNING, "Column '%s' should be at least %d long, but is only %d long.\n", column->name, size, column->len);
						res = -1;
					}
				} else if (strncmp(column->type, "int", 3) == 0) {
					int typesize = atoi(column->type + 3);
					/* Integers can hold only other integers */
					if ((type == RQ_INTEGER8 || type == RQ_UINTEGER8 ||
						type == RQ_INTEGER4 || type == RQ_UINTEGER4 ||
						type == RQ_INTEGER3 || type == RQ_UINTEGER3 ||
						type == RQ_UINTEGER2) && typesize == 2) {
						ast_log_chan(NULL, LOG_WARNING, "Column '%s' may not be large enough for the required data length: %d\n", column->name, size);
						res = -1;
					} else if ((type == RQ_INTEGER8 || type == RQ_UINTEGER8 ||
						type == RQ_UINTEGER4) && typesize == 4) {
						ast_log_chan(NULL, LOG_WARNING, "Column '%s' may not be large enough for the required data length: %d\n", column->name, size);
						res = -1;
					} else if (type == RQ_CHAR || type == RQ_DATETIME || type == RQ_FLOAT || type == RQ_DATE) {
						ast_log_chan(NULL, LOG_WARNING, "Column '%s' is of the incorrect type: (need %s(%d) but saw %s)\n",
							column->name,
								type == RQ_CHAR ? "char" :
								type == RQ_DATETIME ? "datetime" :
								type == RQ_DATE ? "date" :
								type == RQ_FLOAT ? "float" :
								"a rather stiff drink ",
							size, column->type);
						res = -1;
					}
				} else if (strncmp(column->type, "float", 5) == 0) {
					if (!ast_rq_is_int(type) && type != RQ_FLOAT) {
						ast_log_chan(NULL, LOG_WARNING, "Column %s cannot be a %s\n", column->name, column->type);
						res = -1;
					}
				} else if (strncmp(column->type, "timestamp", 9) == 0) {
					if (type != RQ_DATETIME && type != RQ_DATE) {
						ast_log_chan(NULL, LOG_WARNING, "Column %s cannot be a %s\n", column->name, column->type);
						res = -1;
					}
				} else { /* There are other types that no module implements yet */
					ast_log_chan(NULL, LOG_WARNING, "Possibly unsupported column type '%s' on column '%s'\n", column->type, column->name);
					res = -1;
				}
				break;
			}
		}

		if (!column) {
			if (requirements == RQ_WARN) {
				ast_log_chan(NULL, LOG_WARNING, "Table %s requires a column '%s' of size '%d', but no such column exists.\n", tablename, elm, size);
				res = -1;
			} else {
				struct ast_str *sql = ast_str_create(100);
				char fieldtype[20];
				PGresult *result;

				if (requirements == RQ_CREATECHAR || type == RQ_CHAR) {
					/* Size is minimum length; make it at least 50% greater,
					 * just to be sure, because PostgreSQL doesn't support
					 * resizing columns. */
					snprintf(fieldtype, sizeof(fieldtype), "CHAR(%u)",
						size < 15 ? size * 2 :
						(size * 3 / 2 > 255) ? 255 : size * 3 / 2);
				} else if (type == RQ_INTEGER1 || type == RQ_UINTEGER1 || type == RQ_INTEGER2) {
					snprintf(fieldtype, sizeof(fieldtype), "INT2");
				} else if (type == RQ_UINTEGER2 || type == RQ_INTEGER3 || type == RQ_UINTEGER3 || type == RQ_INTEGER4) {
					snprintf(fieldtype, sizeof(fieldtype), "INT4");
				} else if (type == RQ_UINTEGER4 || type == RQ_INTEGER8) {
					snprintf(fieldtype, sizeof(fieldtype), "INT8");
				} else if (type == RQ_UINTEGER8) {
					/* No such type on PostgreSQL */
					snprintf(fieldtype, sizeof(fieldtype), "CHAR(20)");
				} else if (type == RQ_FLOAT) {
					snprintf(fieldtype, sizeof(fieldtype), "FLOAT8");
				} else if (type == RQ_DATE) {
					snprintf(fieldtype, sizeof(fieldtype), "DATE");
				} else if (type == RQ_DATETIME) {
					snprintf(fieldtype, sizeof(fieldtype), "TIMESTAMP");
				} else {
					ast_log_chan(NULL, LOG_ERROR, "Unrecognized request type %d\n", type);
					ast_free(sql);
					continue;
				}
				ast_str_set(&sql, 0, "ALTER TABLE %s ADD COLUMN %s %s", tablename, elm, fieldtype);
				ast_debug(1, "About to lock pgsql_lock (running alter on table '%s' to add column '%s')\n", tablename, elm);

				ast_debug(1, "About to run ALTER query on table '%s' to add column '%s'\n", tablename, elm);

				pgsqlC = pgsql_getConn();

				if (pgsqlC < 0 || !pgsqlConn[pgsqlC]) {
					release_table(table);
					ast_log(LOG_ERROR, "PostgreSQL RealTime: no hay conexión activa para escape.\n");
					return NULL;
				}

				if (pgsql_exec(pgsqlC, ast_str_buffer(sql), NULL, NULL, &result) != 0) {
					pgsqlFlag[pgsqlC] = 0;
					release_table(table);
					return -1;
				}
				pgsqlFlag[pgsqlC] = 0;

				ast_debug(1, "Finished running ALTER query on table '%s'\n", tablename);
				if (PQresultStatus(result) != PGRES_COMMAND_OK) {
					ast_log_chan(NULL, LOG_ERROR, "Unable to add column: %s\n", ast_str_buffer(sql));
				}
				PQclear(result);

				ast_free(sql);
			}
		}
	}
	release_table(table);
	return res;
}

static int unload_pgsql(const char *database, const char *tablename)
{
	struct tables *cur;

	/*
	 * Ignore database from the extconfig.conf since it was
	 * configured by res_pgsql.conf.
	 */
	database = dbname;

	ast_debug(2, "About to lock table cache list\n");
	AST_LIST_LOCK(&psql_tables);
	ast_debug(2, "About to traverse table cache list\n");
	AST_LIST_TRAVERSE_SAFE_BEGIN(&psql_tables, cur, list) {
		if (strcmp(cur->name, tablename) == 0) {
			ast_debug(2, "About to remove matching cache entry\n");
			AST_LIST_REMOVE_CURRENT(list);
			ast_debug(2, "About to destroy matching cache entry\n");
			destroy_table(cur);
			ast_debug(1, "Cache entry '%s@%s' destroyed\n", tablename, database);
			break;
		}
	}
	AST_LIST_TRAVERSE_SAFE_END
	AST_LIST_UNLOCK(&psql_tables);
	ast_debug(2, "About to return\n");
	return cur ? 0 : -1;
}

static struct ast_config_engine pgsql_engine = {
	.name = "pgsql",
	.load_func = config_pgsql,
	.realtime_func = realtime_pgsql,
	.realtime_multi_func = realtime_multi_pgsql,
	.store_func = store_pgsql,
	.destroy_func = destroy_pgsql,
	.update_func = update_pgsql,
	.update2_func = update2_pgsql,
	.require_func = require_pgsql,
	.unload_func = unload_pgsql,
};

static int load_module(void)
{
	if(!parse_config(0))
		return AST_MODULE_LOAD_DECLINE;

	/* Inicializar estadísticas */
	pgsql_packets_current_minute = 0;
	pgsql_packets_last_minute = 0;
	pgsql_packets_total = 0;
	pgsql_cache_updates = 0;
	pgsql_packets_last_update = time(NULL);
	pgsql_service_start_time = time(NULL);  /* Inicializar tiempo de inicio del servicio */
	pgsql_cache_attempts = 0;
	pgsql_cache_hits = 0;
	pgsql_total_db_queries = 0;

	if (pgsql_cache_update_thread == AST_PTHREADT_NULL) {
		if (ast_pthread_create(&pgsql_cache_update_thread, NULL, do_pgsql_cache_update, NULL) < 0) {
			ast_log_chan(NULL, LOG_ERROR, "Unable to start cache update thread.\n");
		}
	}

	ast_mutex_lock(&pgsql_pool);

	int i;
	for (i = 0; i < PGSQL_MAX_POOL_CONN; i++) {
		pgsqlFlag[i] = 0;
		pgsqlConn[i] = NULL;
		pgsqlTime[i] = 0;
		pgsqlUseCount[i] = 0;

		if (!pgsql_reconnect(i)) {
			if (pgsqlConn[i])
				ast_log_chan(NULL, LOG_WARNING,
					"Postgresql RealTime: Couldn't establish connection: %s\n", PQerrorMessage(pgsqlConn[0]));
			else
				ast_log_chan(NULL, LOG_WARNING,
					"Postgresql RealTime: Couldn't establish connection\n");
		}
	}

	ast_mutex_unlock(&pgsql_pool);

	ast_config_engine_register(&pgsql_engine);

	ast_cli_register_multiple(cli_realtime, ARRAY_LEN(cli_realtime));

	return 0;
}

static int unload_module(void)
{
	struct tables *table;
	/* Acquire control before doing anything to the module itself. */

		if (pgsql_cache_update_thread == AST_PTHREADT_NULL) {
				if (ast_pthread_create(&pgsql_cache_update_thread, NULL, do_pgsql_cache_update, NULL) < 0) {
						ast_log_chan(NULL, LOG_ERROR, "Unable to start cache update thread.\n");               
				}
		}
  
	ast_cli_unregister_multiple(cli_realtime, ARRAY_LEN(cli_realtime));
	ast_config_engine_deregister(&pgsql_engine);

	/* Unlock so something else can destroy the lock. */

	/* Destroy cached table info */
	AST_LIST_LOCK(&psql_tables);
	while ((table = AST_LIST_REMOVE_HEAD(&psql_tables, list))) {
		destroy_table(table);
	}
	AST_LIST_UNLOCK(&psql_tables);

	return 0;
}

static int reload(void)
{
	/* parse_config(1); */

	return 0;
}

static int parse_config(int is_reload)
{
	struct ast_config *config;
	const char *s;
	struct ast_flags config_flags = { is_reload ? CONFIG_FLAG_FILEUNCHANGED : 0 };

	config = ast_config_load(RES_CONFIG_PGSQL_CONF, config_flags);
	if (config == CONFIG_STATUS_FILEUNCHANGED) {
//		if (is_reload && pgsqlConn && PQstatus(pgsqlConn) != CONNECTION_OK) {
//			ast_log_chan(NULL, LOG_WARNING, "PostgreSQL RealTime: Not connected\n");
//		}
		return 0;
	}

	if (config == CONFIG_STATUS_FILEMISSING || config == CONFIG_STATUS_FILEINVALID) {
		ast_log_chan(NULL, LOG_WARNING, "Unable to load config %s\n", RES_CONFIG_PGSQL_CONF);
		return 0;
	}


	/* Check new 'user' option first, then fall back to legacy 'dbuser' */
	s = ast_variable_retrieve(config, "general", "user");
	if (!s) {
		s = ast_variable_retrieve(config, "general", "dbuser");
	}
	if (!s) {
		ast_log_chan(NULL, LOG_WARNING, "PostgreSQL RealTime: No database user found, using 'gabpbx' as default.\n");
		strcpy(dbuser, "gabpbx");
	} else {
		ast_copy_string(dbuser, s, sizeof(dbuser));
	}

	/* Check new 'password' option first, then fall back to legacy 'dbpass' */
	s = ast_variable_retrieve(config, "general", "password");
	if (!s) {
		s = ast_variable_retrieve(config, "general", "dbpass");
	}
	if (!s) {
		ast_log_chan(NULL, LOG_WARNING, "PostgreSQL RealTime: No database password found, using 'gabpbx' as default.\n");
		strcpy(dbpass, "gabpbx");
	} else {
		ast_copy_string(dbpass, s, sizeof(dbpass));
	}

	/* Check new 'hostname' option first, then fall back to legacy 'dbhost' */
	s = ast_variable_retrieve(config, "general", "hostname");
	if (!s) {
		s = ast_variable_retrieve(config, "general", "dbhost");
	}
	if (!s) {
		ast_log_chan(NULL, LOG_WARNING, "PostgreSQL RealTime: No database host found, using localhost via socket.\n");
		dbhost[0] = '\0';
	} else {
		ast_copy_string(dbhost, s, sizeof(dbhost));
	}

	if (!(s = ast_variable_retrieve(config, "general", "dbname"))) {
		ast_log_chan(NULL, LOG_WARNING,
			"PostgreSQL RealTime: No database name found, using 'gabpbx' as default.\n");
		strcpy(dbname, "gabpbx");
	} else {
		ast_copy_string(dbname, s, sizeof(dbname));
	}

	/* Check new 'port' option first, then fall back to legacy 'dbport' */
	s = ast_variable_retrieve(config, "general", "port");
	if (!s) {
		s = ast_variable_retrieve(config, "general", "dbport");
	}
	if (!s) {
		ast_log_chan(NULL, LOG_WARNING, "PostgreSQL RealTime: No database port found, using 5432 as default.\n");
		dbport = 5432;
	} else {
		dbport = atoi(s);
	}

	/* germanico Cache */
	   if (!(s = ast_variable_retrieve(config, "cache", "max_items"))) {
				ast_log_chan(NULL, LOG_WARNING,
						"Postgresql RealTime: No cache max items, using 8000 as default.\n");
				pgsql_cache_max_items = 8000;
		} else {
				pgsql_cache_max_items = atoi(s);
		}

		if (!(s = ast_variable_retrieve(config, "cache", "max_size"))) {
				ast_log_chan(NULL, LOG_WARNING,
						"Postgresql RealTime: No cache max size, using 5120000 bytes as default.\n");
				pgsql_cache_max_size = 5120000;
		} else {
				pgsql_cache_max_size = atoi(s);
		}

		if (!(s = ast_variable_retrieve(config, "networkupd", "port"))) {
				ast_log_chan(NULL, LOG_WARNING,
								"Postgresql RealTime: No port found, using 100 as default.\n");
				cache_port = 3300;
		} else {
				cache_port = atoi(s);
		}

	/* Check new 'appname' option first, then fall back to legacy 'dbappname' */
	s = ast_variable_retrieve(config, "general", "appname");
	if (!s) {
		s = ast_variable_retrieve(config, "general", "dbappname");
	}
	if (!s) {
		dbappname[0] = '\0';
	} else {
		ast_copy_string(dbappname, s, sizeof(dbappname));
	}

	/* Handle socket configuration if no host is specified */
	if (!ast_strlen_zero(dbhost)) {
		/* No socket needed */
	} else {
		s = ast_variable_retrieve(config, "general", "socket");
		if (!s) {
			s = ast_variable_retrieve(config, "general", "dbsock");
		}
		if (!s) {
			ast_log_chan(NULL, LOG_WARNING, "PostgreSQL RealTime: No database socket found, using '/tmp/.s.PGSQL.%d' as default.\n", dbport);
			strcpy(dbsock, "/tmp");
		} else {
			ast_copy_string(dbsock, s, sizeof(dbsock));
		}
	}

	if (!(s = ast_variable_retrieve(config, "general", "requirements"))) {
		ast_log_chan(NULL, LOG_WARNING,
				"PostgreSQL RealTime: no requirements setting found, using 'warn' as default.\n");
		requirements = RQ_WARN;
	} else if (!strcasecmp(s, "createclose")) {
		requirements = RQ_CREATECLOSE;
	} else if (!strcasecmp(s, "createchar")) {
		requirements = RQ_CREATECHAR;
	}

		// tablefunc configuration
		if (!(pgsql_tablefunc = ast_config_new()))
				return -1;

		struct ast_category *cat = NULL;
		if (!(cat = ast_category_new("selectfunc", "", 99999)))
				return -1;
		ast_category_append(pgsql_tablefunc, cat);

		char *stringp, *table, *func;
		struct ast_variable *v = NULL;
		for (v = ast_variable_browse(config, "selectfunc"); v; v = v->next) {
				stringp = (char*) v->value;
				table = strsep(&stringp, ",");
				func  = strsep(&stringp, ",");
				if (table && func) {
					ast_variable_append(cat, ast_variable_new(table, func, ""));
				}
		}

		if (!(cat = ast_category_new("updatefunc", "", 99999)))
				return -1;
		ast_category_append(pgsql_tablefunc, cat);

		v = NULL;
		for (v = ast_variable_browse(config, "updatefunc"); v; v = v->next) {
				stringp = (char*) v->value;
				table = strsep(&stringp, ",");
				func  = strsep(&stringp, ",");
				if (table && func) {
					ast_variable_append(cat, ast_variable_new(table, func, ""));
				}
		}

		if (!(cat = ast_category_new("insertfunc", "", 99999)))
				return -1;
		ast_category_append(pgsql_tablefunc, cat);

		v = NULL;
		for (v = ast_variable_browse(config, "insertfunc"); v; v = v->next) {
				stringp = (char*) v->value;
				table = strsep(&stringp, ",");
				func  = strsep(&stringp, ",");
				if (table && func) {
					ast_variable_append(cat, ast_variable_new(table, func, ""));
				}
		}

	/* Result set ordering is enabled by default */
	s = ast_variable_retrieve(config, "general", "order_multi_row_results_by_initial_column");
	order_multi_row_results_by_initial_column = !s || ast_true(s);

	ast_config_destroy(config);

	if (DEBUG_ATLEAST(1)) {
		if (!ast_strlen_zero(dbhost)) {
			ast_log_chan(NULL, LOG_DEBUG, "PostgreSQL RealTime Host: %s\n", dbhost);
			ast_log_chan(NULL, LOG_DEBUG, "PostgreSQL RealTime Port: %i\n", dbport);
		} else {
			ast_log_chan(NULL, LOG_DEBUG, "PostgreSQL RealTime Socket: %s\n", dbsock);
		}
		ast_log_chan(NULL, LOG_DEBUG, "PostgreSQL RealTime User: %s\n", dbuser);
		ast_log_chan(NULL, LOG_DEBUG, "PostgreSQL RealTime Password: %s\n", dbpass);
		ast_log_chan(NULL, LOG_DEBUG, "PostgreSQL RealTime DBName: %s\n", dbname);
	}

	ast_verb_chan(NULL, 2, "PostgreSQL RealTime reloaded.\n");

	/* Done reloading. Release lock so others can now use driver. */

	return 1;
}

static int pgsql_reconnect(int pgsqlC)
{
	if (pgsqlConn[pgsqlC]) {
		if (PQstatus(pgsqlConn[pgsqlC]) == CONNECTION_OK) {
			/* We're good? */
			return 1;
		}

		PQfinish(pgsqlConn[pgsqlC]);
		pgsqlConn[pgsqlC] = NULL;
	}

	/* DB password can legitimately be 0-length */
	if ((!ast_strlen_zero(dbhost) || !ast_strlen_zero(dbsock)) && !ast_strlen_zero(dbuser) && !ast_strlen_zero(dbname)) {
		struct ast_str *conn_info = ast_str_create(128);

		if (!conn_info) {
			ast_log_chan(NULL, LOG_ERROR, "PostgreSQL RealTime: Failed to allocate memory for connection string.\n");
			return 0;
		}

		ast_str_set(&conn_info, 0, "host=%s port=%d dbname=%s user=%s",
			S_OR(dbhost, dbsock), dbport, dbname, dbuser);

		if (!ast_strlen_zero(dbappname)) {
			ast_str_append(&conn_info, 0, " application_name=%s", dbappname);
		}

		if (!ast_strlen_zero(dbpass)) {
			ast_str_append(&conn_info, 0, " password=%s", dbpass);
		}

		pgsqlConn[pgsqlC] = PQconnectdb(ast_str_buffer(conn_info));
		pgsqlTime[pgsqlC] = time(NULL);
		pgsqlUseCount[pgsqlC] = 0;
		ast_free(conn_info);
		conn_info = NULL;

		ast_debug(1, "pgsqlConn=%p\n", pgsqlConn[pgsqlC]);
		if (pgsqlConn[pgsqlCurrent] && PQstatus(pgsqlConn[pgsqlC]) == CONNECTION_OK) {
			ast_debug(1, "PostgreSQL RealTime: Successfully connected to database.\n");
			version = PQserverVersion(pgsqlConn[pgsqlC]);
			return 1;
		} else {
			ast_log_chan(NULL, LOG_ERROR,
					"PostgreSQL RealTime: Failed to connect database %s on %s: %s\n",
					dbname, dbhost, PQresultErrorMessage(NULL));
			return 0;
		}
	} else {
		ast_debug(1, "PostgreSQL RealTime: One or more of the parameters in the config does not pass our validity checks.\n");
		return 1;
	}
}

static char *handle_cli_realtime_pgsql_cache(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
{
	struct tables *cur;
	int l, which;
	char *ret = NULL;

	switch (cmd) {
	case CLI_INIT:
		e->command = "realtime show pgsql cache";
		e->usage =
			"Usage: realtime show pgsql cache [<table>]\n"
			"       Shows table cache for the PostgreSQL RealTime driver\n";
		return NULL;
	case CLI_GENERATE:
		if (a->argc != 4) {
			return NULL;
		}
		l = strlen(a->word);
		which = 0;
		AST_LIST_LOCK(&psql_tables);
		AST_LIST_TRAVERSE(&psql_tables, cur, list) {
			if (!strncasecmp(a->word, cur->name, l) && ++which > a->n) {
				ret = ast_strdup(cur->name);
				break;
			}
		}
		AST_LIST_UNLOCK(&psql_tables);
		return ret;
	}

	if (a->argc == 4) {
		/* List of tables */
		AST_LIST_LOCK(&psql_tables);
		AST_LIST_TRAVERSE(&psql_tables, cur, list) {
			ast_cli(a->fd, "%s\n", cur->name);
		}
		AST_LIST_UNLOCK(&psql_tables);
	} else if (a->argc == 5) {
		/* List of columns */
		if ((cur = find_table(NULL, a->argv[4]))) {
			struct columns *col;
			ast_cli(a->fd, "Columns for Table Cache '%s':\n", a->argv[4]);
			ast_cli(a->fd, "%-20.20s %-20.20s %-3.3s %-8.8s\n", "Name", "Type", "Len", "Nullable");
			AST_LIST_TRAVERSE(&cur->columns, col, list) {
				ast_cli(a->fd, "%-20.20s %-20.20s %3d %-8.8s\n", col->name, col->type, col->len, col->notnull ? "NOT NULL" : "");
			}
			release_table(cur);
		} else {
			ast_cli(a->fd, "No such table '%s'\n", a->argv[4]);
		}
	}
	return 0;
}

static char *handle_cli_realtime_pgsql_cache_clear(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
{
        switch (cmd) {
        case CLI_INIT:
                e->command = "realtime show pgsql advanced cache clear";
                e->usage =
                        "Usage: realtime show pgsql advanced cache clear\n"
                        "       Clear realtime cache from PostgreSQL RealTime driver\n";
                return NULL;
        case CLI_GENERATE:
                if (a->argc != 6) {
                        return NULL;
                }
                return 0;
        }
        if (a->argc == 6)
                pgsql_cache_clear(e, cmd, a);
        return 0;
}

static char *handle_cli_realtime_pgsql_status(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
{
	char connection_info[256];
	char credentials[100] = "";
	char status[256];
	int ctime;

	switch (cmd) {
	case CLI_INIT:
		e->command = "realtime show pgsql status";
		e->usage =
			"Usage: realtime show pgsql status\n"
			"       Shows connection information for the PostgreSQL RealTime driver\n";
		return NULL;
	case CLI_GENERATE:
		return NULL;
	}

	if (a->argc != 4) {
		return CLI_SHOWUSAGE;
	}

	if (!ast_strlen_zero(dbhost)) {
		snprintf(connection_info, sizeof(connection_info), "%s@%s, port %d", dbname, dbhost, dbport);
	} else if (!ast_strlen_zero(dbsock)) {
		snprintf(connection_info, sizeof(connection_info), "%s on socket file %s", dbname, dbsock);
	} else {
		snprintf(connection_info, sizeof(connection_info), "%s@%s", dbname, dbhost);
	}

	if (!ast_strlen_zero(dbuser)) {
		snprintf(credentials, sizeof(credentials), " with username %s", dbuser);
	}

	int i;
	ast_mutex_lock(&pgsql_pool);

	for (i = 0; i < PGSQL_MAX_POOL_CONN; i++) {
		if (PQstatus(pgsqlConn[i]) == CONNECTION_OK) {
			ctime = time(NULL) - pgsqlTime[i];

			snprintf(status, 255, "Connection %i use count %llu %s open", i, \
					pgsqlUseCount[i], pgsqlFlag[i] ? "Active" : "Inactive");

			if (ctime > 31536000) {
				ast_cli(a->fd, "%s for %d years, %d days, %d hours, %d minutes, %d seconds.\n",
							status, ctime / 31536000, (ctime % 31536000) / 86400,
							(ctime % 86400) / 3600, (ctime % 3600) / 60, ctime % 60);
			} else if (ctime > 86400) {
				ast_cli(a->fd, "%s for %d days, %d hours, %d minutes, %d seconds.\n", status,
							ctime / 86400, (ctime % 86400) / 3600, (ctime % 3600) / 60,
							ctime % 60);
			} else if (ctime > 3600) {
				ast_cli(a->fd, "%s for %d hours, %d minutes, %d seconds.\n", status,
							ctime / 3600, (ctime % 3600) / 60, ctime % 60);
			} else if (ctime > 60) {
				ast_cli(a->fd, "%s for %d minutes, %d seconds.\n", status, ctime / 60,
							ctime % 60);
			} else {
				ast_cli(a->fd, "%s for %d seconds.\n", status, ctime);
			}
		} else {
			ast_cli(a->fd, "Connection %d close\n", i);
		}
	}
	ast_mutex_unlock(&pgsql_pool);

	if (option_verbose > 5) {
		int l;
		ast_mutex_lock(&pgsql_cache_flag);
		for (i = 0; i < pgsql_cache_items; i++) {
			l = time(NULL) - pgsql_cache[i].last;
			ast_cli(a->fd, "Item %08u, last access %02d:%02d:%02d, update = %d\n",
					i, l / 3600, (l % 3600) / 60, l % 60, pgsql_cache[i].update);
		}
		ast_mutex_unlock(&pgsql_cache_flag);
	}

	ast_cli(a->fd, "Local cache SQL's count %u (%u max.), size %lu (%lu max.) bytes\n", pgsql_cache_items, \
			pgsql_cache_max_items, pgsql_cache_size, pgsql_cache_max_size);
            
	/* Mostrar estadísticas de tráfico UDP */
	ast_mutex_lock(&pgsql_stats_lock);
	ast_cli(a->fd, "\n");
	ast_cli(a->fd, "UDP Traffic Statistics:\n");
	ast_cli(a->fd, "----------------------------------------\n");
	ast_cli(a->fd, "Packets/minute (current): %u\n", pgsql_packets_current_minute);
	ast_cli(a->fd, "Packets/minute (last full minute): %u\n", pgsql_packets_last_minute);
	ast_cli(a->fd, "Total packets processed: %u\n", pgsql_packets_total);
	ast_cli(a->fd, "Total cache updates: %u\n", pgsql_cache_updates);
    
	/* Calcular tasa promedio (paquetes por minuto) usando tiempo desde inicio del servicio */
	time_t service_uptime = time(NULL) - pgsql_service_start_time;
	if (service_uptime > 0) {
		double rate = (double)pgsql_packets_total / (service_uptime / 60.0);
		ast_cli(a->fd, "Average rate: %.2f packets/minute\n", rate);
        
		/* Calcular eficiencia de actualizaciones */
		if (pgsql_packets_total > 0) {
			double efficiency = ((double)pgsql_cache_updates / pgsql_packets_total) * 100.0;
			ast_cli(a->fd, "Cache update efficiency: %.2f%%\n", efficiency);
		}
	}
	ast_cli(a->fd, "Statistics collecting for: %ld minutes\n", (service_uptime + 59) / 60);

	/* Agregar estadísticas de caché después de las estadísticas de tráfico UDP */
	ast_cli(a->fd, "\n");
	ast_cli(a->fd, "Cache Performance Statistics:\n");
	ast_cli(a->fd, "----------------------------------------\n");
	ast_cli(a->fd, "Total cache lookup attempts: %llu\n", pgsql_cache_attempts);
	ast_cli(a->fd, "Cache hits (DB queries avoided): %llu\n", pgsql_cache_hits);
	ast_cli(a->fd, "Total DB queries executed: %llu\n", pgsql_total_db_queries);
	
	/* Calcular consultas evitadas y eficiencia de la caché */
	if (pgsql_cache_attempts > 0) {
		double hit_ratio = ((double)pgsql_cache_hits / pgsql_cache_attempts) * 100.0;
		ast_cli(a->fd, "Cache hit ratio: %.2f%%\n", hit_ratio);
	}
	
	/* Calcular consultas teóricas y el ahorro */
	unsigned long long theoretical_queries = pgsql_total_db_queries + pgsql_cache_hits;
	if (theoretical_queries > 0) {
		double savings_ratio = ((double)pgsql_cache_hits / theoretical_queries) * 100.0;
		ast_cli(a->fd, "DB query reduction: %.2f%%\n", savings_ratio);
		ast_cli(a->fd, "Theoretical queries without cache: %llu\n", theoretical_queries);
	}

	ast_mutex_unlock(&pgsql_stats_lock);

	return CLI_SUCCESS;
}

/* needs usecount semantics defined */
AST_MODULE_INFO(GABPBX_GPL_KEY, AST_MODFLAG_LOAD_ORDER, "PostgreSQL RealTime Configuration Driver",
	.support_level = AST_MODULE_SUPPORT_EXTENDED,
	.load = load_module,
	.unload = unload_module,
	.reload = reload,
	.load_pri = AST_MODPRI_REALTIME_DRIVER,
	.requires = "extconfig",
);

