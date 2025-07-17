/*
 * GABpbx -- A telephony toolkit for Linux.
 *
 * Copyright 2021 (C) Germán Aracil Boned
 * contact mail, german@7kas.com
 *
 * app_fromteams.c for GABpbx 2.5 - PJSIP Version
 *
 */
#ifdef HAVE_CONFIG_H
#include "confdefs.h"
#endif
#include "gabpbx.h"
#include "gabpbx/module.h"
#include "gabpbx/channel.h"
#include "gabpbx/pbx.h"
#include "gabpbx/lock.h"
#include "gabpbx/app.h"
#include "gabpbx/causes.h"
#include "gabpbx/file.h"
#include "gabpbx/cdr.h"
#include "gabpbx/say.h"
#include "gabpbx/options.h"
#include <math.h>
#include <string.h>

static char *app = "FromTeams";
struct ast_app *goto_app = NULL;
struct ast_app *set_app = NULL;

static int fromteams_gabpbxapp(struct ast_channel *chan, struct ast_app *app, void *data)
{
    int ret;
    
    if (!chan) {
        ast_log(LOG_ERROR, "No channel provided to fromteams_gabpbxapp\n");
        return -1;
    }
    
    if (app) {
        ret = pbx_exec(chan, app, data);
    } else {
        ast_log(LOG_WARNING, "Could not find GABPBX application\n");
        ret = -2;
    }
    return ret;
}

static int fromteams_set_header(struct ast_channel *chan, const char *header_name, const char *header_value)
{
    char header_var[256];
    
    if (!chan) {
        ast_log(LOG_ERROR, "No channel provided to fromteams_set_header\n");
        return -1;
    }
    
    if (!header_name || !header_value) {
        ast_log(LOG_WARNING, "Invalid header name or value\n");
        return -1;
    }
    
    /* Formato para PJSIP: PJSIP_HEADER(add,X-Header)=value */
    if (snprintf(header_var, sizeof(header_var), "PJSIP_HEADER(add,%s)=%s", header_name, header_value) >= (int)sizeof(header_var)) {
        ast_log(LOG_WARNING, "Header variable too long\n");
        return -1;
    }
    
    if (set_app) {
        return pbx_exec(chan, set_app, header_var);
    } else {
        /* Alternativa usando pbx_builtin_setvar_helper */
        char var_name[128];
        if (snprintf(var_name, sizeof(var_name), "PJSIP_HEADER(add,%s)", header_name) >= (int)sizeof(var_name)) {
            ast_log(LOG_WARNING, "Variable name too long\n");
            return -1;
        }
        pbx_builtin_setvar_helper(chan, var_name, header_value);
        return 0;
    }
}

static int fromteams_exec(struct ast_channel *chan, const char *data)
{
    int res = 0;
    struct ast_variable *var = NULL, *tmpvar = NULL;
    char context_buffer[64] = "";
    const char *context = NULL;
    const char *fromname = NULL;
    const char *peername = NULL;
    char fromname_buffer[256] = "";
    int msteamssrv = 0;
    int msteamssrvid = 0;
    char tmp[120];
    const char *cdr_clisrc = NULL;
    const char *cdr_clidst = NULL;
    
    if (!chan) {
        ast_log(LOG_ERROR, "Channel is NULL\n");
        return -1;
    }
    
    /* En PJSIP, usamos PJSIP_ENDPOINT para obtener el endpoint */
    peername = pbx_builtin_getvar_helper(chan, "PEERNAME");
    if (!peername) {
        ast_log(LOG_WARNING, "Could not determine peer name\n");
        return -1;
    }
    
    fromname = pbx_builtin_getvar_helper(chan, "MSTEAMS");

    ast_channel_lock(chan);
    if (ast_channel_softhangup_internal_flag(chan)) {
        ast_channel_unlock(chan);
        return -1;
    }
    
    cdr_clisrc = (ast_channel_caller(chan) &&
                                        ast_channel_caller(chan)->id.number.valid) ?
                                        ast_channel_caller(chan)->id.number.str : "";

    cdr_clidst = (ast_channel_dialed(chan) &&
                                        ast_channel_dialed(chan)->number.str &&
                                        ast_channel_dialed(chan)->number.str[0]) ?
                                        ast_channel_dialed(chan)->number.str :
                                        ast_channel_exten(chan);

    ast_channel_unlock(chan);

    if (!fromname || ast_strlen_zero(fromname)) {
        /* Usar clisrc del CDR */
        ast_copy_string(fromname_buffer, cdr_clisrc, sizeof(fromname_buffer));
        fromname = fromname_buffer;
        
        /* Agregar cabeceras SIP para compatibilidad */
        fromteams_set_header(chan, "X-Tucall-FromTeams", fromname);
        fromteams_set_header(chan, "X-Tucall-FromTeamsPeer", peername);
    } else {
        ast_verbose(VERBOSE_PREFIX_3 "[%s|%s] From MSTEAMS %s\n",
            cdr_clisrc, cdr_clidst, fromname);
    }
    
    /* Verifica que fromname sea válido */
    if (!fromname || ast_strlen_zero(fromname)) {
        ast_log(LOG_WARNING, "Empty fromname\n");
        return -1;
    }
    
    /* Copia fromname a un buffer para manipularlo */
    ast_copy_string(fromname_buffer, fromname, sizeof(fromname_buffer));
    fromname = fromname_buffer;
    
    /* Eliminar el + inicial si existe */
    if (fromname[0] == '+') {
        fromname++;
    }
    
    /* En PJSIP, buscar en la tabla ps_endpoints en lugar de sippeers */
    var = ast_load_realtime("ps_endpoints", "id", peername, NULL);
    if (!var) {
        /* Intentar con ps_aors para compatibilidad */
        var = ast_load_realtime("ps_aors", "id", peername, NULL);
        
        if (!var) {
            ast_log(LOG_WARNING, "Could not find peer %s in ps_endpoints or ps_aors\n", peername);
            return -1;
        }
    }
    
    if (var) {
        tmpvar = var;
        while (var) {
            if (!strcasecmp(var->name, "msteamssrvid") && var->value) {
                msteamssrvid = atoi(var->value);
            } else if (!strcasecmp(var->name, "msteamssrv") && var->value) {
                msteamssrv = atoi(var->value);
            }
            var = var->next;
        }
        ast_variables_destroy(tmpvar);
        
        /* Siempre imprimir verbose sin verificar ast_option_verbose */
        ast_verbose(VERBOSE_PREFIX_3 "[%s|%s] From teams (%s) to service %i ID %i\n",
            cdr_clisrc, cdr_clidst, fromname, msteamssrv, msteamssrvid);
        
        /* Verificar la longitud de fromname antes de hacer la operación */
        if (strlen(fromname) >= 8) {
            fromname += 8;
        } else {
            ast_log(LOG_WARNING, "fromname too short: %s\n", fromname);
        }
        
        switch (msteamssrv) {
            case 0: /* Tucloud */
                /* First get Exten by ID */
                pbx_builtin_pushvar_helper(chan, "TCExtID", fromname);
                
                /* Definir el contexto de manera segura */
                ast_copy_string(context_buffer, "tucloud", sizeof(context_buffer));
                context = context_buffer;
                
                /* Siempre imprimir verbose */
                ast_verbose(VERBOSE_PREFIX_3 "[%s|%s] From teams to Service Tucloud TCExtID %s\n",
                    cdr_clisrc, cdr_clidst, fromname);
                break;
                
            default:
                /* Siempre imprimir verbose */
                ast_verbose(VERBOSE_PREFIX_3 "[%s|%s] From teams (%s) to service %i ID %i nothing to do\n",
                    cdr_clisrc, cdr_clidst, fromname, msteamssrv, msteamssrvid);
                return res;
        }
        
        if (context && !ast_strlen_zero(context)) {
            const char *exten = ast_channel_exten(chan);
            
            if (!exten) {
                ast_log(LOG_WARNING, "No extension available for channel\n");
                return -1;
            }
            
            /* Construir la cadena de manera segura */
            memset(tmp, 0, sizeof(tmp));
            if (snprintf(tmp, sizeof(tmp), "%s,%s", context, exten) >= (int)sizeof(tmp)) {
                ast_log(LOG_WARNING, "Destination string too long\n");
                return -1;
            }
            
            /* Agregar el sufijo ",3" si es necesario */
            if (!strcasecmp(context, "tucloud")) {
                size_t current_len = strlen(tmp);
                if (current_len + 2 < sizeof(tmp)) {
                    strncat(tmp, ",3", sizeof(tmp) - current_len - 1);
                } else {
                    ast_log(LOG_WARNING, "Not enough space to append ,3\n");
                    return -1;
                }
            }
            
            fromteams_gabpbxapp(chan, goto_app, tmp);
        }
    }
    
    return res;
}

static int unload_module(void)
{
    int res;
    res = ast_unregister_application(app);
    return res;
}

static int load_module(void)
{
    /* En PJSIP, usamos Set para manipular cabeceras en lugar de SIPAddHeader */
    set_app = pbx_findapp("Set");
    if (!set_app) {
        ast_log(LOG_ERROR, "Could not find application 'Set'\n");
        return AST_MODULE_LOAD_DECLINE;
    }
    
    goto_app = pbx_findapp("Goto");
    if (!goto_app) {
        ast_log(LOG_ERROR, "Could not find application 'Goto'\n");
        return AST_MODULE_LOAD_DECLINE;
    }
    
    return ast_register_application_xml(app, fromteams_exec);
}

AST_MODULE_INFO(GABPBX_GPL_KEY, AST_MODFLAG_DEFAULT, "GAB FromTeams Application",
    .load = load_module,
    .unload = unload_module,
);
