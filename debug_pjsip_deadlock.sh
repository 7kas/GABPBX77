#!/bin/bash
# Script para debuggear deadlocks en PJSIP y problemas de cache PostgreSQL

echo "=== GABpbx PJSIP Deadlock & Cache Debugging Script ==="
echo "Ejecutar este script cuando GABpbx deje de responder"
echo "Detectado: ERROR de CACHE FULL en PostgreSQL"
echo ""

# Obtener PID de GABpbx
PID=$(pidof gabpbx)
if [ -z "$PID" ]; then
    echo "ERROR: GABpbx no está ejecutándose"
    exit 1
fi

echo "GABpbx PID: $PID"
echo ""

# Crear directorio para dumps
DUMP_DIR="/tmp/gabpbx_debug_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$DUMP_DIR"

echo "1. Capturando información de threads..."
# Thread info
gdb -batch -p $PID -ex "info threads" -ex "thread apply all bt" > "$DUMP_DIR/threads.txt" 2>&1

echo "2. Generando core dump..."
# Core dump
gcore -o "$DUMP_DIR/gabpbx.core" $PID

echo "3. Capturando estado de locks (si está disponible)..."
# Intentar obtener info de locks desde CLI
gabpbx -rx "core show locks" > "$DUMP_DIR/locks.txt" 2>/dev/null

echo "4. Información del sistema..."
# System info
ps aux | grep gabpbx > "$DUMP_DIR/ps.txt"
netstat -anp | grep $PID > "$DUMP_DIR/netstat.txt" 2>/dev/null
lsof -p $PID > "$DUMP_DIR/lsof.txt" 2>/dev/null

echo "5. Estadísticas de PJSIP..."
# PJSIP stats
gabpbx -rx "pjsip show endpoints" > "$DUMP_DIR/pjsip_endpoints.txt" 2>/dev/null
gabpbx -rx "pjsip show registrations" > "$DUMP_DIR/pjsip_registrations.txt" 2>/dev/null
gabpbx -rx "pjsip show contacts" > "$DUMP_DIR/pjsip_contacts.txt" 2>/dev/null

echo "6. Estado de memoria y cache..."
# Memory stats
gabpbx -rx "memory show summary" > "$DUMP_DIR/memory_summary.txt" 2>/dev/null
gabpbx -rx "memory show allocations" > "$DUMP_DIR/memory_allocations.txt" 2>/dev/null

# PostgreSQL cache info
gabpbx -rx "realtime show pgsql status" > "$DUMP_DIR/pgsql_status.txt" 2>/dev/null
gabpbx -rx "realtime show pgsql cache" > "$DUMP_DIR/pgsql_cache.txt" 2>/dev/null

# System memory
free -m > "$DUMP_DIR/system_memory.txt"
cat /proc/$PID/status > "$DUMP_DIR/process_status.txt"

echo "7. Configuración de res_config_pgsql..."
grep -E "(cache|pgsql)" /etc/gabpbx/*.conf > "$DUMP_DIR/pgsql_config.txt" 2>/dev/null

echo ""
echo "Debug información guardada en: $DUMP_DIR"
echo ""
echo "PROBLEMA DETECTADO: Cache PostgreSQL lleno"
echo "Posibles soluciones:"
echo "1. Aumentar el tamaño del cache en res_pgsql.conf"
echo "2. Revisar consultas que no se están liberando"
echo "3. Verificar memoria disponible del sistema"
echo ""
echo "Para analizar el deadlock:"
echo "1. gdb /usr/sbin/gabpbx $DUMP_DIR/gabpbx.core"
echo "2. (gdb) thread apply all bt"
echo "3. Buscar threads bloqueados en pthread_mutex_lock o similar"
echo "4. Revisar threads esperando en pgsql_cache_add"