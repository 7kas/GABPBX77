#!/usr/bin/env bash
#
#  Sustituye:
#       ast_log(  →  ast_log_chan(NULL,
#       ast_verb( →  ast_verb_chan(NULL,
#
#  • No crea backups
#  • Ignora logger.h y logger.c
#
#  Uso:
#       ./replace_chan.sh            # en el directorio actual
#       ./replace_chan.sh /ruta/src  # sobre otro árbol de código
#
set -euo pipefail

ROOT="${1:-.}"

echo "🔍  Buscando código fuente en: $ROOT"

mapfile -d '' FILES < <(find "$ROOT" -type f \
        \( -name '*.c' -o -name '*.cc' -o -name '*.cpp' -o -name '*.h' \) \
        ! -name 'logger.h' ! -name 'logger.c' -print0)

[[ ${#FILES[@]} -eq 0 ]] && { echo "⚠️  No hay archivos fuente"; exit 1; }

echo "📄  Procesando ${#FILES[@]} archivos…"

for file in "${FILES[@]}"; do
    perl -0777 -i -pe '
        s/\bast_log(?!_chan)\s*\(/ast_log_chan(NULL, /g;
        s/\bast_verb(?!_chan)\s*\(/ast_verb_chan(NULL, /g;
    ' "$file"
done

echo "✅  Sustitución completada (sin backups)."

