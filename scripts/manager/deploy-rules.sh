#!/usr/bin/env bash
# deploy-rules.sh - copy the custom rule files into the running manager, validate, restart (docs/04-detections.md).
# Run on the Wazuh host from the repo root:  bash scripts/manager/deploy-rules.sh
# These are the same steps I ran by hand after every rule change.
set -euo pipefail
M=${MANAGER_CONTAINER:-single-node-wazuh.manager-1}
COMPOSE_DIR=${COMPOSE_DIR:-$HOME/wazuh/wazuh-docker/single-node}
# Git Bash on Windows rewrites /var/ossec/... into C:/Program Files/Git/var/ossec/... without this
export MSYS_NO_PATHCONV=1

for f in wazuh/rules/home_soc_tuning.xml wazuh/rules/home_soc_detections.xml; do
  docker cp "$f" "$M:/var/ossec/etc/rules/"
  n=$(basename "$f")
  docker exec "$M" chown wazuh:wazuh "/var/ossec/etc/rules/$n"
  docker exec "$M" chmod 660 "/var/ossec/etc/rules/$n"
  echo "copied $n"
done

echo "Validating the full ruleset (wazuh-analysisd -t)..."
docker exec "$M" /var/ossec/bin/wazuh-analysisd -t && echo "ruleset OK"

# Rules load at start. A restart is enough for rules; config changes need a recreate instead:
#   docker compose up -d --force-recreate --no-deps wazuh.manager
# If you run the watcher, mute it first so the restart doesn't page you:  touch ~/wazuh/watcher/PAUSE
( cd "$COMPOSE_DIR" && docker compose restart wazuh.manager )
sleep 30
echo "Daemons running: $(docker exec "$M" /var/ossec/bin/wazuh-control status | grep -c ' is running') (expect 11)"
echo "If that says 0: the manager hit its known startup race. Restart it once more (docs/08-troubleshooting.md)."
