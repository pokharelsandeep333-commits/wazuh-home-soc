#!/usr/bin/env bash
# agent-repoint.sh - point an existing Wazuh agent at a manager on a new address (docs/07-watcher-and-migration.md).
# No re-enrollment is needed when the manager's volumes (including client.keys) moved with it.
# Run from your workstation:  ssh <server> 'OLD=<old manager IP> NEW=<new manager IP> bash -s' < scripts/server/agent-repoint.sh
# Rollback: sudo cp /var/ossec/etc/ossec.conf.bak-pre-repoint /var/ossec/etc/ossec.conf && sudo systemctl restart wazuh-agent
set -euo pipefail
: "${OLD:?set OLD}"; : "${NEW:?set NEW}"
CONF=/var/ossec/etc/ossec.conf

if ! sudo grep -q "<address>$OLD</address>" "$CONF"; then
  echo "ABORT: <address>$OLD</address> not found in $CONF. Current:"; sudo grep -n '<address>' "$CONF"; exit 1
fi
sudo cp -p "$CONF" "$CONF.bak-pre-repoint"
sudo sed -i "s#<address>$OLD</address>#<address>$NEW</address>#" "$CONF"
echo "address now: $(sudo grep -oP '(?<=<address>)[^<]+' "$CONF" | head -1)"
START=$(date '+%Y/%m/%d %H:%M:%S')
sudo systemctl restart wazuh-agent
sleep 15
echo "agent: $(systemctl is-active wazuh-agent)"
echo "--- ossec.log since restart (connection lines)"
sudo awk -v s="$START" '$0 >= s' /var/ossec/logs/ossec.log | grep -E 'Connected to the server|Requesting a key|ERROR|WARNING' | tail -n 8
