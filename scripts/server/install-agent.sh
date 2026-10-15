#!/usr/bin/env bash
# install-agent.sh - install a Wazuh agent on Ubuntu, pinned to the manager's version, reporting over Tailscale.
# Usage (on the server):  sudo WAZUH_MANAGER=<WAZUH_MANAGER_IP> AGENT_NAME=<name> bash install-agent.sh
# Enrollment needs TCP 1515 open on the manager for a few minutes (docs/03-agents.md). Close it again after.
# I ran these exact commands by hand on both servers; this file collects them into one script.
set -euo pipefail
: "${WAZUH_MANAGER:?set WAZUH_MANAGER to the Tailscale IP of the manager}"
: "${AGENT_NAME:?set AGENT_NAME}"
VERSION=${VERSION:-4.14.8-1}   # never newer than the manager

echo "[1] Reachability over Tailscale"
nc -zv -w 5 "$WAZUH_MANAGER" 1514
nc -zv -w 5 "$WAZUH_MANAGER" 1515 || { echo "1515 closed: open it on the manager while enrolling"; exit 1; }

echo "[2] Wazuh apt repo (signed)"
curl -fsS https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --batch --yes --no-default-keyring \
  --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import
chmod 644 /usr/share/keyrings/wazuh.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
  > /etc/apt/sources.list.d/wazuh.list
apt-get update -qq

echo "[3] Install $VERSION"
WAZUH_MANAGER="$WAZUH_MANAGER" WAZUH_AGENT_NAME="$AGENT_NAME" DEBIAN_FRONTEND=noninteractive \
  apt-get install -y -qq "wazuh-agent=$VERSION"
systemctl daemon-reload
systemctl enable --now wazuh-agent
echo "wazuh-agent hold" | dpkg --set-selections   # an apt upgrade must not make the agent newer than the manager

echo "[4] Verify"
sleep 10
grep -E "Valid key|Connected to the server" /var/ossec/logs/ossec.log | tail -n 3
echo "On the manager: docker exec single-node-wazuh.manager-1 /var/ossec/bin/agent_control -l"
