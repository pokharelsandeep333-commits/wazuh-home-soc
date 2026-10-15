#!/usr/bin/env bash
# docker-listener.sh - enable Wazuh's Docker listener on an agent (docs/04-detections.md, "Containers").
# Run from your workstation:  ssh <server> 'TEST_CONTAINER=<name> bash -s' < scripts/server/docker-listener.sh
#
# 1. Python venv /opt/wazuh-docker-venv with the versions the Wazuh docs require
#    (docker==7.1.0 urllib3==1.26.20 requests==2.32.2). The system Python is left alone:
#    pip --break-system-packages could break Ubuntu's own tools (PEP 668).
# 2. Points /var/ossec/wodles/docker/DockerListener's shebang at the venv (as the Wazuh docs describe).
#    An agent upgrade overwrites this file: run this script again after upgrading the agent.
# 3. Adds <wodle name="docker-listener"> in its own <ossec_config> block, restarts the agent.
# 4. Waits past the listener's 60 s start delay, then sends a harmless test exec (expect rule 87907).
# Every command reads </dev/null: under `ssh 'bash -s'`, stdin IS this script, and a command that reads
# stdin (ausearch, ssh, some docker commands) would silently eat the rest of it.
# Tested on Ubuntu 24.04 (Python 3.12) and 26.04 (Python 3.14; Wazuh lists 3.8-3.13, the library test below
# stops the script before Wazuh is touched if your Python can't run it). No container is restarted.
set -uo pipefail
export DEBIAN_FRONTEND=noninteractive
TEST_CONTAINER=${TEST_CONTAINER:-}
VENV=/opt/wazuh-docker-venv
DL=/var/ossec/wodles/docker/DockerListener
OSSEC=/var/ossec/etc/ossec.conf

rollback() {
  echo "!! ROLLBACK: $1"
  [ -f "$OSSEC.bak-pre-docker" ] && sudo cp -p "$OSSEC.bak-pre-docker" "$OSSEC" < /dev/null
  [ -f "$DL.bak-pre-venv" ] && sudo cp -p "$DL.bak-pre-venv" "$DL" < /dev/null
  sudo systemctl restart wazuh-agent < /dev/null; echo "agent: $(systemctl is-active wazuh-agent)"
  exit 1
}

sudo grep -q "docker-listener" "$OSSEC" < /dev/null && { echo "already applied?"; exit 1; }

echo "[1] python3-venv + venv with the versions Wazuh requires"
sudo apt-get install -y -qq python3-venv < /dev/null >/dev/null 2>&1 || { echo "apt install python3-venv failed"; exit 1; }
[ -x "$VENV/bin/python3" ] || sudo python3 -m venv "$VENV" < /dev/null || { echo "venv creation failed"; exit 1; }
sudo "$VENV/bin/pip" install --quiet --disable-pip-version-check docker==7.1.0 urllib3==1.26.20 requests==2.32.2 < /dev/null || { echo "pip install failed"; exit 1; }
sudo "$VENV/bin/python3" -c "import sys, docker; c=docker.from_env(); print('  python', sys.version.split()[0], '| docker lib', docker.__version__, '| API ping', c.ping(), '| containers', len(c.containers.list()))" < /dev/null \
  || { echo "docker library test FAILED on this Python - stopping (nothing changed in Wazuh yet)"; exit 1; }

echo "[2] DockerListener shebang -> venv python"
sudo cp -p "$DL" "$DL.bak-pre-venv" < /dev/null
sudo sed -i "1s|^#!.*|#!$VENV/bin/python3|" "$DL" < /dev/null
echo "  shebang: $(sudo head -n1 "$DL" < /dev/null)"

echo "[3] Agent config"
sudo cp -p "$OSSEC" "$OSSEC.bak-pre-docker" < /dev/null
sudo sh -c "cat >> '$OSSEC'" <<'XML'

<ossec_config>
  <!-- Docker container events (create/start/stop/die/kill/exec...). Venv: /opt/wazuh-docker-venv -->
  <wodle name="docker-listener">
    <disabled>no</disabled>
  </wodle>
</ossec_config>
XML

echo "[4] Restart agent, wait past the 60 s listener delay"
sudo systemctl restart wazuh-agent < /dev/null
sleep 10
[ "$(systemctl is-active wazuh-agent)" = "active" ] || rollback "agent not active"
sleep 60
sudo grep -i "docker" /var/ossec/logs/ossec.log < /dev/null | tail -n 4 | sed 's/^/  /'
sudo grep -i "docker" /var/ossec/logs/ossec.log < /dev/null | tail -n 4 | grep -q -i -E "error|traceback|No module" && rollback "listener reported an error"

if [ -n "$TEST_CONTAINER" ]; then
  echo "[5] Test event (harmless: runs true inside $TEST_CONTAINER, expect rule 87907)"
  sudo docker exec "$TEST_CONTAINER" true < /dev/null && date -u +"  test docker exec sent %T UTC"
fi
echo "DONE"
