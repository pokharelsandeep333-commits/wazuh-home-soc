#!/usr/bin/env bash
# fim-cargo-bin.sh - Ubuntu 26.04 only: real-time FIM on /usr/lib/cargo/bin (wazuh/agent/fim-cargo-bin.xml).
# Run from your workstation:  ssh <server> 'bash -s' < scripts/server/fim-cargo-bin.sh
#
# Why: on 26.04, /usr/bin/ls, cat, chmod... are SYMLINKS to the Rust coreutils multicall binary in
# /usr/lib/cargo/bin/coreutils/ (plus a setuid-root su in /usr/lib/cargo/bin/). Default FIM watches /usr/bin
# (sees only the links) but NOT the real binaries. Rootcheck's trojan check for them is silenced on the
# manager (rule 100101, a proven false positive), so FIM on the real files is the compensating control.
# The agent restart also triggers a fresh rootcheck scan, which is a live test of rule 100101.
set -uo pipefail
OSSEC=/var/ossec/etc/ossec.conf
# ---- EDIT: an existing, unique <directories> line inside <syscheck>. The new line goes right after it. ----
ANCHOR='<directories realtime="yes">/etc/nginx,/opt/adguardhome/conf,/etc/ssh</directories>'
NEWLINE='    <directories realtime="yes" check_all="yes">/usr/lib/cargo/bin</directories>'

sudo grep -q '/usr/lib/cargo/bin' "$OSSEC" && { echo "already applied?"; exit 1; }
[ "$(sudo grep -c -F -- "$ANCHOR" "$OSSEC")" = "1" ] || { echo "anchor line not found exactly once"; exit 1; }

sudo cp -p "$OSSEC" "$OSSEC.bak-pre-cargo-fim" && echo "backup: $OSSEC.bak-pre-cargo-fim" || exit 1
T=$(mktemp)
sudo awk -v a="$ANCHOR" -v n="$NEWLINE" '{print} index($0,a){print n}' "$OSSEC" > "$T"
sudo sh -c "cat '$T' > '$OSSEC'"; unlink "$T"
sudo grep -n 'cargo' "$OSSEC"

if sudo /var/ossec/bin/wazuh-syscheckd -t; then
  echo "syscheck config OK"
else
  echo "!! ROLLBACK: config test failed"; sudo sh -c "cat '$OSSEC.bak-pre-cargo-fim' > '$OSSEC'"; exit 1
fi

sudo systemctl restart wazuh-agent
sleep 8
systemctl is-active wazuh-agent
sudo grep -E "cargo|Real-time file integrity monitoring started|ERROR" /var/ossec/logs/ossec.log | tail -n 4
echo "DONE"
