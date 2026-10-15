#!/usr/bin/env bash
# sudolog-rotate.sh - rotate /var/log/sudo.log, which CIS batch 1 creates with no rotation (grows forever).
# Run from your workstation:  ssh <server> 'bash -s' < scripts/server/sudolog-rotate.sh
#
# Monthly, keep 12 (1 year), compressed. sudo opens the file per command, so rename + create is safe.
# Wazuh: the rotation is an audit event on key sudo_log_file by /usr/sbin/logrotate -> rule 100229
# (level 3, no Discord page). Deploy rule 100229 BEFORE running this, or rule 100225 (level 10, "sudo log
# tampering") pages you on every rotation.
#
# Two bugs from my first version are fixed here:
#   1. logrotate skipped the file: "parent directory has insecure permissions" (/var/log is root:syslog 775).
#      Fix = `su root syslog`, the same directive Ubuntu's own /etc/logrotate.d/rsyslog uses.
#   2. The safety check `logrotate -d ... | grep -q error` under `set -o pipefail` reported failure even on a
#      match (grep -q exits early -> SIGPIPE -> pipeline status 141), so a bad config was left in place.
#      Fix = capture the output into a variable first, then grep the variable.
set -uo pipefail
F=/etc/logrotate.d/sudo-log
[ -x /usr/sbin/logrotate ] || { echo "/usr/sbin/logrotate not found - stopping"; exit 1; }
[ -e "$F" ] && { echo "already applied? ($F exists)"; exit 1; }

sudo tee "$F" >/dev/null <<'ROT'
# sudo's own log (Defaults logfile=/var/log/sudo.log, CIS 35664)
/var/log/sudo.log {
    monthly
    rotate 12
    compress
    delaycompress
    missingok
    notifempty
    su root syslog
    create 0600 root root
}
ROT
sudo chmod 644 "$F" < /dev/null

echo "[1] Dry run"
OUT=$(sudo logrotate -d "$F" < /dev/null 2>&1)
echo "$OUT" | grep -i -E "error|rotating pattern|needs rotating|does not need" | head -n 4 | sed 's/^/  /'
if grep -i -q "error" <<< "$OUT"; then echo "!! dry run reported an error - removing $F"; sudo unlink "$F"; exit 1; fi
echo "  OK no errors"

echo "[2] Live test: force one rotation now (expect rule 100229 on the manager)"
date -u +"  forced rotation at %T UTC"
OUT=$(sudo logrotate -f "$F" < /dev/null 2>&1); [ -n "$OUT" ] && echo "$OUT" | sed 's/^/  /'
ls -la /var/log/ 2>/dev/null | grep -E "sudo\.log" | sed 's/^/  /'
sudo true < /dev/null   # the next sudo writes the NEW sudo.log
echo "DONE"
