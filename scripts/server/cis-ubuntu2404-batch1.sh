#!/usr/bin/env bash
# cis-ubuntu2404-batch1.sh - CIS Ubuntu 24.04 hardening, batch 1 = safe quick wins (docs/04-detections.md, "CIS").
# Result on my web server: SCA score 53% -> 58% (with batch 2: 65%).
# Run from your workstation:  ssh <server> 'bash -s' < scripts/server/cis-ubuntu2404-batch1.sh
#
# Every fix was checked against the exact rule in /var/ossec/ruleset/sca/cis_ubuntu24-04.yml (Wazuh 4.14.8).
# Targets 24 checks: 35543 35545 35547 35548 35585 35587 35594-35600 35604-35607 35640 35644 35657 35659 35664 35723 35724
# Safety:
#   - backups of every file touched -> /root/cis-backup-<date>/
#   - sudoers: validated with `visudo -c` BEFORE install (a broken sudoers file = no sudo)
#   - sshd: validated with `sshd -t` BEFORE reload; reload keeps existing sessions; auto-restore on failure
#   - KEEP A SECOND SSH SESSION OPEN until you have tested a fresh login afterwards
# NOT included (risky or exceptions, see docs/04): partitions, host firewall, ip_forward (Docker needs it),
#   PAM lockout, AppArmor enforce-all, shell timeout, at.allow (35601 requires the `at` package to be
#   INSTALLED; installing it only to pass a check adds attack surface)
set -uo pipefail
export DEBIAN_FRONTEND=noninteractive
# ---- EDIT: users allowed to use crontab (CIS 35600). Keep any user whose crontab runs your app's jobs. ----
CRON_USERS="root ubuntu"
B=/root/cis-backup-$(date +%F)
ok()   { echo "  OK   $*"; }
fail() { echo "  FAIL $*"; FAILED=1; }
FAILED=0

sudo mkdir -p "$B" && sudo chmod 700 "$B"
for f in /etc/ssh/sshd_config /etc/issue /etc/issue.net /etc/default/apport /etc/crontab; do
  [ -e "$f" ] && sudo cp -p "$f" "$B/$(echo "$f" | tr / _)"
done
echo "backups: $B"

echo "[1] Remove telnet/ftp clients (35585, 35587)"
sudo apt-get purge -y -qq telnet inetutils-telnet ftp tnftp >/dev/null 2>&1
for p in telnet inetutils-telnet ftp tnftp; do dpkg-query -W -f='${Status}' $p 2>/dev/null | grep -q "install ok installed" && fail "$p still installed" || ok "$p removed"; done

echo "[2] Core dumps restricted (35543)"
echo "fs.suid_dumpable = 0" | sudo tee /etc/sysctl.d/60-cis-coredump.conf >/dev/null
sudo sysctl -q -p /etc/sysctl.d/60-cis-coredump.conf
echo "* hard core 0" | sudo tee /etc/security/limits.d/60-cis-coredump.conf >/dev/null
[ "$(sysctl -n fs.suid_dumpable)" = "0" ] && ok "fs.suid_dumpable=0" || fail "suid_dumpable"

echo "[3] Apport disabled (35545)"
[ -f /etc/default/apport ] && sudo sed -i 's/^enabled=.*/enabled=0/' /etc/default/apport
sudo systemctl disable --now apport.service >/dev/null 2>&1
[ "$(systemctl is-active apport.service 2>/dev/null)" != "active" ] && ok "apport inactive" || fail "apport still active"

echo "[4] Login banners (35547, 35548)"
BANNER="Authorized access only. All activity on this system is monitored and logged."
echo "$BANNER" | sudo tee /etc/issue /etc/issue.net >/dev/null
sudo chmod 644 /etc/issue /etc/issue.net
grep -q -E 'Ubuntu|\\[mrsv]' /etc/issue /etc/issue.net && fail "banner still has OS info" || ok "banners set"

echo "[5] Cron permissions + cron.allow (35594-35600)"
sudo chown root:root /etc/crontab && sudo chmod 600 /etc/crontab
for d in /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.d; do sudo chown root:root "$d" && sudo chmod 700 "$d"; done
printf "%s\n" $CRON_USERS | sudo tee /etc/cron.allow >/dev/null
sudo chown root:root /etc/cron.allow && sudo chmod 640 /etc/cron.allow
# Note: with cron.allow at root:root 640, the `crontab` COMMAND run as a normal user can no longer read it,
# so `crontab -l` fails for that user. The cron DAEMON still runs their jobs. Edit with: sudo crontab -u <user> -e
stat -c "%a %U:%G %n" /etc/crontab /etc/cron.d /etc/cron.allow | sed 's/^/       /'

echo "[6] Disable unused network protocol modules (35604-35607)"
sudo tee /etc/modprobe.d/60-cis-net-protocols.conf >/dev/null <<'MOD'
# CIS 3.2.x - uncommon network protocols
install dccp /bin/false
blacklist dccp
install tipc /bin/false
blacklist tipc
install rds /bin/false
blacklist rds
install sctp /bin/false
blacklist sctp
MOD
for m in dccp tipc rds sctp; do modprobe -n -v $m 2>/dev/null | grep -q "^install /bin/false" && ok "$m blocked" || fail "$m not blocked"; done

echo "[7] sudo log file (35664)"
# Note: Wazuh 4.14.8's check 35664 can never pass via /etc/sudoers.d (missing r: in the policy's file
# pattern, reported upstream as wazuh/wazuh#40275). The control below is still correct and effective.
TMP=$(mktemp)
echo 'Defaults logfile=/var/log/sudo.log' > "$TMP"
if sudo visudo -c -q -f "$TMP"; then
  sudo install -o root -g root -m 0440 "$TMP" /etc/sudoers.d/60-cis-logfile
  sudo visudo -c -q && ok "sudoers valid, logfile=/var/log/sudo.log" || { sudo unlink /etc/sudoers.d/60-cis-logfile; fail "full sudoers check failed - removed"; }
else
  fail "sudoers snippet invalid - not installed"
fi
unlink "$TMP"
echo "  -> also run scripts/server/sudolog-rotate.sh, or sudo.log grows forever"

echo "[8] auditd (35723, 35724)"
sudo apt-get install -y -qq auditd audispd-plugins >/dev/null 2>&1
sudo systemctl enable --now auditd >/dev/null 2>&1
[ "$(systemctl is-active auditd)" = "active" ] && ok "auditd active" || fail "auditd not active"

echo "[9] SSH: sshd_config 0600, PermitRootLogin no, Banner, MaxStartups 10:30:60 (35640 35659 35644 35657)"
sudo chmod 600 /etc/ssh/sshd_config && sudo chown root:root /etc/ssh/sshd_config
# 35659 requires the line in the MAIN file. Appending is safe only if the file has no Match blocks: check yours.
sudo grep -q -E '^\s*PermitRootLogin\s+no' /etc/ssh/sshd_config || echo 'PermitRootLogin no' | sudo tee -a /etc/ssh/sshd_config >/dev/null
sudo tee /etc/ssh/sshd_config.d/20-cis.conf >/dev/null <<'SSH'
# CIS 5.1.x
Banner /etc/issue.net
MaxStartups 10:30:60
SSH
sudo chmod 600 /etc/ssh/sshd_config.d/20-cis.conf
if sudo sshd -t; then
  sudo systemctl try-reload-or-restart ssh
  sudo sshd -T | grep -E "^(permitrootlogin|banner|maxstartups|passwordauthentication) " | sed 's/^/       /'
  ok "sshd config valid and reloaded (existing sessions kept)"
else
  echo "  !! sshd -t FAILED - restoring SSH config"
  sudo cp -p "$B/_etc_ssh_sshd_config" /etc/ssh/sshd_config
  sudo unlink /etc/ssh/sshd_config.d/20-cis.conf
  sudo sshd -t && echo "  restored OK"
  FAILED=1
fi

echo "[10] Containers still up?"
for c in $(sudo docker ps --format '{{.Names}}' 2>/dev/null); do printf "       %-28s %s\n" "$c" "$(sudo docker inspect -f '{{.State.Status}} {{if .State.Health}}{{.State.Health.Status}}{{end}}' "$c")"; done

echo "[11] Restart Wazuh agent -> fresh SCA scan"
sudo systemctl restart wazuh-agent && sleep 15
sudo grep "sca" /var/ossec/logs/ossec.log | tail -n 2

[ "$FAILED" = "0" ] && echo "DONE - all steps OK" || echo "DONE WITH FAILURES - read the FAIL lines above"
echo "IMPORTANT: before closing this session, test a NEW SSH login in another window."
