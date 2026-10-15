#!/usr/bin/env bash
# cis-ubuntu2404-batch2-audit.sh - CIS Ubuntu 24.04 hardening, batch 2 = audit rules (docs/04-detections.md, "CIS").
# Result on my web server: SCA score 58% -> 65%. Run batch 1 first (it installs auditd).
# Run from your workstation:  ssh <server> 'bash -s' < scripts/server/cis-ubuntu2404-batch2-audit.sh
#
# Targets the 18 audit-rule checks 35731-35748 (each line written to match the exact regexes in
# /var/ossec/ruleset/sca/cis_ubuntu24-04.yml). Also sends /var/log/audit/audit.log to Wazuh.
# Deliberately NOT done (exceptions):
#   35725/35726 grub audit=1/backlog  -> needs a reboot; do it in a maintenance window
#   35728 keep_logs                   -> never deletes = disk-fill risk; rotation (5x8MB) kept, the SIEM keeps the copy
#   35729/35730 halt/single when full -> a self-inflicted outage on a production web server
#   35749 immutable (-e 2)            -> every rule change would need a reboot
#   35755 audit tools mode            -> Wazuh's policy logic is inverted (compliant 755 fails; wazuh/wazuh#31786)
# Safety: new file only (/etc/audit/rules.d/50-cis.rules, 640 root:root). If the loaded rule count does not match
# the file, the file is removed and the old rule set reloaded. auditd.conf is not touched.
#
# Lesson baked in: my first version stopped silently after step 2. `ausearch` reads STDIN when stdin isn't a
# terminal, and under `ssh 'bash -s'` stdin IS the script, so it ate the rest. Every command that might read
# stdin now gets `< /dev/null`, and ausearch gets `--input-logs`.
set -uo pipefail
R=/etc/audit/rules.d/50-cis.rules
OSSEC=/var/ossec/etc/ossec.conf

[ -e "$R" ] && { echo "already applied? ($R exists)"; exit 1; }

sudo tee "$R" >/dev/null <<'RULES'
## CIS Ubuntu 24.04 6.3.3.x audit rules
## Human actions only where CIS allows it: auid>=1000 and auid!=unset (excludes daemons and containers)

## 35731 sudoers changes
-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d -p wa -k scope

## 35732 commands run as another user (sudo)
-a always,exit -F arch=b64 -C euid!=uid -F auid!=unset -S execve -k user_emulation
-a always,exit -F arch=b32 -C euid!=uid -F auid!=unset -S execve -k user_emulation

## 35733 sudo log tampering
-w /var/log/sudo.log -p wa -k sudo_log_file

## 35734 time changes
-a always,exit -F arch=b64 -S adjtimex,settimeofday -k time-change
-a always,exit -F arch=b32 -S adjtimex,settimeofday -k time-change
-a always,exit -F arch=b64 -S clock_settime -F a0=0x0 -k time-change
-a always,exit -F arch=b32 -S clock_settime -F a0=0x0 -k time-change
-w /etc/localtime -p wa -k time-change

## 35735 network environment
-a always,exit -F arch=b64 -S sethostname,setdomainname -k system-locale
-a always,exit -F arch=b32 -S sethostname,setdomainname -k system-locale
-w /etc/issue -p wa -k system-locale
-w /etc/issue.net -p wa -k system-locale
-w /etc/hosts -p wa -k system-locale
-w /etc/networks -p wa -k system-locale
-w /etc/network -p wa -k system-locale
-w /etc/netplan -p wa -k system-locale

## 35736 unsuccessful file access
-a always,exit -F arch=b64 -S creat,open,openat,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -k access
-a always,exit -F arch=b64 -S creat,open,openat,truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=unset -k access
-a always,exit -F arch=b32 -S creat,open,openat,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -k access
-a always,exit -F arch=b32 -S creat,open,openat,truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=unset -k access

## 35737 user/group/PAM changes
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity
-w /etc/nsswitch.conf -p wa -k identity
-w /etc/pam.conf -p wa -k identity
-w /etc/pam.d -p wa -k identity

## 35738 permission/ownership/xattr changes
-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=unset -k perm_mod
-a always,exit -F arch=b64 -S chown,fchown,lchown,fchownat -F auid>=1000 -F auid!=unset -k perm_mod
-a always,exit -F arch=b32 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=unset -k perm_mod
-a always,exit -F arch=b32 -S lchown,fchown,chown,fchownat -F auid>=1000 -F auid!=unset -k perm_mod
-a always,exit -F arch=b64 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=unset -k perm_mod
-a always,exit -F arch=b32 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=unset -k perm_mod

## 35739 mounts
-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=unset -k mounts
-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=unset -k mounts

## 35740 sessions
-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k session
-w /var/log/btmp -p wa -k session

## 35741 logins (the faillock dir may not exist yet; the watch still loads because /var/run exists)
-w /var/log/lastlog -p wa -k logins
-w /var/run/faillock -p wa -k logins

## 35742 file deletion/rename by users
-a always,exit -F arch=b64 -S unlink,unlinkat,rename,renameat -F auid>=1000 -F auid!=unset -k delete
-a always,exit -F arch=b32 -S unlink,unlinkat,rename,renameat -F auid>=1000 -F auid!=unset -k delete

## 35743 AppArmor policy changes
-w /etc/apparmor/ -p wa -k MAC-policy
-w /etc/apparmor.d/ -p wa -k MAC-policy

## 35744-35746 ACL / context tools (rules stay valid even if setfacl/chacl are not installed)
-a always,exit -F path=/usr/bin/chcon -F perm=x -F auid>=1000 -F auid!=unset -k perm_chng
-a always,exit -F path=/usr/bin/setfacl -F perm=x -F auid>=1000 -F auid!=unset -k perm_chng
-a always,exit -F path=/usr/bin/chacl -F perm=x -F auid>=1000 -F auid!=unset -k perm_chng

## 35747 usermod
-a always,exit -F path=/usr/sbin/usermod -F perm=x -F auid>=1000 -F auid!=unset -k usermod

## 35748 kernel modules
-a always,exit -F arch=b64 -S init_module,finit_module,delete_module,create_module,query_module -F auid>=1000 -F auid!=unset -k kernel_modules
-a always,exit -F path=/usr/bin/kmod -F perm=x -F auid>=1000 -F auid!=unset -k kernel_modules
RULES
sudo chown root:root "$R" < /dev/null && sudo chmod 640 "$R" < /dev/null
WANT=$(sudo grep -c -E '^-[aw] ' "$R" < /dev/null)

echo "[1] Load rules"
LOADOUT=$(sudo augenrules --load < /dev/null 2>&1)
sleep 2
GOT=$(sudo auditctl -l < /dev/null | grep -c -E '^-[aw] ')
echo "  rules in file: $WANT, loaded: $GOT"
echo "$LOADOUT" | grep -i -E "error|unknown|invalid" | head -n 5
if [ "$GOT" -lt "$WANT" ]; then
  echo "!! ROLLBACK: not all rules loaded"
  sudo unlink "$R" < /dev/null; sudo augenrules --load < /dev/null >/dev/null 2>&1
  exit 1
fi
echo "  OK all rules loaded"

echo "[2] Quick test: a sudo command should be audited (key user_emulation)"
sudo true < /dev/null; sleep 1
N=$(sudo ausearch --input-logs -k user_emulation -ts recent < /dev/null 2>/dev/null | grep -c "type=SYSCALL")
[ "$N" -gt 0 ] && echo "  OK $N user_emulation event(s) recorded" || echo "  WARN no user_emulation event yet"

echo "[3] Send audit.log to Wazuh"
if sudo grep -q "/var/log/audit/audit.log" "$OSSEC" < /dev/null; then
  echo "  already configured"
else
  sudo cp -p "$OSSEC" "$OSSEC.bak-pre-audit" < /dev/null
  sudo sh -c "cat >> '$OSSEC'" <<'XML'

<ossec_config>
  <!-- Linux audit log (CIS audit rules in /etc/audit/rules.d/50-cis.rules) -->
  <localfile>
    <log_format>audit</log_format>
    <location>/var/log/audit/audit.log</location>
  </localfile>
</ossec_config>
XML
fi

echo "[4] Restart Wazuh agent -> fresh SCA scan"
sudo systemctl restart wazuh-agent < /dev/null && sleep 15
if [ "$(systemctl is-active wazuh-agent)" != "active" ]; then
  echo "!! agent not active - restoring ossec.conf"
  sudo cp -p "$OSSEC.bak-pre-audit" "$OSSEC" < /dev/null; sudo systemctl restart wazuh-agent < /dev/null; exit 1
fi
sudo grep -E "Analyzing file: '/var/log/audit/audit.log'|Security Configuration Assessment scan finished" /var/ossec/logs/ossec.log < /dev/null | tail -n 2
echo "DONE. Wazuh only alerts on these keys once rules 100220-100229 (home_soc_detections.xml) are deployed."
