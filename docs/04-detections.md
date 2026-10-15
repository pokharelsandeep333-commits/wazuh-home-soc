# 4. Detections, tuning and hardening

Out of the box Wazuh gives you login monitoring, rootkit checks and CIS scoring. This page covers what I added, how each piece was tested, and the rule files in [wazuh/rules/](../wazuh/rules/).

## Deploying the rules

```bash
bash scripts/manager/deploy-rules.sh      # docker cp, chown wazuh:wazuh, chmod 660, wazuh-analysisd -t, restart
```

Custom rules live in their own files so Wazuh upgrades never overwrite them. ID ranges: **100100-100199 tuning**, **100200+ detections**. Then replay the test events:

```bash
docker cp wazuh/tests/. single-node-wazuh.manager-1:/tmp/home-soc-tests/
docker exec single-node-wazuh.manager-1 /var/ossec/framework/python/bin/python3 /tmp/home-soc-tests/run_logtest.py
```

The same test suite runs in CI against a clean `wazuh/wazuh-manager:4.14.8` container on every push ([.github/workflows/rules.yml](../.github/workflows/rules.yml)). Most cases come in pairs: the event a rule should catch or silence, and a similar one that must **still** alert. Rootcheck and vulnerability events can't be replayed through logtest, so 100101 and 100109 are covered by the notes below instead.

## File integrity (FIM)

[wazuh/agent/fim-realtime.xml](../wazuh/agent/fim-realtime.xml). Real-time monitoring of quiet folders: SSH config, nginx config, app folders. Test: create, edit, then delete a file in a watched folder. Expect 554 (added), 550 (modified), 553 (deleted) within about a second, plus 5402 (sudo) showing who did it.

- **No `report_changes`** on folders that hold `.env` files. Diffs would copy the secrets into the SIEM.
- Keep log files out of watched folders, or every log write becomes an alert.

## Web logs and secrets-file probes

Both servers ship nginx access logs. Normal 200s are dropped at level 0; Wazuh alerts on 4xx/5xx, SQL injection (31103), path traversal (31104), XSS (31105) and, most important, **an attack pattern that got a 200 (31106)**.

Wazuh 4.14.8 has no rule for bots requesting `/.env`, `/.git/config` or `/.aws/credentials`. They show up only as a plain 404. Rules **100210-100212**:

| Rule | Level | Fires when |
|---|---|---|
| 100210 | 8 | Request for a secrets path, any status |
| 100211 | 12 | Same, but answered **2xx**: the file may have leaked. Check now |
| 100212 | 10 | 5+ probes from one IP in 120 s: a scanner |

The `if_sid` list matters: a web event first lands on a status rule (31108 for 2xx/3xx, 31101 for 4xx, 31120 for 5xx). A rule hanging only off 31100 never sees them. I copied that list from Wazuh's own SQL-injection rule.

Live result: none of my five hostnames served either file. On the sites behind Cloudflare, Cloudflare's managed rules blocked `/.env` at the edge, so Wazuh there only sees what gets past Cloudflare.

## Attack simulation (only against your own servers)

```powershell
1..10 | ForEach-Object { ssh -o BatchMode=yes -o ConnectTimeout=5 fakeuser@<SERVER_TAILSCALE_IP> exit 2>$null }
```
then log in for real and run `sudo useradd -M wazuhtest; sudo userdel wazuhtest`. Wazuh correlates the chain on its own:

| Rule | Level | Meaning |
|---|---|---|
| 5710 | 5 | Login with a non-existent user |
| 5712 | 10 | SSH brute force (8+ in 120 s) |
| 40112 | 12 | Failed logins followed by a success, same IP |
| 40501 | 15 | Attack followed by a new user |

5902 "new user added" does not appear: 40501 replaces it. Check by event (`full_log`), not only by the rule ID you expect. Make sure fail2ban won't ban your own IP first.

## AWS account (CloudTrail)

Setup: [05-cloudtrail.md](05-cloudtrail.md). Rules **100200-100207**: root console login (12), root login without MFA (14), failed root login (10), new IAM user/key/role (10), permission change (10), **AdministratorAccess** granted (12), MFA removed (12), **CloudTrail tampering** (13).

The gap I found: Wazuh only raises CloudTrail events whose names are in `etc/lists/amazon/aws-eventnames`. `DeleteTrail`, `UpdateTrail` and `PutEventSelectors` are **not** in that list, so deleting the trail produced no alert at all. Rule 100207 hangs off the base AWS rule 80200 as well to catch them.

## Linux audit (CIS keys)

[scripts/server/cis-ubuntu2404-batch2-audit.sh](../scripts/server/cis-ubuntu2404-batch2-audit.sh) loads 53 CIS audit rules, tagged with keys like `scope`, `identity`, `kernel_modules`. Wazuh reads the audit log but its stock rules only alert on keys in its own CDB list, so CIS-keyed events stay at level 0. Rules **100220-100229** turn the important keys into alerts: sudoers changed (10), account/PAM files (8), kernel module loaded by a user (10), sudo log written by anything **other than** sudo (10, log tampering), with logrotate carved out at level 3 (100229) and a fake `/tmp/usr/sbin/logrotate` still alerting.

The audit rules use `auid>=1000 -F auid!=unset` where CIS allows it: human actions only, no daemons or containers. Volume stayed around 230 KB in the first hour.

## Containers

[scripts/server/docker-listener.sh](../scripts/server/docker-listener.sh). Alerts on `docker exec` (87907), shells in containers (87908), destroyed containers (87902), `docker cp` (87910/87911).

Docker runs every HEALTHCHECK as an exec: about **14,000 alerts a day**. Tuning rules 100102-100107 each match **one exact command in one exact container**, using PCRE2 `\Q...\E` so the command is literal. The same command in another container, an extra `; id` appended, or a shell still alert. **Replace the container names and commands with yours**: `docker inspect -f '{{json .Config.Healthcheck.Test}}' <container>`.

## Vulnerability detection

[wazuh/manager/ossec-vulnerability-detection.xml](../wazuh/manager/ossec-vulnerability-detection.xml). Read the disk warning in that file first. About 95 % of my findings were the Ubuntu kernel, with no fixed kernel available yet; rule 100109 demotes `linux-*` High/Critical to level 7 so a kernel update can't flood Discord with hundreds of re-evaluated CVEs. Every other package still pages.

It covers host packages only, not software inside Docker images. That needs an image scanner such as Trivy.

## Tuning: proof first, then a narrow rule

Every tuning rule followed the same steps: find the noisy alert, **prove** it benign, silence exactly that pattern, test that similar events still alert.

| Rule | Noise | Proof |
|---|---|---|
| 100100 | AppArmor `who` denials at every SSH login (Ubuntu 26.04) | 42/42 alerts were the same two reads, timestamps matched SSH logins |
| 100101 | 58 rootcheck "trojaned binary" alerts on `ls`, `cat`, `chmod`... (Ubuntu 26.04) | All 10 are links to one Rust coreutils binary, byte-for-byte identical to a fresh copy from Ubuntu's archive; Wazuh's string signatures match normal text inside it. Compensating control: FIM on the real binaries ([fim-cargo-bin.sh](../scripts/server/fim-cargo-bin.sh)) |
| 100102-100107 | Docker healthcheck execs | `docker inspect` per container |
| 100108 | auditd "promiscuous mode" (level 10) on every container restart | 15/15 were `veth*` devices with no logged-in user, one second after Watchtower recreated a container |
| 31151 overwrite | "Multiple 400s from one IP" paging for every internet scanner | Demoted 10 → 8: still stored, no page. 100211/100212 still page the dangerous case |
| 100109 | Kernel CVE floods | Both servers already ran the newest kernel |

`wazuh-logtest` can't replay rootcheck events (they're decoded from their own agent queue), so 100101 was tested by running its regex over all 58 real alerts (58/58 matched, 5 negatives still alerted) and by a live rescan (0 new alerts).

Result: Discord went from 44 pings in 2 days to about 0-2 a day, all real.

## CIS hardening

| Machine | Before | After | Script |
|---|---|---|---|
| Ubuntu 24.04 web server | 53% | 65% | [batch 1](../scripts/server/cis-ubuntu2404-batch1.sh), [batch 2](../scripts/server/cis-ubuntu2404-batch2-audit.sh) |
| Windows 11 homelab | 25% | 45% | [cis-win11-hardening.ps1](../scripts/windows/cis-win11-hardening.ps1) |

The score rose only 5 points after batch 1 even though 23 of 24 targeted checks flipped: installing auditd made 28 audit checks *applicable*, so the denominator grew. Batch 2 then made them pass.

100% is not the goal. These are documented exceptions (an **exception register**), each with a compensating control:

| Checks | Why skipped | Instead |
|---|---|---|
| Separate partitions (26 checks) | Would mean rebuilding the root disk | Encrypted EBS + daily snapshots |
| IP forwarding disabled | Docker requires it | Containers on isolated networks |
| Host firewall (ufw/nftables) | Docker manages iptables | AWS security group + Cloudflare |
| Bootloader password | Cloud VM, no physical console | AWS account access + root MFA |
| AIDE | Redundant | Wazuh real-time FIM |
| Remote log host | Not using rsyslog forwarding | The Wazuh agent ships logs off-host |
| auditd halt / single-user on full disk | A self-inflicted outage on a web server | auditd suspends instead; Wazuh keeps the copy |
| Immutable audit rules (`-e 2`) | Every rule change would need a reboot | Revisit once the rules are stable |
| grub `audit=1` | Needs a reboot | Maintenance window |

Two checks are **bugs in Wazuh's CIS policy**, not in the server:

- **35664 (sudo log file)** can never pass via `/etc/sudoers.d`: the file pattern is missing its `r:` prefix, so `\.*` is read as a literal filename. Reported as [wazuh/wazuh#40275](https://github.com/wazuh/wazuh/issues/40275). The same line was copied into the new Ubuntu 26.04 policy.
- **35755 (audit tools mode)** has inverted logic: compliant mode 755 fails. Already reported as [wazuh/wazuh#31786](https://github.com/wazuh/wazuh/issues/31786).

Wazuh 4.14.8 ships no CIS policy for Ubuntu 26.04, so the DNS server has no score.
