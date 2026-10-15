# 3. Agents

## Linux servers

1. Temporarily publish TCP 1515 (enrollment) on the manager and allow it in the Tailscale policy, or enroll by key (below).
2. On each server:
   ```bash
   sudo WAZUH_MANAGER=<WAZUH_MANAGER_IP> AGENT_NAME=webserver bash scripts/server/install-agent.sh
   ```
   The script checks both ports over Tailscale, installs the agent from Wazuh's signed apt repo pinned to **4.14.8-1**, and puts it on `apt hold`. An agent must never be newer than the manager, so upgrade the manager first, always.
3. On the manager:
   ```bash
   docker exec single-node-wazuh.manager-1 /var/ossec/bin/agent_control -l
   ```
   "Pending" for about a minute is normal; it flips to Active after the first keep-alive.
4. **Close 1515 again**: comment the port out in `docker-compose.yml`, recreate the manager, and remove it from the Tailscale policy. Verify from a server that 1514 connects and 1515 times out.

## Enrolling without port 1515

Useful for an agent on the Wazuh host itself, or any time you don't want to reopen 1515:

```bash
docker exec -it single-node-wazuh.manager-1 /var/ossec/bin/manage_agents -a any -n <name>   # prints the new ID
docker exec -it single-node-wazuh.manager-1 /var/ossec/bin/manage_agents -e <ID>            # prints the key
```

Import the key on the agent (`manage_agents -i` on Linux, or write it into `client.keys` on Windows). The key is a secret: pipe it straight into the file instead of printing it.

## Windows agent on the Wazuh host

I put an agent on the homelab box itself, so the SIEM host is monitored too:

- MSI from `packages.wazuh.com/4.x/windows/`, the same 4.14.8 version as the manager. Wazuh publishes no checksum file, so I checked the **Authenticode signature** instead (`Get-AuthenticodeSignature`: Valid, signer "Wazuh, Inc").
- `msiexec /i wazuh-agent-4.14.8-1.msi /q WAZUH_MANAGER="127.0.0.1" WAZUH_AGENT_NAME="homelab"`. The manager is on the same machine, and WSL mirrored mode passes loopback, so there's no Tailscale dependency.
- Enrolled with the key method above. Out of the box it covers Windows event logs, FIM on key folders and registry, the CIS Windows 11 SCA policy and vulnerability detection for installed apps.

## What I added to each agent

| Agent | Added | File |
|---|---|---|
| Web server (Ubuntu 24.04) | Real-time FIM on the app folder and `/etc/ssh` | [wazuh/agent/fim-realtime.xml](../wazuh/agent/fim-realtime.xml) |
| | Dockerized nginx access log | [scripts/server/weblogs-docker-nginx.sh](../scripts/server/weblogs-docker-nginx.sh) |
| | Docker listener | [scripts/server/docker-listener.sh](../scripts/server/docker-listener.sh) |
| | CIS hardening + audit log | [scripts/server/cis-ubuntu2404-batch1.sh](../scripts/server/cis-ubuntu2404-batch1.sh), [batch 2](../scripts/server/cis-ubuntu2404-batch2-audit.sh) |
| DNS server (Ubuntu 26.04) | Real-time FIM on nginx, AdGuard config, `/etc/ssh` | [wazuh/agent/fim-realtime.xml](../wazuh/agent/fim-realtime.xml) |
| | FIM on the real coreutils binaries | [scripts/server/fim-cargo-bin.sh](../scripts/server/fim-cargo-bin.sh) |
| | Docker listener | [scripts/server/docker-listener.sh](../scripts/server/docker-listener.sh) |
| Homelab (Windows 11) | CIS hardening | [scripts/windows/cis-win11-hardening.ps1](../scripts/windows/cis-win11-hardening.ps1) |

The host nginx on the DNS server needed nothing: the agent's default config already reads `/var/log/nginx/access.log`.

Every server script backs up what it touches, validates before applying (`wazuh-syscheckd -t`, `nginx -t`, `sshd -t`, `visudo -c`) and rolls back on failure. Run them from your workstation with `ssh <server> 'bash -s' < script.sh`.
