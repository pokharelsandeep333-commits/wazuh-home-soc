# 2. Deploy Wazuh (single-node Docker)

Wazuh 4.14.8, single-node, from the official [wazuh-docker](https://github.com/wazuh/wazuh-docker) repo. I first ran it in Docker Desktop on my Windows laptop, then moved it to an always-on homelab box running Docker Engine inside WSL2 Ubuntu 24.04. Both are covered; where they differ it's marked.

## Requirements (check before starting)

| | Need | Why |
|---|---|---|
| RAM | 8 GB for Docker | Real use is ~2.1-2.5 GB, but the indexer spikes |
| Disk | **50 GB free** (Wazuh's own figure), 30+ GB more for vulnerability detection | Disk filled up twice on my first host. See [troubleshooting](08-troubleshooting.md) problems 1, 2, 5 and 6 |
| `vm.max_map_count` | 262144 | The indexer (OpenSearch) refuses to start below it |
| Always on | Host must not sleep | A sleeping laptop collects nothing |

## Part A: Prepare the host

**Windows + WSL2:** cap WSL's memory **before** anything heavy runs. An uncapped WSL VM took 13 GB on my laptop, Windows grew the pagefile by 7 GB to back it, and the disk hit 0 bytes.

```ini
# %USERPROFILE%\.wslconfig
[wsl2]
memory=8GB
swap=2GB
# Docker Desktop only: the indexer needs this kernel setting
kernelCommandLine = "sysctl.vm.max_map_count=262144"
# Docker Engine inside an always-on WSL Ubuntu also wants these two:
networkingMode=mirrored        # Ubuntu shares the host's IPs, including the Tailscale one
[general]
instanceIdleTimeout=-1         # otherwise the distro stops 15 s after the last terminal closes, killing Docker
```

```powershell
wsl --shutdown
docker run --rm alpine sysctl vm.max_map_count     # expect 262144
```

Set "never sleep on AC" and "lid close: do nothing on AC". For a laptop that stays plugged in, set a battery charge limit if the vendor offers one.

**Docker Engine inside WSL (homelab):** install from Docker's official apt repo, `systemd=true` in `/etc/wsl.conf`, and a Windows scheduled task at startup that runs `wsl.exe -d Ubuntu-24.04 --exec /bin/sh -c "sleep infinity"` as your user with **S4U** (runs with nobody logged in, stores no password). That starts Ubuntu at boot; systemd starts Docker; Docker restarts the containers. Reboot-test it with nobody signed in.

## Part B: Clone outside OneDrive, with LF line endings

```bash
git clone -c core.autocrlf=false --depth 1 --branch v4.14.8 https://github.com/wazuh/wazuh-docker.git
cd wazuh-docker/single-node
```

CRLF line endings break the shell scripts inside the containers, and a synced folder fights with Docker's file locks.

## Part C: Certificates

```bash
docker compose -f generate-indexer-certs.yml run --rm generator
```

`line 636: find: command not found` at the end is harmless: it happens during cleanup, after all 12 certificates exist.

## Part D: Lock the ports, then the firewall, THEN start

Apply [wazuh/manager/docker-compose-changes.yml](../wazuh/manager/docker-compose-changes.yml): dashboard, indexer and API on `127.0.0.1` only, syslog removed, API host port moved to 15500. Validate with `docker compose config --quiet`.

Then allow TCP 1514 **only from Tailscale's ranges** (`100.64.0.0/10`, `fd7a:115c:a1e0::/48`) **before** the first start. The original guide I followed added the firewall after starting, which would have left the agent ports open to the whole Wi-Fi in between.

**Docker Desktop on Windows:** a "block private ranges" rule is not enough. Docker Desktop installs its own inbound rule allowing **any port from any address** on public networks. Block every address *except* Tailscale's; block rules beat allow rules:

```powershell
New-NetFirewallRule -DisplayName "Wazuh agent ports - block all except Tailscale" -Direction Inbound -Protocol TCP -LocalPort 1514,1515 `
  -RemoteAddress "0.0.0.0-100.63.255.255","100.128.0.0-255.255.255.255","::-fd7a:115c:a1df:ffff:ffff:ffff:ffff:ffff","fd7a:115c:a1e1::-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff" -Action Block
```

**Docker Engine in WSL (mirrored networking):** the **Hyper-V firewall** guards WSL, not Windows Firewall. Its default inbound action is Block, so one allow rule is enough:

```powershell
New-NetFirewallHyperVRule -Name "Wazuh-1514-Tailscale" -DisplayName "Wazuh 1514 from Tailscale" -Direction Inbound `
  -VMCreatorId '{40E0AC32-46A5-438A-A0B2-2B479E8F2E90}' -Protocol TCP -LocalPorts 1514 `
  -RemoteAddresses 100.64.0.0/10,fd7a:115c:a1e0::/48 -Action Allow
```

Don't bind 1514 to the Tailscale IP inside WSL. If Tailscale isn't up yet at boot, the bind fails and Docker won't start the manager.

## Part E: Start

```bash
docker compose pull
docker compose up -d
curl -sk -o /dev/null -w '%{http_code}\n' https://127.0.0.1/app/login   # 200
docker stats --no-stream                                                 # indexer ~1.6 GB, manager ~0.6 GB
```

## Part F: Change the default passwords

The official compose file ships default passwords for `admin`, `kibanaserver` and `wazuh-wui`. Change all three before any agent connects, using Wazuh's procedure: <https://documentation.wazuh.com/current/deployment-options/docker/changing-default-password.html>.

What I added on top of the official steps:

- **Hash with Wazuh's own tool, password passed through an environment variable**, never on a command line:
  ```powershell
  $env:WZ_PW = $plain
  docker run --rm -e WZ_PW wazuh/wazuh-indexer:4.14.8 bash /usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh -env WZ_PW
  ```
- **Character whitelist**: letters, digits and `! % * - _ = + . , ? : ~ @`. `$` triggers compose variable interpolation, `#` starts a YAML comment, and `& | ; ' " \` break shell scripts inside the containers. `wazuh-wui` also needs upper, lower, digit and symbol, 8-64 characters, or the manager won't start.
- **Lock the four unused demo users** (`kibanaro`, `logstash`, `readall`, `snapshotrestore`) with random passwords nobody knows.
- **Prove it both ways**: the new passwords work **and** the old defaults are rejected, for the indexer (`/_plugins/_security/authinfo`) and the API (`POST /security/user/authenticate`). Mine: 6/6.
- Run anything that prompts for a secret in a **standalone** terminal. An embedded IDE terminal exited silently at a hidden prompt for me.

`docker-compose.yml` and `wazuh.yml` still hold the passwords in plaintext (Wazuh's Docker deployment requires it). Restrict that folder to your user.

## Part G: Retention

Alerts grow about 1-3 MB/day with the tuning in this repo. I keep 15 days with an Index State Management policy on `wazuh-alerts-*` (Wazuh's documented "Index lifecycle management" JSON with `min_index_age: 15d`). **Screenshot anything you want to keep before it ages out.**

## Applying config changes later

The manager copies `config/wazuh_cluster/wazuh_manager.conf` into its volume **only when the container is created**. A restart keeps the old config:

```bash
docker compose up -d --force-recreate --no-deps wazuh.manager     # config changes
docker compose restart wazuh.manager                               # rule file changes only
```

After any restart, check the daemons, not just "container Up": `docker exec single-node-wazuh.manager-1 /var/ossec/bin/wazuh-control status`.
