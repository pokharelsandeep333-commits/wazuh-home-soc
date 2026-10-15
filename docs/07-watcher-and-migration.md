# 7. Who watches the watcher, and moving the SIEM

## The watcher

Every Discord alert comes **from** Wazuh. When the manager died on my second day (container "Up", every daemon dead, about 6 minutes), nothing told me. The check has to run outside Wazuh.

[scripts/manager/wazuh-watcher.sh](../scripts/manager/wazuh-watcher.sh) runs every 5 minutes from a systemd timer ([service](../scripts/manager/wazuh-watcher.service), [timer](../scripts/manager/wazuh-watcher.timer)):

| Check | Fails when |
|---|---|
| Docker service | not active |
| 3 containers | manager, indexer or dashboard not running |
| 11 manager daemons (`wazuh-control status`) | any one not running |
| Agents (`agent_control -l`) | any listed agent not Active |
| Decoded-events counter | hasn't moved in 15 minutes |
| `filebeat test output` | manager can't reach the indexer, so alerts aren't stored |
| Dashboard | not HTTP 200 |

Why the event counter and not "time since the last alert": quiet gaps between real alerts reached 71 minutes in my data, so an alert-age check would page falsely. The decoded-events counter moves about once a second.

Alert logic, to avoid noise:

- **DOWN** only after 2 failed runs in a row (~10 min), so a normal 1-2 minute manager restart doesn't page.
- **STILL DOWN** every 2 hours while broken, **RECOVERED** with the outage length.
- **AUTO-HEAL**: if the manager container is running but zero daemons are up for 2 runs, restart it once (at most once an hour). That's the known startup race below.
- Mute for maintenance: `touch ~/wazuh/watcher/PAUSE`, and remove it afterwards.
- The webhook is read from `wazuh_manager.conf` at runtime and handed to curl on **stdin**, so it never appears in a command line, a log or a second file.

Tested with `--test-message`, then two `--simulate-fail` runs (DOWN), then a normal run (RECOVERED).

### Its first real catch

After a Docker restart on my Windows host, both agents showed Disconnected although every daemon was running. Windows (WinNAT) had reserved TCP 54965-55064, and the API host port 55000 fell inside it. When one host port fails to bind, Docker publishes **none** of that container's ports, so 1514 vanished too (`docker inspect` showed `"1514/tcp":[]`). The watcher's agent check caught what "container Up + daemons running" missed. Fix: API on host port 15500, below Windows' dynamic range (49152-65535).

## Dead-man's switch for the whole host

The watcher runs on the Wazuh host, so it can't report that host going offline. I run **Uptime Kuma** on one of the servers (bound to `127.0.0.1`, exposed only on the tailnet with `tailscale serve --bg --tcp=3001 tcp://localhost:3001`). It has a **Push** monitor that expects a check-in every 5 minutes; the watcher pushes `up` or `down` on every run. If pushes stop, Kuma alerts Discord. The watcher in turn checks that Kuma answers, so the two machines watch each other. Kuma also monitors the websites and certificate expiry.

Proof it works: the push monitor existed for 29 minutes before I wired the watcher to it. Kuma reported it offline, then "is up!" the moment the first push arrived.

What's still uncovered: both machines down at once. An external service like Healthchecks.io would cover that.

## Moving the SIEM to new hardware

My first host was my daily laptop: it slept, rebooted for updates, and was nearly out of disk. I moved everything to an always-on box. Moving the volumes beats reinstalling, because the agent keys travel with them.

1. On the old host: `docker compose stop` (stop, don't delete: that's your rollback).
2. Export all 14 volumes: `docker run --rm -v <volume>:/v -v "$PWD":/out alpine tar czf /out/<volume>.tgz -C /v .` for each one, plus the `single-node/` config, custom rules and the AWS credentials file. Write a `SHA256SUMS`, copy over Tailscale, verify on arrival. Mine compressed to about 11.5 MB.
3. On the new host: clone wazuh-docker at the same tag, overlay the config, `docker compose pull && docker compose create` (don't start), then per volume clear it and `tar xzf` the archive into it. Ownership is preserved (`client.keys` 0:999, rules 999:999, indexer data 1000:1000).
4. Firewall rule for 1514 from Tailscale only ([02-wazuh-deploy.md](02-wazuh-deploy.md), part D), then `docker compose up -d`.
5. Tailscale policy: add a grant and tests for the new host.
6. Re-point each agent: [scripts/server/agent-repoint.sh](../scripts/server/agent-repoint.sh) changes `<address>` and restarts. **No re-enrollment.** The agents buffer events while the manager is away.
7. End-to-end test: probes → 100212 → Discord, CloudTrail fetch, Docker listener.
8. **Delete the migration bundles on both machines**: they contain passwords, certificate keys, the webhook and the AWS key.
9. Remove the old host from the Tailscale policy, verify the servers can no longer reach it, then retire the old copy.

My downtime was about 12 minutes, with nothing lost.
