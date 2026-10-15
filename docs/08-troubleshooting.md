# 8. Troubleshooting: what broke and how I fixed it

Every entry happened on my build. Symptom first, so you can search for what you're seeing.

## Disk and memory

**1. Docker filled the disk on first start.** Dashboard came up, then *"Docker Desktop is unable to start"*, C: at 0.01 GB free.
Cause: WSL had no memory cap and took 13 GB of RAM; Windows grew the pagefile by 7 GB to back it. The Wazuh images also take 9-12 GB on disk, not ~6, because Docker's containerd image store keeps both compressed layers and the unpacked copy.
Fix: `wsl --shutdown`, then cap memory in `.wslconfig` ([02-wazuh-deploy.md](02-wazuh-deploy.md), part A). On Windows, RAM use can become disk use through the pagefile.

**2. Indexer crash loop: `read past EOF ... opensearch.keystore`.**
Cause: the disk-full crash cut the keystore off mid-write. It lives in the container layer, not the data volume.
Fix: `docker compose down` (keeps volumes) and `docker compose up -d`. Fresh containers, fresh keystore.

**3. Vulnerability detection ate about 4.4 GB a minute.**
Measured with a baseline, a sample every minute and a stop condition: 19 GB in 5 minutes, a third unpacked. It needs 30+ GB of temporary space.
Fix: disable it until the host has room. With 164 GB free, the feed loaded in 14 minutes and settled at about 19 GB.

**4. Deleting data in Docker didn't free disk on Windows.** `docker_data.vhdx` stayed at 28 GB.
Cause: the VHDX grows but never shrinks on its own.
Fix: TRIM first, then compact. Without TRIM, compact can't see the free blocks.
```powershell
docker compose down
docker run --rm --privileged --pid=host alpine nsenter -t 1 -m -- fstrim -av
# quit Docker Desktop, then:
wsl --shutdown
# Administrator PowerShell, Docker closed: diskpart -> select vdisk file="<path>\docker_data.vhdx" -> attach vdisk readonly -> compact vdisk -> detach vdisk
```
Result: 28.3 → 8.95 GB.

**5. Docker Desktop has no disk-size limit on the WSL2 backend.** The settings page says resource limits are managed by Windows; `.wslconfig` caps only memory, CPU and swap. Check free space every session, or run a watchdog that stops the manager below a threshold.

## Config and startup

**6. Config edits didn't apply after `docker compose restart`.**
Cause: the manager copies `wazuh_manager.conf` into its volume only when the container is **created**.
Fix: `docker compose up -d --force-recreate --no-deps wazuh.manager`.

**7. Container "Up", but every Wazuh daemon dead.** Log: `wazuh-apid ... Killed`, then `[cont-init.d] 2-manager: exited 1`. Agents show Unknown/Disconnected. It hit me twice: once after a restart, once on the first boot of the new host, where Ubuntu, Docker and three Wazuh containers all start at once on a 2-core CPU.
Fix: restart the manager once more. The watcher now does that automatically ([07](07-watcher-and-migration.md)). Always check `wazuh-control status`, not just container status. When reading the container log, filter out your own `agent_control` polling noise first.

**8. Agents Disconnected though all daemons run.** `docker inspect` shows `"1514/tcp":[]`.
Cause: Windows reserved a port range that includes one of the container's host ports (`netsh int ipv4 show excludedportrange protocol=tcp`). One failed bind means Docker publishes none of the container's ports.
Fix: keep host ports below 49152.

**9. The password script exited silently** at the last hidden prompt, in an IDE's embedded terminal.
Fix: run anything that prompts for a secret in a standalone terminal. Add an error trap that prints the line number and reason, never the input.

**10. `find: command not found` while generating certificates.** Harmless: it happens in cleanup, after all certificates exist.

## Network

**11. Docker's firewall rule bypassed mine.** My block rule covered private ranges only. Docker Desktop installs an inbound rule allowing any port from any address on public networks, so on a network where peers have non-private addresses, a stranger could have reached 1515 and registered a fake agent.
Fix: block every address except Tailscale's, and close 1515 after enrollment ([02](02-wazuh-deploy.md), part D). Check what other software already allows before trusting your own rule.

**12. `tailnet policy does not permit you to SSH to this node`.** The default SSH rule's `autogroup:self` doesn't cover tagged servers. Add a rule from your login to `tag:server` ([01](01-tailscale.md), step 4).

## Detections

**13. Rule never fires though the regex is right.** For web rules: a 2xx/3xx lands on 31108, 4xx on 31101, 5xx on 31120. Hang the rule off all of them, not just 31100.

**14. Expected rule ID missing after an attack test.** Correlation rules can replace the base rule (40501 replaces 5902 "new user added"). Search by event, not by the ID you expect.

**15. Docker test exec not seen.** The listener waits 60 s after an agent restart before it listens. Test after that.

**16. CloudTrail alerts missing in the dashboard.** They belong to agent 000. Unpin any agent filter.

**17. Discord silent though Wazuh says "sent".** See [06-discord-alerts.md](06-discord-alerts.md): `{"ts": null}`.

## Scripting over SSH

**18. A piped remote script stopped halfway with no error.** Under `ssh host 'bash -s' < script.sh`, stdin **is** the script. Any command that reads stdin (`ausearch`, `ssh`, `read`, some `docker` commands) eats the rest of it. Give those commands `< /dev/null`; for ausearch use `--input-logs`.

**19. A safety check passed when it should have failed.** `cmd | grep -q error` under `set -o pipefail`: `grep -q` exits on the first match, the writer gets SIGPIPE, and the pipeline returns 141. Capture first, then grep: `OUT=$(cmd 2>&1); grep -q error <<< "$OUT"`.

**20. Remote quoting broke** through PowerShell → ssh → remote shell. Write the script to a file and pipe it, or use `powershell -EncodedCommand` for a Windows target.

**21. Git Bash turned `/var/ossec/...` into `C:/Program Files/Git/var/ossec/...`** in `docker exec`. Prefix the command with `MSYS_NO_PATHCONV=1`.

**22. `$'\r': command not found` after a script piped from PowerShell.** PowerShell appended a CRLF. Harmless if it appears after the last command; save scripts with LF endings.

**23. A "wait until SSH answers" loop passed before the reboot even started.** Wait until `uptime -s` is later than the reboot time.
