#!/bin/bash
# wazuh-watcher.sh - "who watches the watcher": health check for a Docker-based Wazuh stack (docs/07-watcher-and-migration.md).
# Every Wazuh alert comes FROM Wazuh, so when Wazuh itself dies, nothing pages you. This runs outside Wazuh.
# Runs every 5 min from wazuh-watcher.timer. Discord (the Slack-compatible hook already in the manager config):
#   DOWN after 2 failed runs in a row, STILL DOWN every 2 h, RECOVERED when healthy again.
# Optional dead-man's switch: pushes up/down to an Uptime Kuma push monitor on ANOTHER machine, so the
# whole Wazuh host going offline is noticed too.
# Mute for planned work:  touch ~/wazuh/watcher/PAUSE   (remove it afterwards)
# Manual:  wazuh-watcher.sh --test-message   |   --simulate-fail (counts as a failed run)
set -uo pipefail

# ---- EDIT THESE ----
AGENTS=("001:webserver" "002:dnsserver")           # ID:name of every agent that must be Active
KUMA_URL=${KUMA_URL:-}                             # optional, e.g. http://<KUMA_HOST_TS_IP>:3001/ (tailnet only)
CONF=$HOME/wazuh/wazuh-docker/single-node/config/wazuh_cluster/wazuh_manager.conf
COMPOSE_DIR=$HOME/wazuh/wazuh-docker/single-node
# --------------------

DIR=$HOME/wazuh/watcher; mkdir -p "$DIR"; chmod 700 "$DIR"
STATE=$DIR/state; LOG=$DIR/watcher.log
PUSH_FILE=$DIR/kuma-push-url               # Kuma push URL (mode 600, never printed)
M=single-node-wazuh.manager-1
NOW=$(date +%s); TS=$(date '+%F %T %Z')
STALL_LIMIT=900            # events counter frozen this long = problem (s)
REMIND=7200                # STILL DOWN reminder interval (s)
HEAL_EVERY=3600            # auto-heal at most once per hour

log() { echo "$TS $*" >> "$LOG"; tail -n 3000 "$LOG" > "$LOG.tmp" && mv "$LOG.tmp" "$LOG"; }

# Send to Discord without ever printing the hook or putting it on a command line (curl reads it from stdin).
notify() {
  local hook body code
  hook=$(grep -oP '(?<=<hook_url>)[^<]+' "$CONF" 2>/dev/null | head -n 1)
  [ -z "$hook" ] && { log "NOTIFY FAILED: no hook_url in config"; return 1; }
  body=$(python3 -c 'import json,sys; print(json.dumps({"text": sys.argv[1]}))' "$1")
  code=$(printf 'url = "%s"\n' "$hook" | curl -s -o /dev/null -w '%{http_code}' --max-time 15 \
         -H 'Content-Type: application/json' -d "$body" --config -)
  log "notify -> HTTP $code"
}

# Dead-man's switch: tell Uptime Kuma we're alive (up) or what's wrong (down). URL from a 600 file, fed to curl on stdin.
push() {
  local base msg code
  [ -s "$PUSH_FILE" ] || return 0
  base=$(head -n 1 "$PUSH_FILE"); base=${base%%\?*}
  msg=$(python3 -c 'import sys, urllib.parse; print(urllib.parse.quote(sys.argv[1][:200]))' "$2")
  code=$(printf 'url = "%s?status=%s&msg=%s&ping="\n' "$base" "$1" "$msg" | curl -s -o /dev/null -w '%{http_code}' --max-time 15 --config -)
  [ "$code" = "200" ] || log "push $1 -> HTTP $code"
}

# state: fails down_since last_alert last_ev ev_changed_at last_heal
fails=0; down_since=0; last_alert=0; last_ev=-1; ev_changed=$NOW; last_heal=0
[ -f "$STATE" ] && read -r fails down_since last_alert last_ev ev_changed last_heal < "$STATE"
last_heal=${last_heal:-0}
mgr_dead=0

if [ "${1:-}" = "--test-message" ]; then
  notify "🟢 Wazuh watcher online on $(hostname). Test message, no action needed."; exit 0
fi
[ -f "$DIR/PAUSE" ] && { log "paused (PAUSE file present)"; exit 0; }

problems=()
[ "${1:-}" = "--simulate-fail" ] && problems+=("SIMULATED failure (watcher test)")
systemctl is-active -q docker || problems+=("docker service not active")
for c in single-node-wazuh.manager-1 single-node-wazuh.indexer-1 single-node-wazuh.dashboard-1; do
  [ "$(docker inspect -f '{{.State.Running}}' "$c" 2>/dev/null)" = "true" ] || problems+=("container $c not running")
done
if [ "$(docker inspect -f '{{.State.Running}}' "$M" 2>/dev/null)" = "true" ]; then
  st=$(docker exec "$M" /var/ossec/bin/wazuh-control status 2>/dev/null)
  # container up but NO daemon running = the known startup failure (cont-init exited 1 / apid Killed)
  [ "$(grep -c ' is running' <<<"$st")" -eq 0 ] && mgr_dead=1
  for d in wazuh-modulesd wazuh-monitord wazuh-logcollector wazuh-remoted wazuh-syscheckd wazuh-analysisd \
           wazuh-execd wazuh-db wazuh-authd wazuh-integratord wazuh-apid; do
    grep -q "^$d is running" <<<"$st" || problems+=("$d not running")
  done
  ag=$(docker exec "$M" /var/ossec/bin/agent_control -l 2>/dev/null)
  for a in "${AGENTS[@]}"; do
    id=${a%%:*}; name=${a#*:}
    grep -qE "ID: $id, Name: $name,.*Active$" <<<"$ag" || problems+=("agent $id $name not Active")
  done
  # The decoded-events counter moves constantly (~1/s). "No new alert for X min" would false-alarm:
  # quiet gaps between real alerts reached 71 min in my data.
  ev=$(docker exec "$M" grep -oP "(?<=^total_events_decoded=')[0-9]+" /var/ossec/var/run/wazuh-analysisd.state 2>/dev/null)
  if [ -n "$ev" ]; then
    if [ "$ev" != "$last_ev" ]; then last_ev=$ev; ev_changed=$NOW
    elif [ $((NOW - ev_changed)) -ge $STALL_LIMIT ]; then problems+=("no events decoded for $(( (NOW - ev_changed) / 60 )) min (stuck at $ev)"); fi
  else problems+=("cannot read analysisd event counter"); fi
  docker exec "$M" filebeat test output 2>/dev/null | grep -q 'talk to server... OK' || problems+=("filebeat cannot talk to the indexer")
fi
code=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 15 https://127.0.0.1:443/app/login)
[ "$code" = "200" ] || problems+=("dashboard HTTP $code")
if [ -n "$KUMA_URL" ]; then
  kcode=$(curl -s -o /dev/null -w '%{http_code}' --max-time 15 "$KUMA_URL")
  case "$kcode" in 200|301|302) ;; *) problems+=("Uptime Kuma unreachable (HTTP $kcode): its host may be down") ;; esac
fi

if [ ${#problems[@]} -eq 0 ]; then
  if [ "$fails" -ge 2 ]; then
    notify "✅ RECOVERED: Wazuh on $(hostname) is healthy again (down $(( (NOW - down_since) / 60 )) min)."
  fi
  log "OK (events $last_ev)"; fails=0; down_since=0
  push up "OK"
else
  fails=$((fails + 1)); [ "$down_since" -eq 0 ] && down_since=$NOW
  list=$(printf -- '- %s\n' "${problems[@]}")
  push down "$(IFS='; '; echo "${problems[*]}")"
  log "FAIL #$fails: $(IFS='; '; echo "${problems[*]}")"
  if [ "$fails" -eq 2 ]; then
    notify "🔴 DOWN: Wazuh watcher on $(hostname) failed 2 checks in a row.
$list
Check: docker compose ps in $COMPOSE_DIR"; last_alert=$NOW
  elif [ "$fails" -gt 2 ] && [ $((NOW - last_alert)) -ge $REMIND ]; then
    notify "🔴 STILL DOWN for $(( (NOW - down_since) / 60 )) min: Wazuh on $(hostname).
$list"; last_alert=$NOW
  fi
  # AUTO-HEAL: manager container up but every daemon dead for 2+ runs -> restart it once (max 1/hour)
  if [ "$mgr_dead" -eq 1 ] && [ "$fails" -ge 2 ] && [ $((NOW - last_heal)) -ge $HEAL_EVERY ]; then
    last_heal=$NOW
    log "AUTO-HEAL: restarting wazuh.manager (0 daemons running)"
    notify "🔧 AUTO-HEAL: all Wazuh daemons were dead inside a running manager container (known startup failure). Restarting the manager once now; RECOVERED should follow within ~5 min. If not, fix by hand."
    ( cd "$COMPOSE_DIR" && docker compose restart wazuh.manager >> "$LOG" 2>&1 )
    log "AUTO-HEAL: restart command finished (exit $?)"
  fi
fi
echo "$fails $down_since $last_alert $last_ev $ev_changed $last_heal" > "$STATE"
