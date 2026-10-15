#!/usr/bin/env bash
# weblogs-docker-nginx.sh - send a Dockerized nginx's access log to Wazuh (docs/04-detections.md, "Web logs").
# Only needed when nginx runs in a container and logs to stdout. Host nginx is read by the agent by default.
#
# Run from your workstation:  ssh <server> 'bash -s' < scripts/server/weblogs-docker-nginx.sh
#
# What it changes (all backed up first, auto-rollback on failure):
#   1. nginx.conf          + one line: access_log /var/log/nginx-wazuh/access.log combined;  (stdout logging stays)
#   2. docker-compose.yml  + one volume on the nginx service: $LOGDIR:/var/log/nginx-wazuh
#   3. recreates ONLY the nginx container (a few seconds of downtime for all sites)
#   4. /etc/logrotate.d/$APP_NAME-nginx (daily, keep 14, copytruncate)
#   5. agent ossec.conf    + <localfile> apache format for that file, then restarts wazuh-agent
# The log lives OUTSIDE the app folder on purpose: if FIM watches that folder in real time,
# a log inside it would raise a file-change alert on every web request.
set -uo pipefail

# ---- EDIT THESE ----
APP_NAME=webapp                                   # used for the log folder and logrotate file name
APP_DIR=/home/ubuntu/webapp                       # folder with docker-compose.yml and nginx.conf
NGINX_CONTAINER=webapp_nginx_1                    # docker ps name of the nginx container
NGINX_SERVICE=nginx                               # compose service name
# An existing, unique line in the nginx service's volumes: list. The new volume is inserted after it.
ANCHOR='      - ./nginx.conf:/etc/nginx/nginx.conf:ro'
# --------------------

cd "$APP_DIR" || exit 1
LOGDIR=/var/log/$APP_NAME-nginx
B="pre-weblogs-$(date +%F)"
VOL="      - $LOGDIR:/var/log/nginx-wazuh"
OSSEC=/var/ossec/etc/ossec.conf

rollback() {
  echo "!! ROLLBACK: $1"
  sudo sh -c "cat '$B/nginx.conf' > nginx.conf"
  sudo sh -c "cat '$B/docker-compose.yml' > docker-compose.yml"
  sudo docker compose up -d --no-deps "$NGINX_SERVICE" >/dev/null 2>&1
  sudo docker ps --filter "name=$NGINX_CONTAINER" --format '{{.Names}} {{.Status}}'
  exit 1
}

# 0. Guards
[ "$(sudo grep -c -F -- "$ANCHOR" docker-compose.yml)" = "1" ] || { echo "anchor line not found exactly once"; exit 1; }
sudo grep -q 'nginx-wazuh' nginx.conf docker-compose.yml && { echo "already applied?"; exit 1; }

# 1. Backups (check first that these files hold no plaintext secrets: use ${VAR} references in compose)
sudo mkdir -p "$B" && sudo cp -p docker-compose.yml nginx.conf "$B/" && echo "backup: $B" || exit 1
INODE_BEFORE=$(stat -c %i nginx.conf)

# 2. Host log dir
sudo install -d -m 0750 -o root -g adm "$LOGDIR"

# 3. nginx.conf: second http-level access_log after line 1. Rewrite in place to keep the inode (a :ro bind
#    mount of a single file keeps pointing at the old inode if the file is replaced instead of rewritten).
T1=$(mktemp)
awk 'NR==1{print; print ""; print "# Copy of the access log for the Wazuh agent (rotated by logrotate on the host)."; print "access_log /var/log/nginx-wazuh/access.log combined;"; next} {print}' nginx.conf > "$T1"
sudo sh -c "cat '$T1' > nginx.conf"; unlink "$T1"
[ "$(stat -c %i nginx.conf)" = "$INODE_BEFORE" ] && echo "nginx.conf inode kept" || rollback "inode changed"

# 4. compose: add the log volume to the nginx service
T2=$(mktemp)
sudo awk -v a="$ANCHOR" -v v="$VOL" '{print} $0==a{print v}' docker-compose.yml > "$T2"
sudo sh -c "cat '$T2' > docker-compose.yml"; unlink "$T2"
sudo docker compose config -q && echo "compose config valid" || rollback "compose invalid"

# 5. Syntax test in the RUNNING container (the file is bind-mounted; nginx is not reloaded by this)
sudo docker exec "$NGINX_CONTAINER" mkdir -p /var/log/nginx-wazuh
sudo docker exec "$NGINX_CONTAINER" nginx -t 2>&1 | tail -n 2 | grep -q 'successful' && echo "nginx -t OK" || rollback "nginx -t failed"

# 6. Recreate nginx only
sudo docker compose up -d --no-deps "$NGINX_SERVICE" 2>&1 | tail -n 2
s=""
for i in $(seq 1 15); do
  s=$(sudo docker inspect -f '{{.State.Status}}' "$NGINX_CONTAINER" 2>/dev/null)
  [ "$s" = "running" ] && break; sleep 1
done
[ "$s" = "running" ] || rollback "nginx not running"

# 7. Verify the file is being written
curl -s -o /dev/null -w "local http: %{http_code}\n" http://127.0.0.1/ || true
sleep 2
echo "lines so far: $(sudo wc -l < "$LOGDIR/access.log")"

# 8. logrotate (copytruncate: nginx inside the container keeps its file handle)
sudo tee "/etc/logrotate.d/$APP_NAME-nginx" >/dev/null <<ROT
$LOGDIR/*.log {
    daily
    rotate 14
    missingok
    notifempty
    compress
    delaycompress
    copytruncate
}
ROT
OUT=$(sudo logrotate -d "/etc/logrotate.d/$APP_NAME-nginx" 2>&1)
grep -i -q "error" <<< "$OUT" && echo "!! logrotate dry run reported an error, check /etc/logrotate.d/$APP_NAME-nginx"

# 9. Wazuh agent: add the localfile in a separate <ossec_config> block (Wazuh merges them)
if sudo grep -q "$LOGDIR" "$OSSEC"; then
  echo "agent already has the localfile"
else
  sudo cp -p "$OSSEC" "$OSSEC.bak-pre-weblogs"
  sudo sh -c "cat >> '$OSSEC'" <<LF

<ossec_config>
  <!-- nginx access log from container $NGINX_CONTAINER (host bind mount) -->
  <localfile>
    <log_format>apache</log_format>
    <location>$LOGDIR/access.log</location>
  </localfile>
</ossec_config>
LF
  sudo systemctl restart wazuh-agent
  sleep 5
  systemctl is-active wazuh-agent
  sudo grep -E "$LOGDIR|ERROR" /var/ossec/logs/ossec.log | tail -n 3
fi
echo "DONE. Test: request a page that doesn't exist; rule 31101 should appear within seconds."
