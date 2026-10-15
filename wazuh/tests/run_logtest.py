#!/var/ossec/framework/python/bin/python3
"""Replay wazuh/tests/cases.json through wazuh-logtest and check which rule wins.

Runs INSIDE the Wazuh manager container (it talks to the logtest Unix socket):
    docker cp wazuh/tests/. <manager>:/tmp/home-soc-tests/
    docker exec <manager> /var/ossec/framework/python/bin/python3 /tmp/home-soc-tests/run_logtest.py

Exit code 0 = every case matched, 1 = at least one mismatch.
The socket protocol is the one the Wazuh API uses: a 4-byte little-endian length, then a JSON message.
"""
import json
import socket
import struct
import sys
from pathlib import Path

SOCK = "/var/ossec/queue/sockets/logtest"


def _recv_exact(s, n):
    buf = b""
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("logtest socket closed early")
        buf += chunk
    return buf


def logtest(event, log_format, location, token=None):
    params = {"event": event, "log_format": log_format, "location": location}
    if token:
        params["token"] = token
    msg = json.dumps({
        "version": 1,
        "origin": {"name": "home-soc-tests", "module": "api"},
        "command": "log_processing",
        "parameters": params,
    }).encode()
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.connect(SOCK)
        s.sendall(struct.pack("<I", len(msg)) + msg)
        size = struct.unpack("<I", _recv_exact(s, 4))[0]
        return json.loads(_recv_exact(s, size))


def main():
    cases = json.loads((Path(__file__).parent / "cases.json").read_text())["cases"]
    tokens = {}
    failed = 0
    for c in cases:
        session = c.get("session")
        reply = logtest(c["event"], c["log_format"], c["location"], tokens.get(session))
        if reply.get("error"):
            print(f"ERROR {c['name']}: {reply.get('message')}")
            failed += 1
            continue
        data = reply["data"]
        if session:
            tokens[session] = data.get("token")
        rule = data.get("output", {}).get("rule", {})
        got, level = str(rule.get("id", "none")), rule.get("level", "-")
        ok = got == c["expect"]
        failed += not ok
        print(f"{'PASS' if ok else 'FAIL'}  {c['name']:<58} expected {c['expect']:<7} got {got} (level {level})")
    total = len(cases)
    print(f"\n{total - failed}/{total} passed")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
