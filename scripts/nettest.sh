#!/usr/bin/env bash
# Reachability check from inside the claude-desktop sandbox. Needs only python3 and /proc.
# Usage: nettest.sh [HOST:PORT...]
#   Each HOST:PORT must be unreachable: host-only services, the host's own IPs, VPN and container networks.
#   127.0.0.1 stands for the host's loopback here, so pick a port something listens on outside the sandbox.
set -euo pipefail
echo "netns: $(readlink /proc/self/ns/net)"
echo "--- interfaces (v6)"
cat /proc/net/if_inet6
echo "--- routes (v4, hex)"
cat /proc/net/route
echo "--- resolv.conf"
cat /etc/resolv.conf
echo "abstract sockets: $(awk '$8 ~ /^@/' /proc/net/unix | wc -l)"
python3 - "$@" <<'PY'
import socket, sys
def t(name, host, port, family=socket.AF_UNSPEC):
    try:
        info = socket.getaddrinfo(host, port, family, socket.SOCK_STREAM)[0]
        s = socket.socket(info[0], socket.SOCK_STREAM); s.settimeout(3)
        s.connect(info[4]); s.close(); print(f"OPEN    {name} {host}:{port}"); return True
    except Exception as e:
        print(f"blocked {name} {host}:{port} ({type(e).__name__}: {e})"); return False
bad = 0
print("--- must be blocked")
for target in sys.argv[1:]:
    host, port = target.rsplit(":", 1)
    bad += t("host-only", host.strip("[]"), int(port))
print("--- must be open")
bad += not t("internet-v4", "api.anthropic.com", 443, socket.AF_INET)
bad += not t("github", "github.com", 443)
print("--- informational")
t("internet-v6", "api.anthropic.com", 443, socket.AF_INET6)
sys.exit(1 if bad else 0)
PY
