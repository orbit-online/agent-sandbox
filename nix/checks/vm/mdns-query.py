# mdns-query FAMILY MODE NAME SECONDS [IFACE [PORT]]: an mDNS querier on port 5353 (or PORT, 0 for any) of IFACE
# (eth0), as avahi is one. MODE query asks for the A
# (FAMILY 4) or AAAA (6) records of NAME with the unicast-response bit set, respond sends a response claiming NAME,
# probe a probe for it, listen only listens. Then, for SECONDS, prints the addresses in each response it gets and
# "query" for each query from elsewhere
import select
import socket
import struct
import sys
import time

fam, mode, name, seconds = sys.argv[1], sys.argv[2], sys.argv[3], float(sys.argv[4])
iface, port = (sys.argv[5:] + ["eth0", "5353"][len(sys.argv[5:]):])[:2]
port = int(port)
v6 = fam == "6"
idx = socket.if_nametoindex(iface)
s = socket.socket(socket.AF_INET6 if v6 else socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
if v6:
    group = "ff02::fb"
    s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    s.bind(("::", port))
    mreq = socket.inet_pton(socket.AF_INET6, group) + struct.pack("@I", idx)
    s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, mreq)
    s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, idx)
    s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, 255)
    dest = (group, 5353, 0, idx)
else:
    group = "224.0.0.251"
    s.bind(("", port))
    mreqn = socket.inet_aton(group) + socket.inet_aton("0.0.0.0") + struct.pack("@i", idx)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreqn)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, mreqn)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
    dest = (group, 5353)
s.setsockopt(socket.IPPROTO_IPV6 if v6 else socket.IPPROTO_IP,
             socket.IPV6_MULTICAST_LOOP if v6 else socket.IP_MULTICAST_LOOP, 0)

qname = b"".join(bytes([len(x)]) + x.encode() for x in name.split(".")) + b"\0"
qtype = 28 if v6 else 1
rdata = socket.inet_pton(socket.AF_INET6 if v6 else socket.AF_INET, "fd00::1" if v6 else "10.9.9.9")
record = qname + struct.pack("!HHIH", qtype, 0x8001, 120, len(rdata)) + rdata
if mode == "query":
    s.sendto(struct.pack("!6H", 0, 0, 1, 0, 0, 0) + qname + struct.pack("!HH", qtype, 0x8001), dest)
elif mode == "respond":
    s.sendto(struct.pack("!6H", 0, 0x8400, 0, 1, 0, 0) + record, dest)
elif mode == "probe":
    s.sendto(struct.pack("!6H", 0, 0, 1, 0, 1, 0) + qname + struct.pack("!HH", 255, 0x8001) + record, dest)


def skip_name(b, i):
    while b[i]:
        if b[i] >= 0xC0:
            return i + 2
        i += b[i] + 1
    return i + 1


end = time.monotonic() + seconds
while (left := end - time.monotonic()) > 0:
    if not select.select([s], [], [], left)[0]:
        break
    b = s.recv(9000)
    flags, qd, an, ns, ar = struct.unpack("!2x5H", b[:12])
    if not flags & 0x8000:
        print("query", flush=True)
        continue
    i = 12
    for _ in range(qd):
        i = skip_name(b, i) + 4
    for _ in range(an + ns + ar):
        i = skip_name(b, i)
        t, _, _, n = struct.unpack("!HHIH", b[i:i + 10])
        i += 10
        if t in (1, 28):
            print(socket.inet_ntop(socket.AF_INET if t == 1 else socket.AF_INET6, b[i:i + n]), flush=True)
        i += n
