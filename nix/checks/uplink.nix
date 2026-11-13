# The host side of the sandbox network (nix/nixos/network.nix): einat and sandbox-uplink from the NixOS module on a
# workstation whose LAN host is its default gateway, on one whose uplink NIC is enslaved to a bridge, and on one that
# boots without a NIC. The test script stands in for the per-launcher helper: a netkit pair whose primary forwards
# through the host stack (no `peer` program), its addresses registered with bpftool
{
  pkgs,
  module,
}:
let
  inherit (pkgs) lib;
  # Replies with the address it was reached from, so the sandbox sees what einat made of its own
  echo = family: {
    wantedBy = [ "multi-user.target" ];
    serviceConfig.ExecStart = "${lib.getExe pkgs.socat} UDP${family}-RECVFROM:7,fork${
      lib.optionalString (family == "6") ",ipv6only=1"
    } \"SYSTEM:echo $$SOCAT_PEERADDR $$SOCAT_PEERPORT\"";
  };
  tools = with pkgs; [
    bpftools
    curl
    iproute2
    socat
    tcpdump
  ];
  # Stand-ins for Cilium, cil_from_netdev and cil_to_netdev at the tail of tcx ingress and egress, ending the chain as
  # it does, and for another program at the head
  standIns =
    pkgs.runCommand "stand-ins.bpf.o" { nativeBuildInputs = [ pkgs.llvmPackages.clang-unwrapped ]; }
      ''
        cat >s.c <<'EOF'
        #include <linux/bpf.h>
        #include <linux/pkt_cls.h>
        #include <bpf/bpf_helpers.h>
        SEC("tc") int cil_from_netdev(struct __sk_buff *skb) { return TC_ACT_OK; }
        SEC("tc") int cil_to_netdev(struct __sk_buff *skb) { return TC_ACT_OK; }
        SEC("tc") int head(struct __sk_buff *skb) { return TCX_NEXT; }
        char LICENSE[] SEC("license") = "GPL";
        EOF
        clang -O2 -target bpf -I${lib.getDev pkgs.libbpf}/include -I${pkgs.linuxHeaders}/include -c s.c -o $out
      '';
  # Sends a UDP frame of 5000 bytes from src to dst on dev through AF_PACKET with a vnet header whose hdr_len is 0: past
  # a page, the kernel puts nothing but the Ethernet header in the linear part (af_packet.c packet_snd, packet_alloc_skb)
  nonlinear = pkgs.writeText "nonlinear.py" ''
    import socket, struct, sys
    dev, src, dst = sys.argv[1:]
    udp = struct.pack("!4H", 5555, 9, 5008, 0) + bytes(5000)
    if ":" in src:
        fam, proto = socket.AF_INET6, 0x86dd
        ip = struct.pack("!IHBB", 6 << 28, len(udp), 17, 64)
    else:
        fam, proto = socket.AF_INET, 0x0800
        ip = struct.pack("!BBHHHBBH", 0x45, 0, 20 + len(udp), 0, 0, 64, 17, 0)
    ip += socket.inet_pton(fam, src) + socket.inet_pton(fam, dst)
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    s.setsockopt(263, 15, 1)  # SOL_PACKET, PACKET_VNET_HDR
    s.bind((dev, 0))
    s.send(bytes(10) + bytes(12) + struct.pack("!H", proto) + ip + udp)
  '';
in
pkgs.testers.runNixOSTest {
  name = "uplink";
  nodes.lan = {
    networking.firewall.enable = false;
    environment.systemPackages = tools ++ [ (pkgs.python3.withPackages (p: [ p.scapy ])) ];
    systemd.services = {
      web = {
        wantedBy = [ "multi-user.target" ];
        serviceConfig.ExecStart = "${pkgs.python3}/bin/python3 -m http.server 80 --bind :: --directory /var/empty";
      };
      echo4 = echo "4";
      echo6 = echo "6";
    };
  };
  nodes.workstation =
    { nodes, ... }:
    {
      imports = [ module ];
      system.stateVersion = "26.05";
      agent-sandbox.network.enable = true;
      networking = {
        defaultGateway = nodes.lan.networking.primaryIPAddress;
        defaultGateway6 = nodes.lan.networking.primaryIPv6Address;
        nftables.enable = true;
      };
      environment.systemPackages = tools ++ [ pkgs.nftables ];
    };
  # Its uplink NIC enslaved to br0, which holds the address
  nodes.bridged =
    { nodes, ... }:
    {
      imports = [ module ];
      system.stateVersion = "26.05";
      agent-sandbox.network.enable = true;
      networking = {
        bridges.br0.interfaces = [ "eth1" ];
        interfaces.eth1.ipv4.addresses = lib.mkForce [ ];
        interfaces.eth1.ipv6.addresses = lib.mkForce [ ];
        interfaces.br0.ipv4.addresses = [
          {
            address = "192.168.1.200";
            prefixLength = 24;
          }
        ];
        defaultGateway = nodes.lan.networking.primaryIPAddress;
        firewall.enable = false;
      };
      environment.systemPackages = tools;
    };
  # No NIC at boot: one comes later, named up0 by a .link file
  nodes.late = {
    imports = [ module ];
    system.stateVersion = "26.05";
    agent-sandbox.network.enable = true;
    virtualisation.vlans = [ ];
    # QEMU adds a NIC of its own without one
    virtualisation.qemu.networkingOptions = lib.mkForce [ "-nic none" ];
    environment.etc."systemd/network/10-up0.link".text = ''
      [Match]
      MACAddress=52:54:00:12:99:01
      [Link]
      Name=up0
    '';
    environment.systemPackages = tools;
  };

  testScript =
    { nodes, ... }:
    let
      ws4 = nodes.workstation.networking.primaryIPAddress;
      ws6 = nodes.workstation.networking.primaryIPv6Address;
      lan4 = nodes.lan.networking.primaryIPAddress;
      lan6 = nodes.lan.networking.primaryIPv6Address;
    in
    ''
      import hashlib, hmac, ipaddress, json, re, struct, time

      ws = workstation
      ws4, ws6, lan4, lan6 = "${ws4}", "${ws6}", "${lan4}", "${lan6}"
      pins = "/run/sandbox-uplink"

      def sb(cmd):
          return f"ip netns exec sb {cmd}"

      # The programs on a tcx hook of dev, in order
      def order(dev, direction, node=ws):
          j = json.loads(node.succeed(f"bpftool -j net show dev {dev}"))
          return [p["name"] for p in j[0]["tc"] if p["kind"] == f"tcx/{direction}"]

      def in_order(dev, node=ws):
          return order(dev, "ingress", node) == ["pre", "ingress_rev_snat", "post"] and order(dev, "egress", node) == ["egress_snat", "egress"]

      def wait_in_order(dev, node=ws, check=in_order):
          try:
              retry(lambda _: check(dev, node), timeout_seconds=30)
          except Exception:
              print(node.execute(f"bpftool net show dev {dev}; findmnt -T {pins}; ls -la {pins}; journalctl -o cat -u sandbox-uplink | tail")[1])
              raise

      # tcpdump as a unit (with props, -p arguments of systemd-run), from when it has its filter attached, read back after
      def capture(node, filt, iface="eth1", unit="cap", props=""):
          node.succeed(f"systemd-run --unit={unit} -p StandardError=truncate:/tmp/{unit}.err {props}"
                       f" tcpdump -U -ni {iface} -w /tmp/{unit}.pcap '{filt}'")
          node.wait_until_succeeds(f"grep -q 'listening on' /tmp/{unit}.err", timeout=30)

      def captured(node, unit="cap"):
          time.sleep(1)
          node.succeed(f"systemctl stop {unit}")
          return node.succeed(f"tcpdump -nr /tmp/{unit}.pcap 2>/dev/null; rm /tmp/{unit}.pcap")

      # As a non-root user in the given group with CAP_BPF alone, as the per-launcher helper runs
      def as_helper(gid, cmd, caps="+bpf"):
          return f"setpriv --reuid=1500 --regid=1500 --groups={gid} --inh-caps={caps} --ambient-caps={caps} {cmd}"

      def hexbytes(b):
          return " ".join(f"{x:02x}" for x in b)

      # An address as the maps hold it: 16 bytes, IPv4 mapped
      def packed(a):
          a = ipaddress.ip_address(a)
          return ipaddress.IPv6Address(f"::ffff:{a}").packed if a.version == 4 else a.packed

      # A netkit pair standing in for the helper, sbx-t in the host netns and nkp in netns sb with the addresses,
      # forwarding through the host stack (no `peer` program); the ifindex of sbx-t
      def netkit_pair(node, *addrs):
          node.succeed("ip netns add sb", "ip link add sbx-t type netkit mode l3 peer name nkp",
                       "ip link set nkp netns sb", "ip link set sbx-t up", sb("ip link set lo up"))
          for a in addrs:
              f, bits, nodad = ("-6", 128, " nodad") if ":" in a else ("-4", 32, "")
              node.succeed(f"ip {f} route add {a}/{bits} dev sbx-t", sb(f"ip {f} addr add {a}/{bits} dev nkp{nodad}"))
          node.succeed(sb("ip link set nkp up"))
          for a in addrs:
              f, fam = ("-6", "ipv6") if ":" in a else ("-4", "ipv4")
              node.succeed(sb(f"ip {f} route add default dev nkp"), f"sysctl -w net.{fam}.conf.all.forwarding=1")
          return int(node.succeed("cat /sys/class/net/sbx-t/ifindex"))

      start_all()
      for n in [bridged, late]:
          n.wait_for_unit("multi-user.target")

      with subtest("no NIC at boot: einat skips, a NIC that comes brings it up, the same NIC again doesn't restart it"):
          late.wait_until_succeeds("journalctl -b -u sandbox-einat | grep -q exec-condition")
          assert late.succeed("systemctl show -P ActiveState sandbox-einat").strip() == "inactive"
          late.send_monitor_command("netdev_add user,id=hot")
          late.send_monitor_command("device_add virtio-net-pci,netdev=hot,id=hotnic,mac=52:54:00:12:99:01")
          late.wait_until_succeeds("grep -q 'if_name = \"up0\"' /run/sandbox-einat/einat.toml", timeout=30)
          late.succeed("ip link set up0 up")
          wait_in_order("up0", late)
          pid = late.succeed("systemctl show -P MainPID sandbox-einat").strip()
          runs = lambda: late.succeed("journalctl -o cat -u sandbox-einat-reload | grep -c '^Finished' || true").strip()
          late.wait_until_fails("systemctl -q is-active sandbox-einat-reload")
          before = int(runs())
          assert before >= 1, "udev didn't run the reload"
          late.succeed("udevadm trigger --action=add --settle /sys/class/net/up0")
          late.wait_until_succeeds(f"[ $(journalctl -o cat -u sandbox-einat-reload | grep -c '^Finished') -gt {before} ]", timeout=30)
          assert late.succeed("systemctl show -P MainPID sandbox-einat").strip() == pid, "einat restarted for an unchanged config"

      lan.wait_for_unit("multi-user.target")
      ws.wait_for_unit("multi-user.target")
      for u in ["web", "echo4", "echo6"]:
          lan.wait_for_unit(f"{u}.service")
      ws.wait_until_succeeds(f"ping -c1 -W1 {lan4} && ping -c1 -W1 {lan6}")
      ws.wait_for_unit("sandbox-einat.service")
      ws.wait_for_unit("sandbox-uplink.service")

      # The sandbox block, as internal/uplink derives it
      machine_id = bytes.fromhex(ws.succeed("cat /etc/machine-id").strip())
      gid = hmac.new(machine_id, bytes.fromhex("0840b57391704da6960f221fb40de13b"), hashlib.sha256).digest()[:5]
      block6 = ipaddress.IPv6Network((b"\xfd" + gid + bytes(10), 48))
      sb4, sb6 = "169.254.100.2", str(block6[2])

      with subtest("einat and sandbox-uplink run without root, with their capabilities alone"):
          for unit, caps in [("sandbox-einat", 0xc000001000), ("sandbox-uplink", 0x8000001000)]:
              pid = ws.succeed(f"systemctl show -P MainPID {unit}").strip()
              status = ws.succeed(f"cat /proc/{pid}/status")
              print(unit, re.findall(r"^(?:Uid|Cap(?:Prm|Eff|Amb|Bnd)):.*$", status, re.M))
              assert re.search(r"^Uid:\s+[1-9]", status, re.M), f"{unit} runs as root"
              for field in ["CapEff", "CapBnd"]:
                  m = re.search(rf"^{field}:\s+(\S+)", status, re.M)
                  assert m, status
                  got = int(m[1], 16)
                  assert got == caps, f"{unit} {field} {got:x}, want {caps:x}"

      with subtest("the einat config: the physical NICs, the sandbox blocks, the port range"):
          conf = ws.succeed("cat /run/sandbox-einat/einat.toml")
          print(conf)
          assert re.findall(r'if_name = "(.*)"', conf) == ["eth0", "eth1"], conf
          assert f'snat_internals = ["169.254.100.0/22", "{block6}"]' in conf, conf
          assert 'tcp_ranges = ["61000-63999"]' in conf and 'udp_ranges = ["61000-63999"]' in conf, conf

      with subtest("pre ahead of einat, post and egress after it, on every uplink"):
          for dev in ["eth0", "eth1"]:
              wait_in_order(dev)
          print(ws.succeed("bpftool net show", "ls -l /run/sandbox-uplink"))

      primary = netkit_pair(ws, sb4, sb6)
      group = ws.succeed("getent group sandbox-uplink | cut -d: -f3").strip()

      with subtest("the registration map: group sandbox-uplink writes it, nobody else"):
          print(ws.succeed("stat -c '%A %U %G %n' /run/sandbox-uplink /run/sandbox-uplink/*",
                           "sysctl kernel.unprivileged_bpf_disabled"))
          assert ws.succeed("stat -c '%a %U %G' /run/sandbox-uplink").split() == ["1770", "sandbox-uplink", "sandbox-uplink"]
          assert ws.succeed("stat -c '%a %G' /run/sandbox-uplink/sandboxes").split() == ["660", "sandbox-uplink"]
          for p in ["pre-eth1", "post-eth1", "egress-eth1"]:
              assert ws.succeed(f"stat -c '%a' /run/sandbox-uplink/{p}").strip() == "600"
          value = hexbytes(struct.pack("=I", primary))
          for addr in [sb4, sb6]:
              key = hexbytes(packed(addr))
              update = f"bpftool map update pinned {pins}/sandboxes key hex {key} value hex {value}"
              # The group alone opens it, and another group with the same (no) capabilities is refused:
              # unprivileged_bpf_disabled stops only creating objects, the modes of the directory and the pin decide who
              # opens one
              ws.fail(as_helper(100, update, caps="-all"))
              ws.succeed(as_helper(group, update, caps="-all"))
          print(ws.succeed(f"bpftool map dump pinned {pins}/sandboxes"))

      with subtest("the uplinks and gateways maps for the `peer` programs, and registrations of gone primaries removed"):
          def dump(m):
              return [{f: bytes(int(x, 16) for x in e[f]) for f in ["key", "value"]}
                      for e in json.loads(ws.succeed(f"bpftool -j map dump pinned {pins}/{m}"))]
          for m in ["uplinks", "gateways"]:
              assert ws.succeed(f"stat -c '%a %G' {pins}/{m}").split() == ["640", "sandbox-uplink"], m
          assert ws.succeed(f"stat -c '%a %G' {pins}/mdns").split() == ["660", "sandbox-uplink"]
          ifindex = {d: int(ws.succeed(f"cat /sys/class/net/{d}/ifindex")) for d in ["eth0", "eth1"]}
          ups = sorted(int.from_bytes(e["key"], "little") for e in dump("uplinks"))
          assert ups == sorted(ifindex.values()), ups
          # Per family the uplink with the default route of the lowest metric (on eth0 IPv6 has one from QEMU's
          # router advertisements), its gateway, and the source and MAC of mDNS queries: its first IPv4 address, its
          # IPv6 link-local one
          gws = {int.from_bytes(e["key"], "little"): e["value"] for e in dump("gateways")}
          for i, family in enumerate(["-4", "-6"]):
              routes = json.loads(ws.succeed(f"ip -j {family} route show default table main"))
              r = min(routes, key=lambda r: r.get("metric", 0))
              link = json.loads(ws.succeed(f"ip -j {family} addr show dev {r['dev']}"))[0]
              src = next(a["local"] for a in link["addr_info"] if family == "-4" or a["scope"] == "link")
              mac = bytes.fromhex(ws.succeed(f"cat /sys/class/net/{r['dev']}/address").strip().replace(":", ""))
              want = struct.pack("=I", ifindex[r["dev"]]) + packed(r["gateway"]) + packed(src) + mac + bytes(2)
              assert gws[i] == want, (routes, gws)
          # A gateways map of another shape, as an earlier sandbox-uplink pinned it, is replaced
          ws.succeed("systemctl stop sandbox-uplink", f"rm {pins}/gateways",
                     f"bpftool map create {pins}/gateways type array key 4 value 20 entries 2 name gateways",
                     f"chown sandbox-uplink:sandbox-uplink {pins}/gateways",
                     "systemctl start sandbox-uplink")
          assert json.loads(ws.succeed(f"bpftool -j map show pinned {pins}/gateways"))["bytes_value"] == 44
          # An uplink whose egress fails to attach (a map pinned where its link goes) isn't published
          def published(want):
              for _ in range(20):
                  ups = sorted(int.from_bytes(e["key"], "little") for e in dump("uplinks"))
                  if ups == sorted(ifindex[d] for d in want):
                      return
                  time.sleep(0.5)
              raise Exception(f"uplinks {ups}, want {want}")
          ws.succeed("systemctl stop sandbox-uplink", f"rm {pins}/egress-eth0",
                     f"bpftool map pin pinned {pins}/mdns {pins}/egress-eth0", "systemctl start sandbox-uplink")
          published(["eth1"])
          ws.succeed(f"rm {pins}/egress-eth0")
          published(["eth0", "eth1"])
          wait_in_order("eth0")
          gone = hexbytes(packed("169.254.103.1"))
          ws.succeed(f"bpftool map update pinned {pins}/sandboxes key hex {gone} value hex {hexbytes(struct.pack('=I', 99999))}")
          ws.wait_until_fails(f"bpftool map lookup pinned {pins}/sandboxes key hex {gone}", timeout=10)
          ws.succeed(f"bpftool map lookup pinned {pins}/sandboxes key hex {hexbytes(packed(sb6))}")
          # An mdns entry whose ifindex isn't a primary (any more) is removed
          eth0 = hexbytes(struct.pack("=I", ifindex["eth0"]))
          ws.succeed(f"bpftool map update pinned {pins}/mdns key hex {eth0} value hex 01")
          ws.wait_until_fails(f"bpftool map lookup pinned {pins}/mdns key hex {eth0}", timeout=10)

      with subtest("sandbox egress over IPv4 and IPv6, SNATed by einat to the uplink address, in the port range"):
          for dst, ext in [(lan4, ws4), (f"[{lan6}]", ws6)]:
              fam = "6" if ":" in dst else "4"
              out = ws.succeed(sb(f"sh -c 'echo x | socat -T3 - UDP{fam}:{dst}:7'")).split()
              print(f"UDP{fam}: the LAN saw {out}")
              assert ipaddress.ip_address(out[0].strip("[]")) == ipaddress.ip_address(ext), out
              assert 61000 <= int(out[1]) <= 63999, out
              ws.succeed(sb(f"curl -sf -m5 http://{dst}/ -o /dev/null"))

      with subtest("replies reach the sandbox through post, not the host stack"):
          ws.succeed("nft add table inet t",
                     "nft 'add chain inet t f { type filter hook forward priority 0; }'",
                     "nft add rule inet t f ip daddr 169.254.100.0/22 drop",
                     f"nft add rule inet t f ip6 daddr {block6} drop")
          for dst in [lan4, f"[{lan6}]"]:
              ws.succeed(sb(f"curl -sf -m5 http://{dst}/ -o /dev/null"))
          # Control: without post, the host stack would have to forward them
          ws.succeed("systemctl stop sandbox-uplink", f"rm {pins}/post-eth1")
          for dst in [lan4, f"[{lan6}]"]:
              ws.fail(sb(f"curl -sf -m3 http://{dst}/ -o /dev/null"))
          ws.succeed("systemctl start sandbox-uplink")
          wait_in_order("eth1")
          ws.succeed(sb(f"curl -sf -m5 http://{lan4}/ -o /dev/null"))
          ws.succeed("nft delete table inet t")

      lan.succeed(f"ip route add {sb4}/32 via {ws4}", f"ip -6 route add {sb6}/128 via {ws6}")
      mac = ws.succeed("cat /sys/class/net/eth1/address").strip()
      inject = (f"python3 -c \"from scapy.all import *; sendp([Ether(dst='{mac}')/IP(dst='{sb4}')/UDP(dport=9999)/b'x', "
                f"Ether(dst='{mac}')/IPv6(dst='{sb6}')/UDP(dport=9999)/b'x'], iface='eth1')\"")

      with subtest("the LAN can't send from a sandbox address: pre drops it before the host stack"):
          ws.succeed("nft add table inet spoof",
                     "nft 'add chain inet spoof pre { type filter hook prerouting priority -400; }'",
                     f"nft add rule inet spoof pre iifname eth1 ip saddr {sb4} counter",
                     f"nft add rule inet spoof pre iifname eth1 ip6 saddr {sb6} counter")
          spoof = (f"python3 -c \"from scapy.all import *; sendp([Ether(dst='{mac}')/IP(src='{sb4}', dst='{ws4}')/ICMP(), "
                   f"Ether(dst='{mac}')/IPv6(src='{sb6}', dst='{ws6}')/ICMPv6EchoRequest()], iface='eth1')\"")
          def spoofed():
              lan.succeed(spoof)
              time.sleep(1)
              return re.findall(r"packets (\d+)", ws.succeed("nft list chain inet spoof pre"))
          assert spoofed() == ["0", "0"], ws.succeed("nft list chain inet spoof pre")
          # Control: without pre, the host stack gets them
          ws.succeed("systemctl stop sandbox-uplink", f"rm {pins}/pre-eth1")
          assert spoofed() == ["1", "1"], ws.succeed("nft list chain inet spoof pre")
          ws.succeed("systemctl start sandbox-uplink", "nft delete table inet spoof")
          wait_in_order("eth1")

      def lan_reaches_sandbox():
          capture(ws, "udp port 9999", iface="nkp", unit="sbcap", props="-p NetworkNamespacePath=/run/netns/sb")
          lan.succeed(inject)
          out = captured(ws, "sbcap")
          print("in the sandbox:", out)
          return out.strip() != ""

      with subtest("the LAN can't address a sandbox: einat running, then einat stopped (pre, and post without the mark from pre)"):
          lan.fail(f"ping -c2 -W1 {sb4}", f"ping -6 -c2 -W1 {sb6}")
          assert not lan_reaches_sandbox()
          # Stopping einat stops sandbox-uplink; the pinned links stay
          ws.succeed("systemctl stop sandbox-einat")
          assert not ws.succeed("systemctl is-active sandbox-uplink || true").strip() == "active"
          print(ws.succeed("bpftool net show dev eth1"))
          assert not lan_reaches_sandbox()
          ws.succeed(f"rm {pins}/pre-eth1")
          assert not lan_reaches_sandbox(), "post let in what pre didn't mark"
          # Control: without either, the host stack forwards it in
          ws.succeed(f"rm {pins}/post-eth1")
          assert lan_reaches_sandbox()

      with subtest("einat stopped: egress keeps sandbox sources off the uplink"):
          ws.succeed("systemctl start sandbox-einat")
          wait_in_order("eth1")
          ws.succeed("systemctl stop sandbox-einat")
          capture(lan, "src net 169.254.100.0/22 or src net " + str(block6))
          ws.fail(sb(f"ping -c1 -W1 {lan4}"), sb(f"ping -6 -c1 -W1 {lan6}"))
          assert captured(lan).strip() == "", "a sandbox source left"
          # Nor with the IP header outside the linear part: egress pulls it in. The same frame from the workstation
          # address leaves (the MTU raised for the frame)
          ws.succeed("ip link set eth1 mtu 9000")
          capture(ws, "udp port 9", unit="nl")
          # A drop at tcx egress fails the send (ENOBUFS)
          for src, dst in [(sb4, lan4), (sb6, lan6), (ws4, lan4)]:
              ws.execute(f"${pkgs.python3}/bin/python3 ${nonlinear} eth1 {src} {dst}")
          out = captured(ws, "nl")
          print("non-linear frames out:", out)
          assert f"{ws4}.5555 >" in out and sb4 not in out and sb6 not in out, out
          ws.succeed("ip link set eth1 mtu 1500")
          # Control: without it, they leave un-NATed
          ws.succeed(f"rm {pins}/egress-eth1")
          capture(lan, "src net 169.254.100.0/22 or src net " + str(block6))
          ws.fail(sb(f"ping -c1 -W1 {lan4}"), sb(f"ping -6 -c1 -W1 {lan6}"))
          leak = captured(lan)
          print("without egress:", leak)
          assert sb4 in leak and sb6 in leak, leak
          ws.succeed("systemctl start sandbox-einat")
          wait_in_order("eth1")
          ws.succeed(sb(f"curl -sf -m5 http://{lan4}/ -o /dev/null"))

      def flap():
          # Its IPv6 address kept, the routes put back
          ws.succeed("sysctl -w net.ipv6.conf.eth1.keep_addr_on_down=1", "ip link set eth1 down", "ip link set eth1 up")
          ws.wait_until_succeeds(f"ip route replace default via {lan4} dev eth1 && ip -6 route replace default via {lan6} dev eth1", timeout=30)
          # einat attaches again, at the head
          retry(lambda _: "ingress_rev_snat" in order("eth1", "ingress"), timeout_seconds=30)

      # The program IDs on the tcx hooks of dev, by name
      def prog_ids(dev):
          return {p["name"]: p["prog_id"] for p in json.loads(ws.succeed(f"bpftool -j net show dev {dev}"))[0]["tc"]}

      with subtest("einat restarted or attaching again on link up: sandbox-uplink puts pre ahead again"):
          ws.succeed("systemctl restart sandbox-einat")
          wait_in_order("eth1")
          ws.succeed(sb(f"curl -sf -m5 http://{lan4}/ -o /dev/null"))
          before = prog_ids("eth1")
          flap()
          wait_in_order("eth1")
          # Moved make-before-break: the other instance of pre attached at the head before the old link went
          after = prog_ids("eth1")
          print("program IDs before and after the link flap:", before, after)
          assert after["pre"] != before["pre"], (before, after)
          ws.wait_until_succeeds(sb(f"curl -sf -m3 http://{lan4}/ -o /dev/null"))
          print(ws.succeed("journalctl -u sandbox-uplink -o cat | grep Reordered"))
          # Control: without sandbox-uplink, einat stays ahead of pre, which drops the replies (failing closed)
          ws.succeed("systemctl stop sandbox-uplink")
          flap()
          time.sleep(2)
          assert order("eth1", "ingress")[:2] == ["ingress_rev_snat", "pre"], order("eth1", "ingress")
          ws.fail(sb(f"curl -sf -m3 http://{lan4}/ -o /dev/null"))
          ws.succeed("systemctl start sandbox-uplink")
          wait_in_order("eth1")
          ws.succeed(sb(f"curl -sf -m5 http://{lan4}/ -o /dev/null"))

      with subtest("a new physical NIC: a new einat config, and the programs on it"):
          before = ws.succeed("systemctl show -P MainPID sandbox-einat").strip()
          ws.send_monitor_command("netdev_add user,id=hot")
          ws.send_monitor_command("device_add virtio-net-pci,netdev=hot,id=hotnic")
          ws.wait_until_succeeds("grep -q 'if_name = \"eth2\"' /run/sandbox-einat/einat.toml", timeout=30)
          ws.succeed("ip link set eth2 up")
          wait_in_order("eth2")
          assert ws.succeed("systemctl show -P MainPID sandbox-einat").strip() != before
          ws.succeed(sb(f"curl -sf -m5 http://{lan4}/ -o /dev/null"))

      # pre first; post after einat and egress after it, with programs of others after them, Cilium at the tail
      def around_einat(dev, node=ws):
          i, e = order(dev, "ingress", node), order(dev, "egress", node)
          try:
              return (i[0] == "pre" and i.index("ingress_rev_snat") < i.index("post") < i.index("cil_from_netdev") == len(i) - 1
                      and e.index("egress_snat") < e.index("egress") < e.index("cil_to_netdev") == len(e) - 1)
          except ValueError:
              return False

      def sandbox_out(node, ext):
          out = node.succeed(sb("sh -c 'echo x | socat -T3 - UDP4:" + lan4 + ":7'")).split()
          assert out[0] == ext and 61000 <= int(out[1]) <= 63999, out
          node.succeed(sb(f"curl -sf -m5 http://{lan4}/ -o /dev/null"))

      with subtest("Cilium at the tail and another program at the head, both there before einat and sandbox-uplink start"):
          # The hooks emptied, then head at the head and Cilium after it (bpftool appends)
          ws.succeed("systemctl stop sandbox-einat", f"rm {pins}/pre-eth1 {pins}/post-eth1 {pins}/egress-eth1",
                     "bpftool prog loadall ${standIns} /sys/fs/bpf/stand")
          for hook, tail in [("tcx_ingress", "cil_from_netdev"), ("tcx_egress", "cil_to_netdev")]:
              ws.succeed(f"bpftool net attach {hook} pinned /sys/fs/bpf/stand/head dev eth1",
                         f"bpftool net attach {hook} pinned /sys/fs/bpf/stand/{tail} dev eth1")
          assert order("eth1", "ingress") == ["head", "cil_from_netdev"], order("eth1", "ingress")
          ws.succeed("systemctl start sandbox-einat")
          wait_in_order("eth1", check=around_einat)
          print(order("eth1", "ingress"), order("eth1", "egress"))
          sandbox_out(ws, ws4)
          # einat attaching again (link up) and restarting: still in place
          flap()
          wait_in_order("eth1", check=around_einat)
          ws.succeed("systemctl restart sandbox-einat")
          wait_in_order("eth1", check=around_einat)
          print(order("eth1", "ingress"), order("eth1", "egress"))
          sandbox_out(ws, ws4)
          # einat stopped: egress, ahead of Cilium, still drops sandbox sources
          ws.succeed("systemctl stop sandbox-einat")
          # The workstation pinging in the same capture, the positive control
          capture(lan, f"src net 169.254.100.0/22 or (icmp and src host {ws4})")
          ws.fail(sb(f"ping -c1 -W1 {lan4}"))
          ws.succeed(f"ping -c1 -W1 {lan4}")
          out = captured(lan)
          assert f"{ws4} >" in out, "the ping of the workstation didn't arrive"
          assert " IP 169.254." not in out, "a sandbox source left"
          ws.succeed("systemctl start sandbox-einat")

      with subtest("an uplink NIC enslaved to a bridge: the bridge is the uplink, and the sandbox leaves through it"):
          bridged.wait_for_unit("sandbox-uplink.service")
          conf = bridged.succeed("cat /run/sandbox-einat/einat.toml")
          assert re.findall(r'if_name = "(.*)"', conf) == ["br0", "eth0"], conf
          wait_in_order("br0", bridged)
          primary = netkit_pair(bridged, sb4)
          bridged.succeed(f"bpftool map update pinned {pins}/sandboxes key hex {hexbytes(packed(sb4))} value hex {hexbytes(struct.pack('=I', primary))}")
          sandbox_out(bridged, "192.168.1.200")
    '';
}
