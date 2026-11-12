# The host side of the sandbox network (nix/nixos/network.nix): einat and sandbox-uplink from the NixOS module on a
# workstation whose LAN host is its default gateway. The test script stands in for the per-launcher helper: a netkit
# pair whose primary forwards through the host stack (no PEER program), its addresses registered with bpftool
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
      def order(dev, direction):
          j = json.loads(ws.succeed(f"bpftool -j net show dev {dev}"))
          return [p["name"] for p in j[0]["tc"] if p["kind"] == f"tcx/{direction}"]

      def in_order(dev):
          return order(dev, "ingress") == ["pre", "ingress_rev_snat", "post"] and order(dev, "egress") == ["egress_snat", "egress"]

      def wait_in_order(dev):
          try:
              retry(lambda _: in_order(dev), timeout_seconds=30)
          except Exception:
              print(ws.execute(f"bpftool net show dev {dev}; findmnt -T {pins}; ls -la {pins}; journalctl -o cat -u sandbox-uplink | tail")[1])
              raise

      # tcpdump as a unit, read back after
      def capture(node, filt, iface="eth1", unit="cap"):
          node.succeed(f"systemd-run --unit={unit} tcpdump -U -ni {iface} -w /tmp/{unit}.pcap '{filt}'")
          time.sleep(1)

      def captured(node, unit="cap"):
          time.sleep(1)
          node.succeed(f"systemctl stop {unit}")
          return node.succeed(f"tcpdump -nr /tmp/{unit}.pcap 2>/dev/null; rm /tmp/{unit}.pcap")

      # As a non-root user in the given group with CAP_BPF alone, as the per-launcher helper runs
      def as_helper(gid, cmd, caps="+bpf"):
          return f"setpriv --reuid=1500 --regid=1500 --groups={gid} --inh-caps={caps} --ambient-caps={caps} {cmd}"

      def hexbytes(b):
          return " ".join(f"{x:02x}" for x in b)

      start_all()
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

      ws.succeed(
          "ip netns add sb",
          "ip link add sbx-t type netkit mode l3 peer name nkp",
          "ip link set nkp netns sb",
          "ip link set sbx-t up",
          f"ip route add {sb4}/32 dev sbx-t",
          f"ip -6 route add {sb6}/128 dev sbx-t",
          sb("ip link set lo up"),
          sb(f"ip addr add {sb4}/32 dev nkp"),
          sb(f"ip -6 addr add {sb6}/128 dev nkp nodad"),
          sb("ip link set nkp up"),
          sb("ip route add default dev nkp"),
          sb("ip -6 route add default dev nkp"),
          # Out through the host stack: step in for the PEER program
          "sysctl -w net.ipv4.conf.all.forwarding=1 net.ipv6.conf.all.forwarding=1",
      )
      primary = int(ws.succeed("cat /sys/class/net/sbx-t/ifindex"))
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
              key = hexbytes(ipaddress.ip_address(addr).packed if ":" in addr else ipaddress.IPv6Address(f"::ffff:{addr}").packed)
              update = f"bpftool map update pinned {pins}/sandboxes key hex {key} value hex {value}"
              # Another group with CAP_BPF is refused; the group alone opens it: unprivileged_bpf_disabled stops only
              # creating objects, the mode of the pin decides who opens one
              ws.fail(as_helper(100, update))
              ws.succeed(as_helper(group, update, caps="-all"))
          print(ws.succeed(f"bpftool map dump pinned {pins}/sandboxes"))

      with subtest("the uplinks and gateways maps for the PEER programs, and registrations of gone primaries removed"):
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
          def packed(a):
              a = ipaddress.ip_address(a)
              return ipaddress.IPv6Address(f"::ffff:{a}").packed if a.version == 4 else a.packed
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
          gone = hexbytes(ipaddress.IPv6Address("::ffff:169.254.103.1").packed)
          ws.succeed(f"bpftool map update pinned {pins}/sandboxes key hex {gone} value hex {hexbytes(struct.pack('=I', 99999))}")
          ws.wait_until_fails(f"bpftool map lookup pinned {pins}/sandboxes key hex {gone}", timeout=10)
          ws.succeed(f"bpftool map lookup pinned {pins}/sandboxes key hex {hexbytes(ipaddress.ip_address(sb6).packed)}")

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

      def lan_reaches_sandbox():
          ws.succeed("systemd-run --unit=sbcap -p NetworkNamespacePath=/run/netns/sb tcpdump -U -ni nkp -w /tmp/sbcap.pcap 'udp port 9999'")
          time.sleep(1)
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

      with subtest("einat restarted or attaching again on link up: sandbox-uplink puts pre ahead again"):
          ws.succeed("systemctl restart sandbox-einat")
          wait_in_order("eth1")
          ws.succeed(sb(f"curl -sf -m5 http://{lan4}/ -o /dev/null"))
          flap()
          wait_in_order("eth1")
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
    '';
}
