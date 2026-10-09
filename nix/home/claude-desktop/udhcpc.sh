# shellcheck shell=bash
# udhcpc's event script. $1: the event; $interface, $ip, $mask, $router, $dns and $domain come from udhcpc
: "${RESOLV_CONF:?}"
# shellcheck disable=SC2154
case $1 in
  deconfig) ip -4 addr flush dev "$interface" ;;
  bound | renew)
    [[ $1 == bound ]] && ip -4 addr flush dev "$interface"
    ip addr replace "$ip/$mask" dev "$interface"
    [[ -z ${router:-} ]] || ip route replace default via "${router%% *}" dev "$interface"
    # Written in place: the file is bind-mounted, a rename would leave the sandbox on the old inode
    {
      [[ -z ${domain:-} ]] || echo "search $domain"
      for d in ${dns:-}; do echo "nameserver $d"; done
    } >"$RESOLV_CONF"
    ;;
esac
