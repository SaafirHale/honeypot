#!/usr/bin/env bash
# Block every connection that STARTS inside the honeypot network.
#
# Replies to attackers (ESTABLISHED/RELATED) pass; anything new from the
# br-honeynet bridge (outbound to the internet, to the host itself, DNS, the
# metadata service) is logged at a low rate and dropped.
#
# The rules sit in mangle/PREROUTING rather than DOCKER-USER so they do not
# depend on Docker's chain layout and can be installed before dockerd starts:
# matching on an interface name works even if the bridge does not exist yet.
#
#   egress-lock.sh apply    install rules (idempotent)
#   egress-lock.sh remove   remove rules
#   egress-lock.sh status   show rules and counters
#   egress-lock.sh verify   prove the cowrie container cannot reach the internet
set -euo pipefail

BRIDGE="${HONEYNET_BRIDGE:-br-honeynet}"
CHAIN="HP-EGRESS"

have_v6() { command -v ip6tables >/dev/null 2>&1 && ip6tables -t mangle -L >/dev/null 2>&1; }

apply_family() {
  local ipt="$1"
  "$ipt" -t mangle -N "$CHAIN" 2>/dev/null || "$ipt" -t mangle -F "$CHAIN"
  "$ipt" -t mangle -A "$CHAIN" -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
  "$ipt" -t mangle -A "$CHAIN" -m limit --limit 6/min --limit-burst 10 \
    -j LOG --log-prefix "hp-egress-drop: " --log-level 4
  "$ipt" -t mangle -A "$CHAIN" -j DROP
  "$ipt" -t mangle -C PREROUTING -i "$BRIDGE" -j "$CHAIN" 2>/dev/null \
    || "$ipt" -t mangle -I PREROUTING 1 -i "$BRIDGE" -j "$CHAIN"
}

remove_family() {
  local ipt="$1"
  while "$ipt" -t mangle -D PREROUTING -i "$BRIDGE" -j "$CHAIN" 2>/dev/null; do :; done
  "$ipt" -t mangle -F "$CHAIN" 2>/dev/null || true
  "$ipt" -t mangle -X "$CHAIN" 2>/dev/null || true
}

verify() {
  local compose_dir
  compose_dir="$(cd "$(dirname "$0")/.." && pwd)"
  echo "Trying outbound TCP from inside the cowrie container (should fail)..."
  # The cowrie image is distroless; its Python is the only tool available, which is the point.
  if docker compose --project-directory "$compose_dir" exec -T cowrie \
      /cowrie/cowrie-env/bin/python3 -c \
      "import socket; socket.create_connection(('1.1.1.1', 443), timeout=4); print('CONNECTED')" \
      2>/dev/null | grep -q CONNECTED; then
    echo "FAIL: container reached 1.1.1.1:443. Egress is NOT blocked." >&2
    return 1
  fi
  echo "Trying DNS from inside the cowrie container (should fail)..."
  if docker compose --project-directory "$compose_dir" exec -T cowrie \
      /cowrie/cowrie-env/bin/python3 -c \
      "import socket; socket.setdefaulttimeout(4); print(socket.gethostbyname('example.com'))" \
      2>/dev/null | grep -qE '^[0-9.]+$'; then
    echo "FAIL: container resolved a public name. DNS egress is NOT blocked." >&2
    return 1
  fi
  echo "OK: no outbound TCP, no DNS from the honeypot network."
}

case "${1:-}" in
  apply)
    apply_family iptables
    have_v6 && apply_family ip6tables
    echo "egress lock applied on $BRIDGE"
    ;;
  remove)
    remove_family iptables
    have_v6 && remove_family ip6tables
    echo "egress lock removed from $BRIDGE"
    ;;
  status)
    iptables -t mangle -L PREROUTING -v -n --line-numbers | sed -n '1,6p'
    iptables -t mangle -L "$CHAIN" -v -n
    ;;
  verify)
    verify
    ;;
  *)
    echo "usage: $0 apply|remove|status|verify" >&2
    exit 2
    ;;
esac
