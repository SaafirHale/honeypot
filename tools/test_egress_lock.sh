#!/usr/bin/env bash
# Exercise deploy/host/egress-lock.sh without root on the Docker host.
#
# Builds a three-container topology that reproduces what the VPS sees:
#   honeypot (10.99.0.10, default route via router) --> router (10.99.0.2 + default bridge) --> internet
# The router stands in for the VPS: it forwards and NATs for the honeypot, and
# egress-lock.sh runs on it unchanged, matching the router's interface on the
# internal network. Only NET_ADMIN inside the test containers' own network
# namespaces is needed. Nothing on the Docker host's firewall is touched.
#
# Checks, before and after `egress-lock.sh apply`:
#   honeypot -> internet TCP (1.1.1.1:443)       open before, blocked after
#   honeypot -> public DNS (1.1.1.1:53)          open before, blocked after
#   outside -> honeypot TCP, and the reply      works before and after
#
# Usage: tools/test_egress_lock.sh [extra-ca.pem]
#   The optional PEM is appended to the test containers' CA bundle so apk can
#   reach its mirror through a TLS-inspecting proxy; verification stays on.
set -euo pipefail

here="$(cd "$(dirname "$0")/.." && { pwd -W 2>/dev/null || pwd; })"  # pwd -W: Windows path for Docker Desktop
ca="${1:-}"
img="alpine:3.20"
net="hp_egresstest"
pass=0; fail=0
ok()  { echo "PASS  $*"; pass=$((pass + 1)); }
bad() { echo "FAIL  $*"; fail=$((fail + 1)); }

cleanup() {
  docker rm -f hp-et-router hp-et-pot >/dev/null 2>&1 || true
  docker network rm "$net" >/dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup

mounts=(-v "$here/deploy/host/egress-lock.sh:/egress-lock.sh:ro")
[ -n "$ca" ] && mounts+=(-v "$ca:/extra-ca.pem:ro")
prep='[ -f /extra-ca.pem ] && cat /extra-ca.pem >> /etc/ssl/certs/ca-certificates.crt; apk add -q --no-progress'

# Not --internal: Docker drops off-subnet frames from internal networks before they
# reach the router, which would make the "before" baseline meaningless.
docker network create --subnet 10.99.0.0/24 "$net" >/dev/null

# Router: default bridge for the internet, internal network for the honeypot.
docker run -d --name hp-et-router --cap-add NET_ADMIN --sysctl net.ipv4.ip_forward=1 \
  "${mounts[@]}" "$img" sleep 600 >/dev/null
docker network connect --ip 10.99.0.2 "$net" hp-et-router
docker exec hp-et-router sh -c "$prep iptables bash netcat-openbsd iproute2"
inner_if="$(docker exec hp-et-router sh -c "ip -o -4 addr show | awk '/10\.99\.0\.2/ {print \$2}'")"
outer_if="$(docker exec hp-et-router sh -c "ip route show default | awk '{print \$5}'")"
docker exec hp-et-router iptables -t nat -A POSTROUTING -s 10.99.0.0/24 -o "$outer_if" -j MASQUERADE
echo "router: inner=$inner_if outer=$outer_if"

# Honeypot stand-in: tools installed while it still uses Docker's gateway, then
# its default route is pointed at the router so all egress crosses the lock.
docker run -d --name hp-et-pot --cap-add NET_ADMIN --network "$net" --ip 10.99.0.10   "${mounts[@]}" "$img" sleep 600 >/dev/null
docker exec hp-et-pot sh -c "$prep netcat-openbsd bind-tools" >/dev/null
docker exec hp-et-pot ip route replace default via 10.99.0.2

probe_out() {   # honeypot -> internet over TCP (by address: no DNS needed)
  docker exec hp-et-pot sh -c 'nc -z -w 4 1.1.1.1 443' >/dev/null 2>&1
}
probe_dns() {   # honeypot -> public resolver over UDP
  # dig prints ";; communications error" to stdout on timeout, so require an address.
  docker exec hp-et-pot sh -c 'dig +time=3 +tries=1 +short example.com @1.1.1.1' 2>/dev/null | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'
}
probe_in() {    # outside -> honeypot, honeypot replies on the same connection
  docker exec -d hp-et-pot sh -c 'echo SSH-2.0-OpenSSH_9.6 | nc -l -p 2222 -w 5'
  sleep 1
  docker exec hp-et-router sh -c 'nc -w 4 10.99.0.10 2222 </dev/null' 2>/dev/null | grep -q SSH-2.0
}

echo "--- before egress-lock"
probe_out && ok "honeypot reaches the internet (baseline)" || bad "baseline outbound TCP failed; test cannot prove anything"
probe_dns && ok "honeypot resolves via 1.1.1.1 (baseline)" || bad "baseline DNS failed"
probe_in  && ok "inbound connection gets a reply (baseline)" || bad "baseline inbound failed"

echo "--- egress-lock.sh apply (HONEYNET_BRIDGE=$inner_if)"
docker exec -e HONEYNET_BRIDGE="$inner_if" hp-et-router bash /egress-lock.sh apply
docker exec -e HONEYNET_BRIDGE="$inner_if" hp-et-router bash /egress-lock.sh apply >/dev/null  # idempotent

echo "--- after egress-lock"
probe_out && bad "honeypot still reaches the internet" || ok "outbound TCP from honeypot blocked"
probe_dns && bad "honeypot still resolves via 1.1.1.1" || ok "outbound DNS from honeypot blocked"
probe_in  && ok "inbound connection still gets a reply (ESTABLISHED passes)" || bad "inbound replies broken by the lock"

rules=$(docker exec hp-et-router iptables -t mangle -S PREROUTING | grep -c HP-EGRESS)
[ "$rules" = 1 ] && ok "jump rule installed exactly once after two applies" || bad "jump rule count is $rules"
docker exec hp-et-router iptables -t mangle -L HP-EGRESS -v -n | sed 's/^/      /'

echo "--- egress-lock.sh remove"
docker exec -e HONEYNET_BRIDGE="$inner_if" hp-et-router bash /egress-lock.sh remove
probe_out && ok "outbound restored after remove" || bad "remove did not restore outbound"

echo "--- $pass passed, $fail failed"
[ "$fail" -eq 0 ]
