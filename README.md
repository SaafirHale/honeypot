# honeypot

A deployable SSH/Telnet honeypot with a public attack dashboard.

* **Sensor**: [Cowrie](https://github.com/cowrie/cowrie) 3.1.4 in Docker on ports 22/23. It runs unprivileged on a read-only filesystem with resource limits, and every outbound connection is dropped at the host.
* **Collector**: a small Python service with no network access. It turns Cowrie's JSON logs into one anonymised `stats.json`: top countries and ASNs (offline DB-IP Lite lookups), credentials guessed, commands run, payload hashes, sessions per hour.
* **Dashboard**: a static Next.js 15 page that reads `stats.json` and shows charts, a world map and recent commands. It is built to mount at `saafirhale.com/honeypot`.
* **Provisioning**: cloud-init and an idempotent setup script for a $5 Ubuntu 24.04 VPS, plus a [threat model](docs/THREAT_MODEL.md) and a [runbook](docs/RUNBOOK.md).

```
attackers ─22/23─▶ cowrie ──logs──▶ collector ──stats.json──▶ caddy ──HTTPS──▶ dashboard
                   (egress dropped)  (network: none)           (one file)      (static page)
```

## What gets published, and what never does

| Published | Never published |
|---|---|
| Counts per hour/day, per country, per ASN | Full source IPs (top /24s only with `--publish-prefixes`, off by default) |
| Top usernames, passwords, pairs, SSH client banners | Session IDs, source ports, tty transcripts |
| Commands, after sanitising: IPs cut to `a.b.c.x`, URLs defanged to `hxxp://host[.]tld`, control characters stripped, length capped | Download URLs, uploaded file names |
| SHA-256 of files pushed in over SFTP/SCP | The files themselves (pruned on the sensor after 14 days) |
| | Anything from `ADMIN_CIDR` (your own IP) |

If a full IPv4 address survives sanitisation for any reason, the collector refuses
to write the file and keeps the previous one (`assert_publishable`).

## Layout

```
collector/            Python package + tests + Dockerfile (stdlib + maxminddb)
deploy/
  docker-compose.yml  cowrie, collector, stats-web (Caddy, profile "publish")
  cowrie/             cowrie.cfg overrides, userdb.txt
  caddy/Caddyfile     serves /stats.json only, CORS for saafirhale.com
  host/               egress-lock.sh + systemd unit, retention.sh, update-geoip.sh
provision/            cloud-init.yaml, setup.sh (Ubuntu 24.04)
dashboard/            Next.js 15 static export, reads stats.json at runtime
samples/              synthetic/ (generated) and local-cowrie/ (real Cowrie 3.1.4 output) logs + stats
tools/                generate_sample_logs.py, simulate_attacks.py
docs/                 THREAT_MODEL.md, RUNBOOK.md, VPS_OPTIONS.md
```

## Run it locally

Needs Python 3.11+, Node 20+; Docker for the sensor itself.

```bash
# GeoIP (CC BY 4.0, ~18 MB, not committed)
bash deploy/host/update-geoip.sh data/geoip

# Collector tests
python -m venv .venv && .venv/bin/pip install -e "collector[test]" paramiko   # Windows: .venv\Scripts\
cd collector && ../.venv/bin/python -m pytest -q && cd ..

# Stats from the synthetic sample
.venv/bin/python -m honeypot_collector --logs samples/synthetic --out dashboard/public/stats.json \
  --country-db data/geoip/dbip-country-lite.mmdb --asn-db data/geoip/dbip-asn-lite.mmdb \
  --days 14 --end last-event --dataset sample

# Dashboard
cd dashboard && npm install && npm test && npm run build && npm run serve   # http://localhost:3101
```

Real Cowrie without Docker (how `samples/local-cowrie/` was produced). Cowrie 3.1.4 runs
natively under Python 3.12, Windows included, with this repo's config bound to localhost:

```bash
python -m venv cowrie-venv && cowrie-venv/bin/pip install cowrie==3.1.4
mkdir -p run/etc run/var/log/cowrie run/var/lib/cowrie/downloads run/var/lib/cowrie/tty
sed 's/interface=0.0.0.0/interface=127.0.0.1/' deploy/cowrie/cowrie.cfg > run/etc/cowrie.cfg
cp deploy/cowrie/userdb.txt run/etc/ && cd run && ../cowrie-venv/bin/twistd -n cowrie &
python tools/simulate_attacks.py --ssh-port 2222 --telnet-port 2223
```

There is no egress lock in this mode: Cowrie's emulated `wget` really fetches its URL
(the simulator only uses example.com). That behaviour is why the deployed stack drops
outbound traffic at the host.

The real sensor, end to end, on Docker Desktop (run on Windows 11 + WSL2, Docker 29.9):

```bash
cd deploy
printf 'HONEYPOT_SSH_PORT=2222
HONEYPOT_TELNET_PORT=2323
HONEYPOT_BIND=127.0.0.1
STATS_DATASET=local-test
STATS_DAYS=2
COLLECT_INTERVAL=20
STATS_SITE=:8080
CORS_ORIGIN=*
STATS_BIND=127.0.0.1
STATS_HTTP_PORT=8088
STATS_HTTPS_PORT=8443
' > .env
# Behind a TLS-inspecting proxy, put its root CA (PEM) at deploy/local/extra-ca.pem and
# add the local override; it reaches the collector build as a BuildKit secret only.
docker compose -f docker-compose.yml -f docker-compose.local.yml --profile publish up -d --build
python ../tools/simulate_attacks.py --ssh-port 2222 --telnet-port 2323
curl http://127.0.0.1:8088/stats.json
bash host/egress-lock.sh verify      # on Docker Desktop this FAILS, correctly: there is no lock
bash ../tools/test_egress_lock.sh [proxy-ca.pem]   # exercises the lock script itself; see below
```

On Docker Desktop the "host" firewall lives inside its VM, which this repo does not
modify. `tools/test_egress_lock.sh` instead builds a router container (NET_ADMIN in its
own namespace only) with a honeypot stand-in behind it, runs `egress-lock.sh` on the
router unchanged, and checks egress before and after. On the VPS, `setup.sh` runs
`egress-lock.sh verify` against the real container and stops if it does not pass.

To mount the dashboard on the site, build with `NEXT_PUBLIC_BASE_PATH=/honeypot` and
`NEXT_PUBLIC_STATS_URL=https://<stats-host>/stats.json`. Or copy
`dashboard/src/components/honeypot/` and `src/lib/stats.ts` into the site. Its
`sh-*` classes and tokens already match the site's `globals.css`.

## What has been verified

| Check | Result |
|---|---|
| Collector unit + integration tests (`collector/tests`) | 42 passed, including one against real Cowrie 3.1.4 output |
| Dashboard parser tests (`npm test`) | 5 passed |
| Dashboard `tsc --noEmit` and `next build` (static export) | clean |
| Real Cowrie 3.1.4 + `simulate_attacks.py` → collector → dashboard | 35 sessions (18 SSH, 17 Telnet), 68 commands, 2 payload hashes (wget download, SFTP upload) rendered in the browser |
| Browser preview: hover tooltips, light/dark, 375 px width without horizontal scroll | checked; screenshots in [docs/screenshots](docs/screenshots) |
| Compose stack on Docker Desktop: Cowrie 3.1.4 container + collector + Caddy, attacked by `simulate_attacks.py` | 26 sessions (13 SSH, 13 Telnet), 49 commands, 2 payload hashes, served by Caddy and rendered by the dashboard over a cross-origin fetch |
| Hardening as applied (`docker inspect`) | Cowrie uid 999, collector uid 10001; read-only rootfs, `cap_drop: ALL`, no-new-privileges, memory/CPU/PID limits and log rotation on all three; collector `network_mode: none` (outbound attempt: *Network is unreachable*); idle memory about 84 MB total |
| Caddy endpoint | `/stats.json` 200 with CORS, CSP `default-src 'none'`, nosniff, no-referrer; any other path 404 |
| `egress-lock.sh` rules (`tools/test_egress_lock.sh`) | 8/8: outbound TCP and DNS open before, dropped and logged after; inbound connections still answered; idempotent apply; `remove` restores egress |
| `egress-lock.sh verify` fails closed | reports FAIL on a container with open egress and when the probe cannot run |
| `setup.sh` / cloud-init on a real Ubuntu VPS | **not yet run**: needs the VPS |

## Deploy

See [docs/RUNBOOK.md](docs/RUNBOOK.md). In short: create an Ubuntu 24.04 VPS with
`provision/cloud-init.yaml` as user data. It moves the real sshd to port 49222
(keys only), installs the egress lock before Docker, and starts the stack.
Provider options and their policies are in [docs/VPS_OPTIONS.md](docs/VPS_OPTIONS.md).

## Data sources and licences

IP geolocation by [DB-IP](https://db-ip.com) (Lite databases, CC BY 4.0); the
attribution is carried in `stats.json` and shown on the page. Country shapes are from
[world-atlas](https://github.com/topojson/world-atlas) (Natural Earth, public domain).
Cowrie is BSD-3-Clause.
