#!/usr/bin/env bash
# Provision a fresh Ubuntu 24.04 VPS as a honeypot host. Idempotent: safe to re-run.
#
# Run as root from a checkout at /opt/honeypot:
#   sudo ADMIN_SSH_PORT=49222 ADMIN_USER=hpadmin /opt/honeypot/provision/setup.sh
#
# Order matters. The real sshd moves off port 22 and is confirmed listening on
# the new port BEFORE the honeypot is allowed to bind 22, and the egress lock is
# in place BEFORE the honeypot container first starts.
set -euo pipefail

ADMIN_SSH_PORT="${ADMIN_SSH_PORT:-49222}"
ADMIN_USER="${ADMIN_USER:-hpadmin}"
ADMIN_CIDR="${ADMIN_CIDR:-}"   # optional: restrict admin SSH to this source
REPO_DIR="${REPO_DIR:-/opt/honeypot}"
PUBLISH="${PUBLISH:-auto}"     # auto = publish if deploy/.env sets a STATS_SITE domain

log() { printf '\n==> %s\n' "$*"; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "run as root"
. /etc/os-release
[ "${ID:-}" = "ubuntu" ] || die "expected Ubuntu, got ${ID:-unknown}"
[ -d "$REPO_DIR/deploy" ] || die "repo not found at $REPO_DIR"
id "$ADMIN_USER" >/dev/null 2>&1 || die "admin user $ADMIN_USER does not exist"
[ -s "/home/$ADMIN_USER/.ssh/authorized_keys" ] \
  || die "$ADMIN_USER has no authorized_keys; refusing to disable password auth"

# --------------------------------------------------------------- packages ---
log "Base packages and unattended security upgrades"
export DEBIAN_FRONTEND=noninteractive
apt-get update -q
apt-get install -y -q ca-certificates curl gnupg ufw unattended-upgrades iptables \
  apt-listchanges needrestart
dpkg-reconfigure -f noninteractive unattended-upgrades
cat >/etc/apt/apt.conf.d/52honeypot-upgrades <<'EOF'
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-Time "04:30";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
EOF

# --------------------------------------------------------- admin SSH move ---
log "Real sshd -> port $ADMIN_SSH_PORT, keys only, $ADMIN_USER only"
cat >/etc/ssh/sshd_config.d/10-honeypot-admin.conf <<EOF
# Managed by provision/setup.sh. Port 22 belongs to the honeypot.
Port $ADMIN_SSH_PORT
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
AuthenticationMethods publickey
AllowUsers $ADMIN_USER
MaxAuthTries 3
LoginGraceTime 20
X11Forwarding no
AllowAgentForwarding no
PermitTunnel no
EOF
sshd -t || die "sshd config invalid; not restarting"

# Ubuntu 24.04 uses socket activation: the listening port comes from ssh.socket,
# which a systemd generator derives from sshd_config on daemon-reload.
if systemctl is-enabled ssh.socket >/dev/null 2>&1; then
  systemctl daemon-reload
  systemctl restart ssh.socket
fi
systemctl restart ssh.service || systemctl restart ssh

for _ in $(seq 1 10); do
  ss -ltnH "sport = :$ADMIN_SSH_PORT" | grep -q . && break
  sleep 1
done
ss -ltnH "sport = :$ADMIN_SSH_PORT" | grep -q . || die "sshd is not listening on $ADMIN_SSH_PORT"
if ss -ltnpH "sport = :22" | grep -q sshd; then
  die "sshd still holds port 22; refusing to start the honeypot"
fi

# --------------------------------------------------------------- firewall ---
log "UFW: deny inbound except admin SSH and the honeypot/stats ports"
ufw --force reset >/dev/null
ufw default deny incoming
ufw default allow outgoing
if [ -n "$ADMIN_CIDR" ]; then
  ufw allow from "$ADMIN_CIDR" to any port "$ADMIN_SSH_PORT" proto tcp comment 'admin ssh'
else
  ufw limit "$ADMIN_SSH_PORT"/tcp comment 'admin ssh'
fi
# Docker-published ports bypass UFW's INPUT rules; these lines document intent.
ufw allow 22/tcp comment 'honeypot ssh'
ufw allow 23/tcp comment 'honeypot telnet'
ufw allow 80/tcp comment 'stats http (acme)'
ufw allow 443/tcp comment 'stats https'
ufw --force enable

# ------------------------------------------------------------- egress lock ---
log "Egress lock for the honeypot bridge (installed before Docker starts it)"
chmod 0755 "$REPO_DIR"/deploy/host/*.sh
install -m 0644 "$REPO_DIR/deploy/host/honeypot-egress.service" \
  /etc/systemd/system/honeypot-egress.service
systemctl daemon-reload
systemctl enable --now honeypot-egress.service

# ------------------------------------------------------------------ docker ---
if ! command -v docker >/dev/null 2>&1; then
  log "Docker Engine from Docker's signed apt repository"
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
  chmod a+r /etc/apt/keyrings/docker.asc
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] \
https://download.docker.com/linux/ubuntu ${VERSION_CODENAME} stable" \
    >/etc/apt/sources.list.d/docker.list
  apt-get update -q
  apt-get install -y -q docker-ce docker-ce-cli containerd.io docker-compose-plugin
fi

log "Docker daemon defaults: log rotation, no-new-privileges, no inter-container traffic"
mkdir -p /etc/docker
cat >/etc/docker/daemon.json <<'EOF'
{
  "log-driver": "json-file",
  "log-opts": { "max-size": "10m", "max-file": "3" },
  "no-new-privileges": true,
  "icc": false,
  "live-restore": true,
  "userland-proxy": false
}
EOF
systemctl restart docker
systemctl is-active --quiet honeypot-egress.service || die "egress lock is not active"

# ------------------------------------------------------------------- geoip ---
log "DB-IP Lite databases"
"$REPO_DIR/deploy/host/update-geoip.sh" "$REPO_DIR/data/geoip"

# -------------------------------------------------------------------- cron ---
log "Cron: daily retention, monthly GeoIP refresh"
cat >/etc/cron.d/honeypot <<EOF
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
15 3 * * * root $REPO_DIR/deploy/host/retention.sh >>/var/log/honeypot-retention.log 2>&1
40 3 3 * * root $REPO_DIR/deploy/host/update-geoip.sh $REPO_DIR/data/geoip >>/var/log/honeypot-geoip.log 2>&1
EOF
chmod 0644 /etc/cron.d/honeypot

# ------------------------------------------------------------------- stack ---
cd "$REPO_DIR/deploy"
[ -f .env ] || { cp .env.example .env; echo "created deploy/.env from the example; review it"; }
if [ -n "$ADMIN_CIDR" ] && ! grep -q "^ADMIN_CIDR=." .env; then
  sed -i "s|^ADMIN_CIDR=.*|ADMIN_CIDR=$ADMIN_CIDR|" .env
fi

profiles=()
if [ "$PUBLISH" = "yes" ] || { [ "$PUBLISH" = "auto" ] \
    && grep -qE '^STATS_SITE=[A-Za-z0-9.-]+\.[A-Za-z]{2,}$' .env \
    && ! grep -q '^STATS_SITE=stats.example.com$' .env; }; then
  profiles=(--profile publish)
fi

log "Starting the stack ${profiles[*]:-(no public stats endpoint)}"
docker compose "${profiles[@]}" pull --ignore-buildable
docker compose "${profiles[@]}" up -d --build

log "Verifying egress is blocked from inside the honeypot"
sleep 5
"$REPO_DIR/deploy/host/egress-lock.sh" verify

log "Done"
cat <<EOF
  Admin SSH:   ssh -p $ADMIN_SSH_PORT $ADMIN_USER@<this-host>
  Honeypot:    22/tcp (ssh), 23/tcp (telnet)
  Stats:       docker compose -f $REPO_DIR/deploy/docker-compose.yml exec collector cat /stats/stats.json | head
  Runbook:     $REPO_DIR/docs/RUNBOOK.md
EOF
