# Runbook

Commands assume you are on the VPS as `hpadmin` in `/opt/honeypot/deploy`
(`cd /opt/honeypot/deploy`). Connect with:

```bash
ssh -p 49222 hpadmin@<vps-ip>
```

Port 22 on this machine is the honeypot. If you `ssh` without `-p` you are
talking to Cowrie and anything you type is logged.

## 1. Deploy

1. Pick a provider ([VPS_OPTIONS.md](VPS_OPTIONS.md)), Ubuntu 24.04 LTS, 1 vCPU / 1 GB.
2. Make a dedicated key: `ssh-keygen -t ed25519 -f ~/.ssh/honeypot -C honeypot-admin`.
3. Paste `provision/cloud-init.yaml` into the provider's user-data field after
   replacing the `CHANGE_ME` public key. Set `ADMIN_CIDR` if
   your IP is stable.
4. Create the server. Wait 5 to 10 minutes. Watch progress in the provider's web
   console: `tail -f /var/log/cloud-init-output.log`.
5. Connect: `ssh -i ~/.ssh/honeypot -p 49222 hpadmin@<vps-ip>`.
6. Check it from outside:
   ```bash
   nc -vz <vps-ip> 22 && nc -vz <vps-ip> 23 && nc -vz <vps-ip> 49222
   ssh -o StrictHostKeyChecking=no root@<vps-ip>      # should reach Cowrie's fake prompt
   ```
7. Public stats (optional): point a DNS record such as `hp.saafirhale.com` at the
   VPS, set `STATS_SITE=hp.saafirhale.com` in `deploy/.env`, then
   `docker compose --profile publish up -d`. Caddy gets a certificate on its own.

No cloud-init? Clone the repo to `/opt/honeypot` by hand and run
`sudo ADMIN_SSH_PORT=49222 ADMIN_USER=hpadmin /opt/honeypot/provision/setup.sh`.
Keep your current SSH session open until you have logged in on the new port.

## 2. Daily and weekly checks

| What | Command | Healthy |
|---|---|---|
| Containers up | `docker compose ps` | cowrie and collector `running` |
| Egress lock | `sudo host/egress-lock.sh verify` | `OK: no outbound TCP, no DNS` |
| Lock counters | `sudo host/egress-lock.sh status` | DROP packet count grows over time; that is attackers' droppers failing |
| Stats fresh | `docker compose exec collector python -c "import json;print(json.load(open('/stats/stats.json'))['generated_at'])"` | within the last `COLLECT_INTERVAL` |
| Disk | `df -h /` | under 70% |
| Who logged in for real | `last -n 20` and `journalctl -u ssh --since -7d \| grep Accepted` | only you |

## 3. Updates

Security patches for the OS install themselves (unattended-upgrades, reboot at
04:30 UTC when needed). The egress lock comes back before Docker on every boot.

Images are pinned in `deploy/.env`. To move Cowrie forward:

```bash
# Read https://github.com/cowrie/cowrie/releases first; check whether
# cowrie.cfg options or the JSON event names changed.
sed -i 's|^COWRIE_IMAGE=.*|COWRIE_IMAGE=cowrie/cowrie:<new-tag>|' .env
docker compose pull cowrie && docker compose up -d cowrie
sudo host/egress-lock.sh verify
docker compose logs --tail 50 cowrie
```

Collector or dashboard code changes: `git pull && docker compose up -d --build collector`.

GeoIP refreshes on the 3rd of every month by cron (`/etc/cron.d/honeypot`). To run it now:
`sudo host/update-geoip.sh /opt/honeypot/data/geoip`.

## 4. Looking at the raw data (operator only)

```bash
vol=$(docker volume inspect -f '{{ .Mountpoint }}' honeypot_cowrie-var)
sudo tail -f $vol/log/cowrie/cowrie.json | jq -c '{eventid,src_ip,username,password,input}'
sudo ls -la $vol/lib/cowrie/downloads      # captured files: do NOT open or copy off the box
```

To check a hash, look it up on VirusTotal or MalwareBazaar by SHA-256. Never upload or move the file.

## 5. If you think the host is compromised

Signs: logins in `last` you did not make, unknown processes outside containers
(`ps auxf`), outbound traffic from the host itself, changed files under
`/etc/ssh`, stats.json that stopped updating or shows impossible numbers, an
abuse complaint from the provider.

The VPS holds nothing that cannot be rebuilt. **Do not try to clean it; replace it.**

1. **Contain.** In the provider's panel, power off the server or attach a
   deny-all cloud firewall. Do this from the panel, not over SSH.
2. **Preserve (optional).** Take a provider snapshot before destroying, if you
   want to investigate later. Do not download it to a personal machine.
3. **Revoke.** Remove the `honeypot` public key from anywhere else it is trusted,
   and generate a new one for the replacement. Rotate any DNS or provider API
   token that was ever used from that box.
4. **Abuse report?** Reply to the provider with what the box is, the egress
   controls, and that it has been shut down and is being rebuilt. Attach
   `egress-lock.sh status` output if you still have it.
5. **Rebuild** from the repo with a fresh key (section 1). Consider tightening
   `ADMIN_CIDR` and bumping image versions first.
6. **Write it up.** What was seen, how it got in if known, what changed. A short
   incident note is worth more to a reader than the dashboard.

If the **dashboard** shows something it should not (a full IP, a live link,
offensive content): stop publishing first with `docker compose stop stats-web`,
or remove the page from the site. Then fix the collector with a test that
reproduces the problem.

## 6. Tear down

1. `docker compose --profile publish down` (add `-v` to delete logs and payloads now).
2. Delete the DNS record for the stats host, if one was made.
3. Remove the honeypot page or its data URL from saafirhale.com.
4. Destroy the server **and** its snapshots/backups in the provider's panel, then
   check billing shows no running resources (reserved IPs, volumes).
5. Delete the `honeypot` SSH key pair locally.

Billing stops when the server is destroyed (hourly providers) or at the end of
the period (monthly). The last stats.json in this repo or on the site keeps working
as a static snapshot if you want the page to stay up.
