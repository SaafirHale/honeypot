# Threat model

A honeypot invites hostile traffic on purpose, so the design question is
narrower than usual: what can the people who connect to it do to **the host**,
to **third parties**, to **the portfolio site**, and to **the operator**?

## System

```
 internet ──22/23──▶ [ cowrie container ]  ── writes ──▶ cowrie-var volume (logs, tty, payloads)
                       uid 999, read-only rootfs,              │ read-only
                       no caps, 384 MB / 0.5 CPU,              ▼
                       egress dropped at host        [ collector container ]  network: none
                                                               │ writes
                                                               ▼
 saafirhale.com ◀──HTTPS GET stats.json── [ caddy ] ◀── stats volume (read-only)
 (static page)                            separate network, serves one file

 operator ──SSH, key only, high port──▶ host sshd
```

Assets, in order of how bad losing them would be:

1. **Third parties' safety.** The box must never become an attack source.
2. **The operator's identity and credentials.** Nothing personal on the VPS; the admin key is the only secret.
3. **The portfolio site's integrity.** Attacker text ends up on saafirhale.com.
4. **The VPS itself.** Disposable. Rebuilt from this repo in minutes.
5. **The data.** Nice to have. Thirty days of it is retained.

## Adversaries

| Who | Capability | Goal |
|---|---|---|
| Commodity bots (the 99%) | Credential lists, scripted post-login commands, wget/curl droppers | Enrol the box in a botnet or miner |
| Hands-on intruder | Notices it is Cowrie, probes for an escape | Reach the real host or use it as a pivot |
| Cowrie / Python 0-day | Code execution inside the container as uid 999 | Same as above |
| Data poisoner | Crafts usernames, passwords and commands | Get markup or links onto saafirhale.com, or embarrass the operator with what is displayed |
| Provider / abuse desk | Receives complaints about traffic from the IP | Suspend the account |

## Threats and controls

### T1. The honeypot is used to attack others

The worst outcome: abuse reports, account suspension, and real harm to someone else.

* **Egress lock** (`deploy/host/egress-lock.sh`). Every connection that *starts*
  inside the `br-honeynet` bridge is dropped in `mangle/PREROUTING`. This includes
  TCP, UDP, DNS and the cloud metadata address. Replies to inbound attackers
  (`ESTABLISHED,RELATED`) pass. The rule matches on the bridge name, so systemd
  installs it *before* `docker.service` starts and the container never runs unlocked.
  `egress-lock.sh verify` proves it by opening a socket from inside the container.
* **Cowrie's fake `wget`/`curl` make real HTTP requests.** Before 2.9.0 these
  could be abused for amplification (GHSA-83jg-m2pm-4jxj). The image is pinned to
  3.1.4, and the egress lock makes those requests fail regardless of version.
* **No SSH tunnelling.** `forwarding`, `forward_redirect` and `forward_tunnel`
  are all off in `deploy/cowrie/cowrie.cfg`, so Cowrie does not offer a
  `direct-tcpip` endpoint at all.
* **Trade-off accepted.** With egress blocked, droppers fail. Payload hashes are
  recorded only for files pushed in over SFTP/SCP, and blocked downloads are
  counted, not fetched. Malware capture is deliberately given up for safety.

### T2. Escape from the container to the host

* Cowrie is an *emulated* shell. Attacker "commands" are parsed by Python and
  never executed by a real shell.
* Container: uid 999, `cap_drop: ALL`, `no-new-privileges`, read-only root
  filesystem, `noexec` tmpfs, `pids_limit`, memory and CPU caps. The distroless
  image has no shell or package manager to work with.
* Host: Docker daemon with `icc: false`, `no-new-privileges` by default,
  `userland-proxy: false`. Unattended security upgrades with automatic reboot.
* Lateral: the collector has `network_mode: none`; Caddy is on a separate
  network. The only shared surface is a read-only volume of Cowrie's own logs.
* Residual risk: a kernel or runc 0-day. Mitigation is that the host holds
  nothing of value and is rebuilt rather than cleaned (see RUNBOOK, *If compromised*).

### T3. Attacker-controlled text on saafirhale.com

Usernames, passwords, commands and SSH client banners are typed by attackers.

* **Collector** (`collector/honeypot_collector/sanitize.py`): strips control and
  bidi-override characters, collapses whitespace, caps length (commands 160,
  credentials 48 characters). IPv4 addresses are cut to their /24 (`1.2.3.x`),
  IPv6 addresses are removed, and URLs are defanged (`hxxp://host[.]tld`) so the
  page can never hold a live link to attacker infrastructure.
* **Dashboard**: renders every string as React text. There is no
  `dangerouslySetInnerHTML` and no markdown. It validates the JSON shape before
  use, and the stats endpoint sends `Content-Security-Policy: default-src 'none'`.
* **Residual risk**: offensive words in a top-passwords list. These are
  publicly known credential dictionaries; the operator can add a deny-list if needed.

### T4. Publishing what should stay private

* **Attacker IPs**: never published in full. Optional top-/24 list is off by default
  (`--publish-prefixes`). A final guard (`assert_publishable`) refuses to write
  stats.json if any full dotted-quad survives sanitisation, and the previous file is
  left in place.
* **Captured malware**: never published. Only SHA-256 hashes leave the box; payload
  files are pruned after 14 days. Download URLs and filenames are not published.
* **Session IDs, ports, tty transcripts**: not in the output schema.
* **The operator's own traffic**: if the operator mistakenly connects to port 22
  instead of the admin port and types a real password, it would be logged like
  any attack. Setting `ADMIN_CIDR` drops every event from that network before
  aggregation (tested in `test_exclude_cidr_drops_admin_traffic`). Admin SSH being
  key-only means there is no real password to mistype in the first place.

### T5. Compromise of the operator's access

* Real sshd on a high port, `AuthenticationMethods publickey`, `AllowUsers hpadmin`,
  root login off, `MaxAuthTries 3`, UFW rate limit (or source restriction via
  `ADMIN_CIDR`).
* Use a dedicated key pair for this VPS, not a key that unlocks anything else.
* No API tokens, git credentials or cloud keys on the box. The repo is cloned over
  HTTPS read-only. If the operator chooses to push stats elsewhere later, use a
  write-only, single-purpose credential.

### T6. Data integrity (a compromised box lies)

An intruder who gets root on the VPS can write whatever they like to stats.json.

* The dashboard treats the JSON as untrusted (T3 controls apply regardless of
  where the text came from), so the worst case is false numbers, not code.
* Detection: numbers that jump implausibly, stats.json that stops updating
  (`generated_at` is shown on the page), or `hp-egress-drop` log volume changes.

### T7. Resource exhaustion

* Container limits cap CPU, memory and PIDs. Docker and Cowrie logs rotate, and
  retention prunes logs (45 days), tty (14) and payloads (14).
* The collector re-reads the whole window on each run. On the 3,000-session
  synthetic sample it takes about 4 seconds on a desktop, but a busy sensor can
  produce far more. If runs get slow, lower `STATS_DAYS` or raise `COLLECT_INTERVAL`.

### T8. Legal and provider policy

* None of the shortlisted providers names honeypots in its acceptable-use
  policy. All of them prohibit **outbound** scanning or attacks, which T1's
  controls exist to prevent. DigitalOcean requires prior written consent for
  "security or malware research"; see [VPS_OPTIONS.md](VPS_OPTIONS.md).
* Only aggregate statistics are published; no personal data of identifiable
  people. Full IPs stay on the box for 45 days at most.

## Out of scope

* Making Cowrie undetectable. Skilled attackers can fingerprint it; that is fine
  for a statistics sensor.
* High-interaction honeypots (real shells in VMs). Too much risk for a $5 box.
