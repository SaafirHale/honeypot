from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from honeypot_collector.geo import GeoInfo

REPO = Path(__file__).resolve().parents[2]
END = datetime(2026, 10, 25, 12, 30, tzinfo=UTC)


class FakeGeo:
    """Deterministic geo table keyed by first octet, so tests need no MMDB file."""

    TABLE = {
        "1": GeoInfo("CN", "China", 4134, "CHINANET-BACKBONE"),
        "2": GeoInfo("US", "United States", 14061, "DIGITALOCEAN-ASN"),
        "3": GeoInfo("BR", "Brazil", 28573, "Claro NXT"),
    }

    def __init__(self) -> None:
        self.calls = 0

    def lookup(self, ip: str) -> GeoInfo:
        self.calls += 1
        return self.TABLE.get(ip.split(".")[0], GeoInfo("ZZ", "Unknown", None, None))


def ev(eventid: str, ts: str, ip: str = "1.1.1.10", session: str = "s1", **fields) -> dict:
    return {"eventid": eventid, "timestamp": ts, "src_ip": ip, "session": session, **fields}


def session_events(ip: str, session: str, ts: str, protocol: str = "ssh", logins=(),
                   commands=()) -> list[dict]:
    out = [ev("cowrie.session.connect", ts, ip, session, protocol=protocol)]
    for user, pw, ok in logins:
        eid = "cowrie.login.success" if ok else "cowrie.login.failed"
        out.append(ev(eid, ts, ip, session, username=user, password=pw))
    for cmd in commands:
        out.append(ev("cowrie.command.input", ts, ip, session, input=cmd))
    out.append(ev("cowrie.session.closed", ts, ip, session, duration=1.0))
    return out


def write_jsonl(path: Path, events: list[dict], extra_lines: list[str] = ()) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        for e in events:
            fh.write(json.dumps(e) + "\n")
        for line in extra_lines:
            fh.write(line + "\n")
    return path


@pytest.fixture
def geo() -> FakeGeo:
    return FakeGeo()
