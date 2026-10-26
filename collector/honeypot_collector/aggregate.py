"""Turn Cowrie events into the aggregated, anonymised stats.json document.

What is published: counts, top-N lists, sanitised command samples and SHA-256
hashes. What is never published: full source IPs, session IDs, raw URLs,
file names, or file contents.
"""

from __future__ import annotations

import ipaddress
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from .events import parse_ts
from .geo import GeoInfo, GeoLookup
from .sanitize import sanitize_command, sanitize_credential, truncate_ip

SCHEMA_VERSION = 1
HOURLY_BUCKETS = 168  # one week of hours

LOGIN_EVENTS = {"cowrie.login.failed", "cowrie.login.success"}
PAYLOAD_EVENTS = {"cowrie.session.file_download", "cowrie.session.file_upload"}
_SHA256_HEX = set("0123456789abcdef")


def _hour(ts: datetime) -> datetime:
    return ts.replace(minute=0, second=0, microsecond=0)


def _iso(ts: datetime) -> str:
    return ts.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _top(counter: Counter, n: int) -> list[tuple]:
    """most_common with a stable tie-break, so output does not depend on file order."""
    return sorted(counter.items(), key=lambda kv: (-kv[1], str(kv[0])))[:n]


def _valid_sha256(value: object) -> str | None:
    if isinstance(value, str):
        v = value.strip().lower()
        if len(v) == 64 and set(v) <= _SHA256_HEX:
            return v
    return None


@dataclass
class _Payload:
    count: int = 0
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    via: set[str] = field(default_factory=set)


@dataclass
class Aggregator:
    geo: GeoLookup
    end: datetime
    days: int = 30
    exclude: list[ipaddress._BaseNetwork] = field(default_factory=list)
    top_n: int = 15
    recent_n: int = 25

    def __post_init__(self) -> None:
        self.end = self.end.astimezone(UTC)
        self.start = self.end - timedelta(days=self.days)
        self.hour_end = _hour(self.end)
        self.hour_start = self.hour_end - timedelta(hours=HOURLY_BUCKETS - 1)

        self.events_seen = 0
        self.events_in_window = 0
        self.events_excluded = 0
        self.first: datetime | None = None
        self.last: datetime | None = None

        self.sessions = 0
        self.protocols: Counter[str] = Counter()
        self.countries: Counter[str] = Counter()
        self.country_names: dict[str, str] = {}
        self.asns: Counter[int] = Counter()
        self.asn_orgs: dict[int, str] = {}
        self.prefixes: Counter[str] = Counter()
        self.sources: set[str] = set()

        self.hourly_sessions: Counter[datetime] = Counter()
        self.hourly_logins: Counter[datetime] = Counter()
        self.daily_sessions: Counter[str] = Counter()

        self.login_attempts = 0
        self.login_successes = 0
        self.usernames: Counter[str] = Counter()
        self.passwords: Counter[str] = Counter()
        self.pairs: Counter[tuple[str, str]] = Counter()
        self.client_versions: Counter[str] = Counter()

        self.command_count = 0
        self.commands: Counter[str] = Counter()
        self._recent: dict[str, tuple[datetime, str]] = {}

        self.payloads: dict[str, _Payload] = {}
        self.downloads_blocked = 0

    # ------------------------------------------------------------------ input

    def _excluded(self, ip: str) -> bool:
        if not self.exclude:
            return False
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr in net for net in self.exclude)

    def add_all(self, events: Iterable[dict]) -> Aggregator:
        for e in events:
            self.add(e)
        return self

    def add(self, event: dict) -> None:
        self.events_seen += 1
        ts = parse_ts(event.get("timestamp"))
        if ts is None or not (self.start <= ts <= self.end):
            return
        ip = str(event.get("src_ip") or "")
        if ip and self._excluded(ip):
            self.events_excluded += 1
            return
        self.events_in_window += 1
        self.first = ts if self.first is None or ts < self.first else self.first
        self.last = ts if self.last is None or ts > self.last else self.last

        eid = event.get("eventid")
        if eid == "cowrie.session.connect":
            self._on_connect(event, ts, ip)
        elif eid in LOGIN_EVENTS:
            self._on_login(event, ts)
        elif eid == "cowrie.command.input":
            self._on_command(event, ts, ip)
        elif eid == "cowrie.client.version":
            version = sanitize_command(event.get("version", ""), max_len=80)
            if version:
                self.client_versions[version] += 1
        elif eid in PAYLOAD_EVENTS:
            self._on_payload(event, ts, "download" if eid.endswith("download") else "upload")
        elif eid == "cowrie.session.file_download.failed":
            self.downloads_blocked += 1

    def _geo(self, ip: str) -> GeoInfo:
        return self.geo.lookup(ip)

    def _on_connect(self, e: dict, ts: datetime, ip: str) -> None:
        self.sessions += 1
        self.protocols[str(e.get("protocol") or "ssh").lower()] += 1
        self.hourly_sessions[_hour(ts)] += 1
        self.daily_sessions[ts.date().isoformat()] += 1
        if not ip:
            return
        self.sources.add(ip)
        g = self._geo(ip)
        self.countries[g.country_code] += 1
        self.country_names[g.country_code] = g.country_name
        if g.asn is not None:
            self.asns[g.asn] += 1
            if g.as_org:
                self.asn_orgs[g.asn] = g.as_org
        prefix = truncate_ip(ip)
        if prefix:
            self.prefixes[prefix] += 1

    def _on_login(self, e: dict, ts: datetime) -> None:
        self.login_attempts += 1
        if e.get("eventid") == "cowrie.login.success":
            self.login_successes += 1
        self.hourly_logins[_hour(ts)] += 1
        user = sanitize_credential(e.get("username", ""))
        pw = sanitize_credential(e.get("password", ""))
        self.usernames[user] += 1
        self.passwords[pw] += 1
        self.pairs[(user, pw)] += 1

    def _on_command(self, e: dict, ts: datetime, ip: str) -> None:
        cmd = sanitize_command(e.get("input", ""))
        if not cmd:
            return
        self.command_count += 1
        self.commands[cmd] += 1
        country = self._geo(ip).country_code if ip else "ZZ"
        prev = self._recent.get(cmd)
        if prev is None or ts > prev[0]:
            self._recent[cmd] = (ts, country)

    def _on_payload(self, e: dict, ts: datetime, via: str) -> None:
        sha = _valid_sha256(e.get("shasum"))
        if sha is None:
            return
        p = self.payloads.setdefault(sha, _Payload())
        p.count += 1
        p.via.add(via)
        p.first_seen = ts if p.first_seen is None or ts < p.first_seen else p.first_seen
        p.last_seen = ts if p.last_seen is None or ts > p.last_seen else p.last_seen

    # ----------------------------------------------------------------- output

    def result(
        self,
        dataset: str = "live",
        publish_prefixes: bool = False,
        generated_at: datetime | None = None,
        attribution: dict | None = None,
    ) -> dict:
        hourly = []
        for i in range(HOURLY_BUCKETS):
            h = self.hour_start + timedelta(hours=i)
            hourly.append(
                {"t": _iso(h), "sessions": self.hourly_sessions[h], "logins": self.hourly_logins[h]}
            )

        daily = []
        day = self.start.date()
        while day <= self.end.date():
            key = day.isoformat()
            daily.append({"d": key, "sessions": self.daily_sessions[key]})
            day += timedelta(days=1)

        recent = sorted(self._recent.items(), key=lambda kv: (kv[1][0], kv[0]), reverse=True)
        recent = recent[: self.recent_n]

        payloads = sorted(
            self.payloads.items(), key=lambda kv: (-kv[1].count, kv[1].first_seen, kv[0])
        )[:20]

        known_countries = {k: v for k, v in self.countries.items() if k != "ZZ"}

        doc = {
            "schema": SCHEMA_VERSION,
            "dataset": dataset,
            "generated_at": _iso(generated_at or datetime.now(UTC)),
            "window": {
                "start": _iso(self.start),
                "end": _iso(self.end),
                "days": self.days,
                "first_event": _iso(self.first) if self.first else None,
                "last_event": _iso(self.last) if self.last else None,
            },
            "totals": {
                "sessions": self.sessions,
                "ssh_sessions": self.protocols.get("ssh", 0),
                "telnet_sessions": self.protocols.get("telnet", 0),
                "login_attempts": self.login_attempts,
                "login_successes": self.login_successes,
                "unique_sources": len(self.sources),
                "countries": len(known_countries),
                "asns": len(self.asns),
                "commands": self.command_count,
                "unique_commands": len(self.commands),
                "payloads": len(self.payloads),
                "downloads_blocked": self.downloads_blocked,
            },
            "hourly": hourly,
            "daily": daily,
            "countries": [
                {"code": c, "name": self.country_names.get(c, c), "sessions": n}
                for c, n in _top(self.countries, len(self.countries))
            ],
            "asns": [
                {"asn": a, "org": self.asn_orgs.get(a, ""), "sessions": n}
                for a, n in _top(self.asns, self.top_n)
            ],
            "usernames": [{"value": v, "count": n} for v, n in _top(self.usernames, self.top_n)],
            "passwords": [{"value": v, "count": n} for v, n in _top(self.passwords, self.top_n)],
            "credentials": [
                {"username": u, "password": p, "count": n} for (u, p), n in _top(self.pairs, 10)
            ],
            "client_versions": [
                {"value": v, "count": n} for v, n in _top(self.client_versions, 10)
            ],
            "commands": [{"value": v, "count": n} for v, n in _top(self.commands, self.top_n)],
            "recent_commands": [
                {"t": _iso(ts.replace(second=0, microsecond=0)), "cmd": cmd, "country": cc}
                for cmd, (ts, cc) in recent
            ],
            "payloads": [
                {
                    "sha256": sha,
                    "count": p.count,
                    "via": sorted(p.via),
                    "first_seen": _iso(p.first_seen),
                    "last_seen": _iso(p.last_seen),
                }
                for sha, p in payloads
            ],
            "attribution": attribution or {},
        }
        if publish_prefixes:
            doc["prefixes"] = [{"prefix": p, "sessions": n} for p, n in _top(self.prefixes, 10)]
        return doc
