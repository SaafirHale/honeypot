import json

import pytest

from honeypot_collector import cli

from .conftest import REPO, session_events, write_jsonl

COUNTRY_DB = REPO / "data" / "geoip" / "dbip-country-lite.mmdb"
ASN_DB = REPO / "data" / "geoip" / "dbip-asn-lite.mmdb"
SYNTHETIC = REPO / "samples" / "synthetic"
LOCAL_DOCKER = REPO / "samples" / "local-docker"


def test_run_once_writes_stats_atomically(tmp_path):
    logs = write_jsonl(
        tmp_path / "logs" / "cowrie.json",
        session_events("203.0.113.5", "s1", "2026-10-25T10:00:00Z", commands=["id"]),
    )
    out = tmp_path / "public" / "stats.json"
    assert cli.main(["--logs", str(logs.parent), "--out", str(out),
                     "--end", "2026-10-25T12:00:00Z", "--dataset", "local-test"]) == 0
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["schema"] == 1
    assert doc["dataset"] == "local-test"
    assert doc["totals"]["sessions"] == 1
    assert [p.name for p in out.parent.iterdir()] == ["stats.json"]  # no temp files left


def test_end_last_event(tmp_path):
    logs = write_jsonl(tmp_path / "cowrie.json",
                       session_events("203.0.113.5", "s1", "2024-01-02T03:04:05Z"))
    out = tmp_path / "stats.json"
    cli.main(["--logs", str(logs), "--out", str(out), "--end", "last-event", "--days", "1"])
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["window"]["end"] == "2024-01-02T03:04:05Z"
    assert doc["totals"]["sessions"] == 1


def test_exclude_flag(tmp_path):
    logs = write_jsonl(tmp_path / "cowrie.json",
                       session_events("203.0.113.5", "s1", "2026-10-25T10:00:00Z"))
    out = tmp_path / "stats.json"
    cli.main(["--logs", str(logs), "--out", str(out), "--end", "2026-10-25T12:00:00Z",
              "--exclude", "203.0.113.0/24"])
    assert json.loads(out.read_text(encoding="utf-8"))["totals"]["sessions"] == 0


def test_exclude_from_environment(tmp_path, monkeypatch):
    logs = write_jsonl(tmp_path / "cowrie.json",
                       session_events("203.0.113.5", "s1", "2026-10-25T10:00:00Z")
                       + session_events("198.51.100.5", "s2", "2026-10-25T10:00:00Z"))
    out = tmp_path / "stats.json"
    monkeypatch.setenv("HP_EXCLUDE", "203.0.113.0/24, 198.51.100.5/32")
    cli.main(["--logs", str(logs), "--out", str(out), "--end", "2026-10-25T12:00:00Z"])
    assert json.loads(out.read_text(encoding="utf-8"))["totals"]["sessions"] == 0


def test_privacy_guard_blocks_full_ipv4():
    with pytest.raises(cli.PrivacyError):
        cli.assert_publishable({"oops": "seen from 198.51.100.7"})
    # CIDR network addresses and redacted forms are allowed.
    cli.assert_publishable({"ok": ["198.51.100.0/24", "198.51.100.x", "SSH-2.0-OpenSSH_9.2p1"]})


def test_privacy_guard_leaves_previous_file_untouched(tmp_path, monkeypatch):
    logs = write_jsonl(tmp_path / "cowrie.json",
                       session_events("203.0.113.5", "s1", "2026-10-25T10:00:00Z"))
    out = tmp_path / "stats.json"
    out.write_text('{"previous": true}', encoding="utf-8")
    monkeypatch.setattr(cli.Aggregator, "result",
                        lambda self, **kw: {"leak": "203.0.113.5"})
    with pytest.raises(cli.PrivacyError):
        cli.main(["--logs", str(logs), "--out", str(out), "--end", "2026-10-25T12:00:00Z"])
    assert json.loads(out.read_text(encoding="utf-8")) == {"previous": True}


@pytest.mark.skipif(not SYNTHETIC.exists(), reason="synthetic sample not generated")
def test_synthetic_sample_end_to_end(tmp_path):
    out = tmp_path / "stats.json"
    cli.main(["--logs", str(SYNTHETIC), "--out", str(out), "--end", "last-event",
              "--days", "14", "--dataset", "sample"])
    doc = json.loads(out.read_text(encoding="utf-8"))
    t = doc["totals"]
    assert t["sessions"] == 3000
    assert t["ssh_sessions"] + t["telnet_sessions"] == 3000
    assert t["login_attempts"] >= t["sessions"]
    assert len(doc["hourly"]) == 168
    assert doc["payloads"] and all(len(p["sha256"]) == 64 for p in doc["payloads"])
    assert all("http://" not in c["value"] for c in doc["commands"])


@pytest.mark.skipif(not COUNTRY_DB.exists(), reason="DB-IP Lite not downloaded")
def test_real_dbip_lookup():
    from honeypot_collector.geo import MmdbGeo

    geo = MmdbGeo(COUNTRY_DB, ASN_DB)
    g = geo.lookup("8.8.8.8")
    assert g.country_code == "US"
    assert g.asn == 15169
    assert geo.lookup("10.0.0.1").country_code == "ZZ"  # private space is never looked up
    assert geo.lookup("garbage").country_code == "ZZ"
    assert set(geo.database_dates()) == {"country", "asn"}


@pytest.mark.skipif(not (LOCAL_DOCKER / "cowrie.json").exists(),
                    reason="no captured local Cowrie log")
def test_real_cowrie_log_from_local_container(tmp_path):
    """Logs written by an actual Cowrie container under scripted local attack traffic."""
    out = tmp_path / "stats.json"
    cli.main(["--logs", str(LOCAL_DOCKER), "--out", str(out), "--end", "last-event",
              "--days", "2", "--dataset", "local-test"])
    doc = json.loads(out.read_text(encoding="utf-8"))
    t = doc["totals"]
    assert t["sessions"] > 0
    assert t["ssh_sessions"] > 0 and t["telnet_sessions"] > 0
    assert t["login_attempts"] > 0 and t["login_successes"] > 0
    assert t["commands"] > 0
