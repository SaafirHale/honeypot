import gzip
import json
from datetime import UTC, datetime

from honeypot_collector.events import ReadStats, expand_paths, iter_events, parse_ts

from .conftest import ev, write_jsonl


def test_malformed_lines_are_skipped_not_fatal(tmp_path):
    good = ev("cowrie.session.connect", "2026-10-25T10:00:00Z")
    path = write_jsonl(
        tmp_path / "cowrie.json",
        [good],
        extra_lines=["{not json", "[1,2,3]", '{"no_eventid": true}', '{"eventid": "x", "trunc'],
    )
    stats = ReadStats()
    events = list(iter_events([path], stats))
    assert events == [good]
    assert stats.skipped == 4
    assert stats.lines == 5


def test_directory_expands_to_rotations_and_gzip(tmp_path):
    a = ev("cowrie.session.connect", "2026-10-24T10:00:00Z", session="a")
    b = ev("cowrie.session.connect", "2026-10-25T10:00:00Z", session="b")
    c = ev("cowrie.session.connect", "2026-10-23T10:00:00Z", session="c")
    write_jsonl(tmp_path / "cowrie.json", [b])
    write_jsonl(tmp_path / "cowrie.json.2026-10-24", [a])
    with gzip.open(tmp_path / "cowrie.json.2026-10-23.gz", "wt", encoding="utf-8") as fh:
        fh.write(json.dumps(c) + "\n")
    (tmp_path / "cowrie.log").write_text("not the json log\n")
    (tmp_path / "tty").mkdir()

    paths = expand_paths([tmp_path])
    assert [p.name for p in paths] == [
        "cowrie.json",
        "cowrie.json.2026-10-23.gz",
        "cowrie.json.2026-10-24",
    ]
    assert {e["session"] for e in iter_events(paths)} == {"a", "b", "c"}


def test_missing_paths_are_ignored(tmp_path):
    assert expand_paths([tmp_path / "nope"]) == []


def test_parse_ts_variants():
    want = datetime(2026, 10, 26, 3, 8, 22, 134687, tzinfo=UTC)
    assert parse_ts("2026-10-26T03:08:22.134687Z") == want
    assert parse_ts("2026-10-26T03:08:22.134687+00:00") == want
    assert parse_ts("2026-10-26T05:08:22.134687+02:00") == want
    assert parse_ts("2026-10-26T03:08:22.134687") == want  # naive -> UTC
    assert parse_ts("yesterday") is None
    assert parse_ts(1729911702) is None
    assert parse_ts(None) is None
