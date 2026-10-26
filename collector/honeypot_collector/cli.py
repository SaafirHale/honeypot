"""Command-line entry point: python -m honeypot_collector --logs ... --out stats.json"""

from __future__ import annotations

import argparse
import ipaddress
import json
import logging
import os
import re
import sys
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path

from .aggregate import Aggregator
from .events import ReadStats, expand_paths, iter_events, parse_ts
from .geo import MmdbGeo, NullGeo

log = logging.getLogger("honeypot_collector")

# A full dotted quad that is not the network part of a CIDR (1.2.3.0/24 is allowed).
_FULL_IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d./])")


class PrivacyError(RuntimeError):
    pass


def assert_publishable(doc: dict) -> str:
    """Serialise and refuse to publish anything that still carries a full IPv4 address."""
    text = json.dumps(doc, ensure_ascii=False, indent=1)
    hit = _FULL_IPV4.search(text)
    if hit:
        raise PrivacyError(f"refusing to publish: full IPv4 address in output near {hit.start()}")
    return text


def write_atomic(path: Path, text: str) -> None:
    """Write to a temp file in the same directory, then rename, so readers never see half a file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".stats-", suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
            fh.write("\n")
        os.chmod(tmp, 0o644)
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def _env_list(name: str) -> list[str]:
    return [v.strip() for v in os.environ.get(name, "").split(",") if v.strip()]


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="honeypot_collector",
        description="Aggregate Cowrie JSON logs into an anonymised stats.json.",
    )
    p.add_argument("--logs", nargs="+", type=Path, required=True,
                   help="Cowrie log directory or cowrie.json files (rotations and .gz included).")
    p.add_argument("--out", type=Path, required=True, help="Where to write stats.json.")
    p.add_argument("--country-db", type=Path, help="DB-IP Lite country MMDB.")
    p.add_argument("--asn-db", type=Path, help="DB-IP Lite ASN MMDB.")
    p.add_argument("--days", type=int, default=30, help="Window length in days (default 30).")
    p.add_argument("--end", help="Window end, ISO 8601. Default: now. Use 'last-event' for samples.")
    p.add_argument("--dataset", default="live",
                   help="Label shown on the dashboard: live, sample, local-test.")
    p.add_argument("--exclude", action="append", default=_env_list("HP_EXCLUDE"), metavar="CIDR",
                   help="Drop all events from this network (your admin IP). Repeatable. "
                        "Also read from HP_EXCLUDE (comma-separated).")
    p.add_argument("--publish-prefixes", action="store_true",
                   help="Also publish the top source /24 networks. Off by default.")
    p.add_argument("--interval", type=int, default=0,
                   help="Seconds between runs. 0 = run once and exit.")
    p.add_argument("-v", "--verbose", action="store_true")
    return p


def _resolve_end(arg: str | None, paths: list[Path]) -> datetime:
    if not arg:
        return datetime.now(UTC)
    if arg == "last-event":
        last = None
        for e in iter_events(paths):
            ts = parse_ts(e.get("timestamp"))
            if ts and (last is None or ts > last):
                last = ts
        return last or datetime.now(UTC)
    ts = parse_ts(arg)
    if ts is None:
        raise SystemExit(f"--end: not an ISO 8601 timestamp: {arg}")
    return ts


def run_once(args: argparse.Namespace, geo) -> dict:
    paths = expand_paths(args.logs)
    end = _resolve_end(args.end, paths)
    exclude = [ipaddress.ip_network(c, strict=False) for c in args.exclude]
    read = ReadStats()
    agg = Aggregator(geo=geo, end=end, days=args.days, exclude=exclude)
    agg.add_all(iter_events(paths, read))

    attribution = {}
    if isinstance(geo, MmdbGeo):
        attribution = {
            "geoip": "IP geolocation by DB-IP (https://db-ip.com), CC BY 4.0",
            "geoip_builds": geo.database_dates(),
        }
    doc = agg.result(
        dataset=args.dataset, publish_prefixes=args.publish_prefixes, attribution=attribution
    )
    text = assert_publishable(doc)
    write_atomic(args.out, text)
    log.info(
        "wrote %s: %d files, %d lines (%d skipped), %d events in window, %d excluded, %d sessions",
        args.out, read.files, read.lines, read.skipped, agg.events_in_window,
        agg.events_excluded, agg.sessions,
    )
    return doc


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        stream=sys.stderr,
    )
    geo = MmdbGeo(args.country_db, args.asn_db) if (args.country_db or args.asn_db) else NullGeo()
    if args.interval <= 0:
        run_once(args, geo)
        return 0
    while True:
        try:
            run_once(args, geo)
        except PrivacyError:
            log.exception("output withheld")
        except Exception:  # keep the loop alive; the next run may succeed
            log.exception("collector run failed")
        time.sleep(args.interval)


if __name__ == "__main__":
    raise SystemExit(main())
