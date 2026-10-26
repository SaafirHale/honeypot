"""Offline IP enrichment from DB-IP Lite (MMDB format, CC BY 4.0).

The lookups never leave the box: no API calls, no rate limits, and attacker
addresses are not sent to a third party.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Protocol

UNKNOWN_COUNTRY = ("ZZ", "Unknown")


@dataclass(frozen=True)
class GeoInfo:
    country_code: str
    country_name: str
    asn: int | None
    as_org: str | None


class GeoLookup(Protocol):
    def lookup(self, ip: str) -> GeoInfo: ...


class NullGeo:
    """Used when no database is configured. Everything is Unknown."""

    def lookup(self, ip: str) -> GeoInfo:
        return GeoInfo(*UNKNOWN_COUNTRY, None, None)


class MmdbGeo:
    def __init__(self, country_db: Path | None, asn_db: Path | None) -> None:
        import maxminddb  # imported here so tests and NullGeo do not need it

        self._country = maxminddb.open_database(str(country_db)) if country_db else None
        self._asn = maxminddb.open_database(str(asn_db)) if asn_db else None
        self.lookup = lru_cache(maxsize=65536)(self._lookup)  # type: ignore[method-assign]

    def _lookup(self, ip: str) -> GeoInfo:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return GeoInfo(*UNKNOWN_COUNTRY, None, None)
        if not addr.is_global:
            return GeoInfo(*UNKNOWN_COUNTRY, None, None)

        code, name = UNKNOWN_COUNTRY
        if self._country is not None:
            rec = self._country.get(str(addr)) or {}
            country = rec.get("country") or {}
            if country.get("iso_code"):
                code = country["iso_code"]
                name = (country.get("names") or {}).get("en", code)

        asn = org = None
        if self._asn is not None:
            rec = self._asn.get(str(addr)) or {}
            asn = rec.get("autonomous_system_number")
            org = rec.get("autonomous_system_organization")
        return GeoInfo(code, name, asn, org)

    def database_dates(self) -> dict[str, str]:
        """Build dates of the loaded databases, for the attribution line."""
        import datetime as dt

        out = {}
        for key, db in (("country", self._country), ("asn", self._asn)):
            if db is not None:
                epoch = db.metadata().build_epoch
                out[key] = dt.datetime.fromtimestamp(epoch, dt.UTC).date().isoformat()
        return out
