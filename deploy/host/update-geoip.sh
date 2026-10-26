#!/usr/bin/env bash
# Download the current DB-IP Lite country and ASN databases (CC BY 4.0).
# DB-IP publishes a new build monthly; falls back to last month early in the month.
# Usage: update-geoip.sh [target_dir]   (default /opt/honeypot/data/geoip)
set -euo pipefail

DEST="${1:-/opt/honeypot/data/geoip}"
mkdir -p "$DEST"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

fetch() {
  local kind="$1" month
  for month in "$(date -u +%Y-%m)" "$(date -u -d "$(date -u +%Y-%m-01) -1 month" +%Y-%m)"; do
    if curl -fsSL --retry 3 -o "$tmp/$kind.mmdb.gz" \
        "https://download.db-ip.com/free/dbip-$kind-lite-$month.mmdb.gz"; then
      gunzip -f "$tmp/$kind.mmdb.gz"
      # Swap in atomically so the collector never opens a half-written file.
      install -m 0644 "$tmp/$kind.mmdb" "$DEST/.dbip-$kind-lite.mmdb.new"
      mv -f "$DEST/.dbip-$kind-lite.mmdb.new" "$DEST/dbip-$kind-lite.mmdb"
      echo "dbip-$kind-lite $month -> $DEST"
      return 0
    fi
  done
  echo "could not download dbip-$kind-lite" >&2
  return 1
}

fetch country
fetch asn
