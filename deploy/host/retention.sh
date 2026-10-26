#!/usr/bin/env bash
# Prune old Cowrie data from the named volume. Run daily from cron.
#   rotated JSON logs   older than LOG_DAYS (default 45; the dashboard window is 30)
#   tty transcripts     older than TTY_DAYS (default 14)
#   captured payloads   older than PAYLOAD_DAYS (default 14)
# Payload files are live malware. They exist only so hashes can be computed;
# nothing copies them off the box.
set -euo pipefail

LOG_DAYS="${LOG_DAYS:-45}"
TTY_DAYS="${TTY_DAYS:-14}"
PAYLOAD_DAYS="${PAYLOAD_DAYS:-14}"
VOLUME="${COWRIE_VOLUME:-honeypot_cowrie-var}"

root="$(docker volume inspect -f '{{ .Mountpoint }}' "$VOLUME")"
[ -d "$root" ] || { echo "volume $VOLUME not found" >&2; exit 1; }

find "$root/log/cowrie" -maxdepth 1 -type f -name 'cowrie.json.*' -mtime +"$LOG_DAYS" -print -delete
find "$root/log/cowrie" -maxdepth 1 -type f -name 'cowrie.log.*' -mtime +"$LOG_DAYS" -print -delete
find "$root/lib/cowrie/tty" -type f -mtime +"$TTY_DAYS" -print -delete 2>/dev/null || true
find "$root/lib/cowrie/downloads" -type f -mtime +"$PAYLOAD_DAYS" -print -delete 2>/dev/null || true

# Compress rotated JSON older than a day; the collector reads .gz directly.
find "$root/log/cowrie" -maxdepth 1 -type f -name 'cowrie.json.*' ! -name '*.gz' -mtime +1 \
  -exec gzip -9 {} \;
