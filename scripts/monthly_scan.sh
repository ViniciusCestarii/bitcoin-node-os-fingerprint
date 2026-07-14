#!/usr/bin/env bash
#
# Monthly cronjob: download the current Bitnodes CSV, run the OS
# fingerprint scan, filter/classify it, and push the new scan data.
#
# Suggested crontab entry (runs at 03:00 on the 1st of every month,
# one log file per month; note the escaped % in crontab):
#   0 3 1 * * /path/to/os-fingerprinting-bitcoin-nodes/scripts/monthly_scan.sh >> /var/log/bitcoin-node-scan-$(date +\%Y-\%m).log 2>&1
#
# SECURITY: os_fingerprint.py needs root (raw-socket OS detection), so the
# scan step runs inside a Docker container instead of granting the host
# passwordless sudo. Root there is root in a throwaway container, not on
# the host. The container still needs --network host plus NET_RAW/NET_ADMIN
# capabilities to do raw-socket scanning, so it isn't fully locked down,
# but it can't touch anything else on the host filesystem or the repo's
# git credentials. Only the download and git push run on the host, with
# your normal user permissions.

set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DATA_DIR="$REPO_DIR/data"
DATE="$(date +%F)"

IMAGE_NAME="bitcoin-node-scanner"
NODES_URL="https://bitnod.es/csv/bitcoin_nodes_${DATE}.csv"

NODES_CSV="$DATA_DIR/bitcoin_nodes-${DATE}.csv"
RAW_SCAN_CSV="$DATA_DIR/raw-scan-${DATE}.csv"
FILTERED_SCAN_CSV="$DATA_DIR/scan-${DATE}.csv"

# bitnod.es may not have published today's CSV yet at the time cron fires
# or may be offline, so retry with backoff instead of failing outright.
MAX_ATTEMPTS=12
RETRY_DELAY=1800 # 30 minutes

cd "$REPO_DIR"
git checkout master
git pull --rebase

echo "[$DATE] Downloading node list from $NODES_URL"
attempt=1
until curl -fsSL -o "$NODES_CSV" "$NODES_URL"; do
    if [ "$attempt" -ge "$MAX_ATTEMPTS" ]; then
        echo "[$DATE] Gave up after $attempt attempts: $NODES_URL not available"
        rm -f "$NODES_CSV"
        exit 1
    fi
    echo "[$DATE] Attempt $attempt failed, retrying in ${RETRY_DELAY}s"
    attempt=$((attempt + 1))
    sleep "$RETRY_DELAY"
done

echo "[$DATE] Building scanner image"
docker build -t "$IMAGE_NAME" "$REPO_DIR"

echo "[$DATE] Running OS fingerprint scan in container"
docker run --rm \
    --network host \
    --cap-add NET_RAW \
    --cap-add NET_ADMIN \
    -v "$DATA_DIR:/app/data" \
    "$IMAGE_NAME" \
    os_fingerprint.py "/app/data/$(basename "$NODES_CSV")" --out "/app/data/$(basename "$RAW_SCAN_CSV")"

echo "[$DATE] Filtering scan in container"
docker run --rm \
    -v "$DATA_DIR:/app/data" \
    "$IMAGE_NAME" \
    data/filter_scan.py "/app/data/$(basename "$RAW_SCAN_CSV")" "/app/data/$(basename "$FILTERED_SCAN_CSV")"

echo "[$DATE] Committing and pushing results"
git add "$FILTERED_SCAN_CSV"
git commit -m "[AUTO] add new scan scan-${DATE}.csv"
git pull --rebase
git push

echo "[$DATE] Done"
