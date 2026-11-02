#!/usr/bin/env bash
#
# Build the GitHub Pages output into _site/.
#
# The page needs two things at runtime: the scan CSVs and a list of which
# CSVs exist. Both are produced here instead of being committed, so data/
# stays the single source of truth and the CSVs are never duplicated in git.
#
#   _site/index.html        the page
#   _site/versions.html     OS by node version, per scan
#   _site/as-map.html       OS by autonomous system and country, per scan
#   _site/vendor/           d3 and the country shapes those two pages use
#   _site/data/scan-*.csv   copies of the committed scans
#   _site/data/index.json   generated manifest listing those filenames
#   _site/data/enriched/    per-scan AS, country and version data
#   _site/pages/index.html  redirect, keeps the old /pages/ URL working
#
# The enriched data needs three downloads, cached in $PAGES_CACHE:
# iptoasn.com (AS per IP), DB-IP Lite (country per IP, CC BY 4.0) and the
# btcnodes.io snapshot closest to each scan date (node user agents).
#
# Run locally with: scripts/build_pages.sh && python3 -m http.server -d _site

set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${1:-$REPO_DIR/_site}"

rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR/data" "$OUT_DIR/pages"

cp "$REPO_DIR"/pages/*.html "$OUT_DIR/"
cp -r "$REPO_DIR/pages/vendor" "$OUT_DIR/vendor"

# Only the filtered per-scan CSVs are published; raw scans and the Bitnodes
# node lists are not committed in the first place.
shopt -s nullglob
scans=("$REPO_DIR"/data/scan-*.csv)
shopt -u nullglob

if [ ${#scans[@]} -eq 0 ]; then
    echo "build_pages: no data/scan-*.csv files found" >&2
    exit 1
fi

cp "${scans[@]}" "$OUT_DIR/data/"

# Manifest: replaces the GitHub contents API the page used to list data/ with.
# The page itself decides which of these files it can plot.
{
    printf '{\n  "generated": "%s",\n  "files": [\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    sep=""
    for f in "${scans[@]}"; do
        printf '%s    "%s"' "$sep" "$(basename "$f")"
        sep=$',\n'
    done
    printf '\n  ]\n}\n'
} > "$OUT_DIR/data/index.json"

CACHE_DIR="${PAGES_CACHE:-${TMPDIR:-/tmp}/bitcoin-node-pages-cache}"
mkdir -p "$CACHE_DIR"
IP2ASN="$CACHE_DIR/ip2asn-combined-$(date -u +%Y-%m-%d).tsv.gz"
[ -s "$IP2ASN" ] || curl -fsSL -o "$IP2ASN" https://iptoasn.com/data/ip2asn-combined.tsv.gz
# DB-IP publishes one file per month; early in a month it may not be up yet
DBIP=""
for month in "$(date -u +%Y-%m)" "$(date -u -d "$(date -u +%Y-%m-01) -1 month" +%Y-%m)"; do
    f="$CACHE_DIR/dbip-country-lite-$month.csv.gz"
    if [ -s "$f" ] || curl -fsSL -o "$f" "https://download.db-ip.com/free/dbip-country-lite-$month.csv.gz"; then
        DBIP="$f"
        break
    fi
    rm -f "$f"
done
if [ -z "$DBIP" ]; then
    echo "build_pages: could not download the DB-IP country database" >&2
    exit 1
fi
python3 "$REPO_DIR/data/enrich_scan.py" --ip2asn "$IP2ASN" --dbip "$DBIP" \
    --cache "$CACHE_DIR" --out "$OUT_DIR/data/enriched" "${scans[@]}"

cat > "$OUT_DIR/pages/index.html" <<'HTML'
<!doctype html>
<meta charset="utf-8">
<title>Redirecting</title>
<meta http-equiv="refresh" content="0; url=../">
<link rel="canonical" href="../">
<p>This page moved to <a href="../">the site root</a>.</p>
HTML

echo "build_pages: wrote $OUT_DIR with ${#scans[@]} scan file(s)"
