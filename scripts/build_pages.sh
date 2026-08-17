#!/usr/bin/env bash
#
# Build the GitHub Pages output into _site/.
#
# The page needs two things at runtime: the scan CSVs and a list of which
# CSVs exist. Both are produced here instead of being committed, so data/
# stays the single source of truth and the CSVs are never duplicated in git.
#
#   _site/index.html        the page
#   _site/data/scan-*.csv   copies of the committed scans
#   _site/data/index.json   generated manifest listing those filenames
#   _site/pages/index.html  redirect, keeps the old /pages/ URL working
#
# Run locally with: scripts/build_pages.sh && python3 -m http.server -d _site

set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${1:-$REPO_DIR/_site}"

rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR/data" "$OUT_DIR/pages"

cp "$REPO_DIR/pages/index.html" "$OUT_DIR/index.html"

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

cat > "$OUT_DIR/pages/index.html" <<'HTML'
<!doctype html>
<meta charset="utf-8">
<title>Redirecting</title>
<meta http-equiv="refresh" content="0; url=../">
<link rel="canonical" href="../">
<p>This page moved to <a href="../">the site root</a>.</p>
HTML

echo "build_pages: wrote $OUT_DIR with ${#scans[@]} scan file(s)"
