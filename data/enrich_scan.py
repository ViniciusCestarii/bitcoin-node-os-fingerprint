"""Freeze AS, node country and node version for one filtered scan.

Writes data/enrich-YYYY-MM-DD.csv with one row per reachable node of
scan-YYYY-MM-DD.csv. Run once, when the scan is made, so the lookups
describe the network as it was then instead of whatever the databases say
at a later build:

    python3 data/enrich_scan.py data/scan-2026-11-01.csv data/enrich-2026-11-01.csv \
        --ip2asn ip2asn-combined.tsv.gz --dbip dbip-country-lite-2026-11.csv.gz \
        --snapshot nodes-snapshot-2026-11-01.json

  --ip2asn    https://iptoasn.com/data/ip2asn-combined.tsv.gz (AS per IP)
  --dbip      https://download.db-ip.com/free/dbip-country-lite-YYYY-MM.csv.gz
              (country per IP, CC BY 4.0)
  --snapshot  the btcnodes.io snapshot the scan's node list came from, for
              user agents. Without it, the latest snapshot taken before the
              end of the scan date is downloaded (for backfilling old scans).
"""
import argparse
import bisect
import csv
import datetime
import gzip
import ipaddress
import json
import re
import urllib.request

SNAPSHOTS_URL = "https://btcnodes.io/api/v1/snapshots/"
# btcnodes.io answers 403 to urllib's default User-Agent
HEADERS = {"User-Agent": "bitcoin-node-os-fingerprint (+https://github.com/ViniciusCestarii/bitcoin-node-os-fingerprint)"}
SCAN_RE = re.compile(r"scan-(\d{4}-\d{2}-\d{2})\.csv$")


def ip_key(ip):
    # one sorted keyspace for both families: IPv6 sorts after all of IPv4
    a = ipaddress.ip_address(ip)
    return int(a) + (a.version == 6) * (1 << 128)


class RangeTable:
    def __init__(self):
        self.starts, self.ends, self.values = [], [], []

    def add(self, start, end, value):
        self.starts.append(ip_key(start))
        self.ends.append(ip_key(end))
        self.values.append(value)

    def get(self, ip):
        k = ip_key(ip)
        i = bisect.bisect_right(self.starts, k) - 1
        return self.values[i] if i >= 0 and k <= self.ends[i] else None


def load_ip2asn(path):
    table = RangeTable()
    for line in gzip.open(path, "rt"):
        start, end, asn, cc, name = line.rstrip("\n").split("\t")
        if asn != "0":
            table.add(start, end, (asn, cc, name))
    return table


def load_dbip(path):
    table = RangeTable()
    for line in gzip.open(path, "rt"):
        start, end, cc = line.rstrip("\n").split(",")
        table.add(start, end, cc)
    return table


def short_as_name(name):
    # "HETZNER-AS Hetzner Online GmbH" -> "Hetzner Online GmbH"
    return re.sub(r"^[A-Z0-9_-]+( -)? (?=\S)", "", name)


def fetch_json(url):
    with urllib.request.urlopen(urllib.request.Request(url, headers=HEADERS), timeout=120) as r:
        return json.load(r)


def download_snapshot(date):
    """Latest btcnodes.io snapshot taken before the end of `date` (UTC)."""
    day_end = datetime.datetime.fromisoformat(date).replace(tzinfo=datetime.timezone.utc) + datetime.timedelta(days=1)
    target = int(day_end.timestamp())
    # the list is newest first, 100 per page and has no date filter:
    # binary search for the first page whose oldest entry is before target
    limit = 100
    first = fetch_json(f"{SNAPSHOTS_URL}?page=1&limit={limit}")
    lo, hi, page = 1, -(-first["count"] // limit), None
    while lo <= hi:
        mid = (lo + hi) // 2
        res = first["results"] if mid == 1 else fetch_json(f"{SNAPSHOTS_URL}?page={mid}&limit={limit}")["results"]
        if res[-1]["timestamp"] < target:
            page, hi = res, mid - 1
        else:
            lo = mid + 1
    hit = next((s for s in page or [] if s["timestamp"] < target), None)
    if not hit:
        raise SystemExit(f"enrich_scan: btcnodes.io has no snapshot before the end of {date}")
    return fetch_json(f"{SNAPSHOTS_URL}{hit['timestamp']}/")


def main():
    p = argparse.ArgumentParser()
    p.add_argument("scan_csv", help="filtered scan-YYYY-MM-DD.csv")
    p.add_argument("out_csv", help="enrich-YYYY-MM-DD.csv to write")
    p.add_argument("--ip2asn", required=True)
    p.add_argument("--dbip", required=True)
    p.add_argument("--snapshot", help="btcnodes.io snapshot JSON the scan was made from")
    args = p.parse_args()

    snap = json.load(open(args.snapshot)) if args.snapshot else download_snapshot(SCAN_RE.search(args.scan_csv)[1])
    agents = {}
    for addr, v in snap["nodes"].items():
        host, port = addr.rsplit(":", 1)
        agents[(host.strip("[]"), port)] = v[1]
    ip2asn, dbip = load_ip2asn(args.ip2asn), load_dbip(args.dbip)

    reachable = matched = 0
    with open(args.scan_csv, newline="") as fin, open(args.out_csv, "w", newline="") as fout:
        w = csv.writer(fout)
        w.writerow(["ip_address", "port", "asn", "as_name", "as_country", "country", "user_agent"])
        for r in csv.DictReader(fin):
            if r["host_state"] != "reachable":
                continue
            asn, as_cc, as_name = ip2asn.get(r["ip_address"]) or ("", "", "")
            agent = agents.get((r["ip_address"], r["port"]), "")
            reachable += 1
            matched += bool(agent)
            w.writerow([r["ip_address"], r["port"], asn, short_as_name(as_name), as_cc,
                        dbip.get(r["ip_address"]) or "", agent])
    print(f"enrich_scan: {args.out_csv}: {reachable} reachable, {matched} with a user agent "
          f"(snapshot {snap['timestamp']})")


if __name__ == "__main__":
    main()
