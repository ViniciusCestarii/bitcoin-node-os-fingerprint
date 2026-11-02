"""Enrich filtered scans with AS, node country and node version for the site.

For each scan-YYYY-MM-DD.csv, writes <out>/scan-YYYY-MM-DD.json with the
reachable nodes grouped by AS (iptoasn.com), each node's country (DB-IP
Lite) and an OS-by-version summary built from the btcnodes.io snapshot
closest to the end of the scan date. Used by scripts/build_pages.sh; the
output is generated at build time and never committed.

    python3 data/enrich_scan.py --ip2asn ip2asn-combined.tsv.gz \
        --dbip dbip-country-lite.csv.gz --cache .cache --out enriched \
        data/scan-*.csv
"""
import argparse
import bisect
import csv
import datetime
import gzip
import ipaddress
import json
import os
import re
import urllib.request
from collections import Counter

SNAPSHOTS_URL = "https://btcnodes.io/api/v1/snapshots/"
# btcnodes.io answers 403 to urllib's default User-Agent
HEADERS = {"User-Agent": "bitcoin-node-os-fingerprint (+https://github.com/ViniciusCestarii/bitcoin-node-os-fingerprint)"}
# same colours as the overview page; this order keeps orange (Windows) and
# yellow (BSD) apart in stacked bars
OS = ["Linux", "Windows", "Other", "BSD", "macOS", "Android", "Unknown"]
OS_INDEX = {o: i for i, o in enumerate(OS)}
OS_INDEX["Other/Device"] = OS_INDEX["Solaris"] = OS_INDEX["Other"]
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
            table.add(start, end, (int(asn), cc, name))
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


def fetch(url):
    return urllib.request.urlopen(urllib.request.Request(url, headers=HEADERS), timeout=120)


def fetch_json(url):
    with fetch(url) as r:
        return json.load(r)


def snapshot_for(date, cache):
    """Latest btcnodes.io snapshot taken on or before the end of `date` (UTC)."""
    day_end = datetime.datetime.fromisoformat(date).replace(tzinfo=datetime.timezone.utc) + datetime.timedelta(days=1)
    target = int(day_end.timestamp())
    index_path = os.path.join(cache, f"snapshot-for-{date}.txt")
    if os.path.exists(index_path):
        ts = open(index_path).read().strip()
    else:
        # the list is newest first, 100 per page and has no date filter:
        # binary search for the first page whose oldest entry is <= target
        limit = 100
        first = fetch_json(f"{SNAPSHOTS_URL}?page=1&limit={limit}")
        lo, hi = 1, -(-first["count"] // limit)
        page = None
        while lo <= hi:
            mid = (lo + hi) // 2
            res = first["results"] if mid == 1 else fetch_json(f"{SNAPSHOTS_URL}?page={mid}&limit={limit}")["results"]
            if res[-1]["timestamp"] <= target:
                page, hi = res, mid - 1
            else:
                lo = mid + 1
        hit = next((s for s in page or [] if s["timestamp"] <= target), None)
        ts = str(hit["timestamp"]) if hit else ""
        with open(index_path, "w") as f:
            f.write(ts)
    if not ts:
        return None
    path = os.path.join(cache, f"snapshot-{ts}.json")
    if not os.path.exists(path):
        with fetch(f"{SNAPSHOTS_URL}{ts}/") as r, open(path + ".part", "wb") as f:
            f.write(r.read())
        os.replace(path + ".part", path)
    return json.load(open(path))


def version_group(ua):
    if "Knots" in ua:
        return "Knots"
    if "FutureBit-Apollo" in ua:
        return "FutureBit Apollo"
    m = re.fullmatch(r"/Satoshi:(\d+)\.\d+[\d.]*/", ua)
    if not m:
        return "Other software"
    major = int(m[1])
    if major == 0:
        return "Core 0.x"
    if major <= 24:
        return "Core 22-24"
    return f"Core {major}"


def version_order(name):
    fixed = {"Core 0.x": (0, 0), "Core 22-24": (0, 24), "Knots": (2, 0), "FutureBit Apollo": (2, 1), "Other software": (2, 2)}
    return fixed.get(name) or (1, int(name.split()[1]))


def enrich(scan_path, ip2asn, dbip, cache):
    date = SCAN_RE.search(scan_path)[1]
    rows = [r for r in csv.DictReader(open(scan_path, newline="")) if r["host_state"] == "reachable"]

    ases = {}
    for r in rows:
        asn, cc, name = ip2asn.get(r["ip_address"]) or (0, "ZZ", "Unknown AS")
        a = ases.setdefault(asn, {"asn": asn, "cc": cc, "name": short_as_name(name), "counts": [0] * len(OS), "nodes": []})
        i = OS_INDEX.get(r["os_class"], OS_INDEX["Other"])
        a["counts"][i] += 1
        a["nodes"].append([r["ip_address"], int(r["port"]), i, int(r["accuracy"] or 0), dbip.get(r["ip_address"]) or "ZZ"])

    versions = None
    try:
        snap = snapshot_for(date, cache)
    except OSError as e:
        # btcnodes.io being down should not take the site down
        print(f"enrich_scan: {scan_path}: snapshot unavailable ({e}), skipping versions")
        snap = None
    if snap:
        ua = {}
        for addr, v in snap["nodes"].items():
            host, port = addr.rsplit(":", 1)
            ua[(host.strip("[]"), port)] = v[1]
        groups = {}
        matched = 0
        for r in rows:
            agent = ua.get((r["ip_address"], r["port"]))
            if agent is None:
                continue
            matched += 1
            groups.setdefault(version_group(agent), Counter())[r["os_class"]] += 1
        rows_out = []
        for name in sorted(groups, key=version_order):
            c = groups[name]
            counts = [0] * len(OS)
            for cls, n in c.items():
                counts[OS_INDEX.get(cls, OS_INDEX["Other"])] += n
            rows_out.append({"name": name, "counts": counts})
        versions = {"snapshot": snap["timestamp"], "matched": matched, "groups": rows_out}

    return {
        "scan": os.path.basename(scan_path),
        "date": date,
        "os": OS,
        "reachable": len(rows),
        "ases": sorted(ases.values(), key=lambda a: -len(a["nodes"])),
        "versions": versions,
    }


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--ip2asn", required=True, help="ip2asn-combined.tsv.gz from iptoasn.com")
    p.add_argument("--dbip", required=True, help="dbip-country-lite-*.csv.gz from db-ip.com")
    p.add_argument("--cache", required=True, help="directory for downloaded btcnodes.io snapshots")
    p.add_argument("--out", required=True, help="directory to write one JSON per scan into")
    p.add_argument("scans", nargs="+")
    args = p.parse_args()
    os.makedirs(args.cache, exist_ok=True)
    os.makedirs(args.out, exist_ok=True)

    ip2asn, dbip = load_ip2asn(args.ip2asn), load_dbip(args.dbip)
    for scan in args.scans:
        if not SCAN_RE.search(scan):
            continue
        data = enrich(scan, ip2asn, dbip, args.cache)
        out = os.path.join(args.out, data["scan"].replace(".csv", ".json"))
        with open(out, "w") as f:
            json.dump(data, f, separators=(",", ":"))
        v = data["versions"]
        print(f"enrich_scan: {data['scan']}: {data['reachable']} reachable, {len(data['ases'])} ASes, "
              + (f"{v['matched']} matched to snapshot {v['snapshot']}" if v else "no snapshot"))


if __name__ == "__main__":
    main()
