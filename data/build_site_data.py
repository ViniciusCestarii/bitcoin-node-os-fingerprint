"""Turn scan-*.csv + enrich-*.csv into the JSON the site's per-scan pages load.

For every scan-YYYY-MM-DD.csv that has a matching enrich-YYYY-MM-DD.csv
next to it, writes <out>/scan-YYYY-MM-DD.json with the reachable nodes
grouped by AS and an OS-by-version summary. Offline: all lookups were
frozen into enrich-*.csv by enrich_scan.py. Used by scripts/build_pages.sh.

    python3 data/build_site_data.py --out _site/data/enriched data/scan-*.csv
"""
import argparse
import csv
import json
import os
import re

# same colours as the overview page; this order keeps orange (Windows) and
# yellow (BSD) apart in stacked bars
OS = ["Linux", "Windows", "Other", "BSD", "macOS", "Android", "Unknown"]
OS_INDEX = {o: i for i, o in enumerate(OS)}
OS_INDEX["Other/Device"] = OS_INDEX["Solaris"] = OS_INDEX["Other"]
SCAN_RE = re.compile(r"scan-(\d{4}-\d{2}-\d{2})\.csv$")


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


def build(scan_path, enrich_path):
    enrich = {(r["ip_address"], r["port"]): r for r in csv.DictReader(open(enrich_path, newline=""))}
    rows = [r for r in csv.DictReader(open(scan_path, newline="")) if r["host_state"] == "reachable"]

    ases, versions, matched = {}, {}, 0
    for r in rows:
        e = enrich[(r["ip_address"], r["port"])]
        i = OS_INDEX.get(r["os_class"], OS_INDEX["Other"])
        asn = int(e["asn"] or 0)
        a = ases.setdefault(asn, {"asn": asn, "cc": e["as_country"] or "ZZ", "name": e["as_name"] or "Unknown AS",
                                  "counts": [0] * len(OS), "nodes": []})
        a["counts"][i] += 1
        a["nodes"].append([r["ip_address"], int(r["port"]), i, int(r["accuracy"] or 0), e["country"] or "ZZ"])
        if e["user_agent"]:
            matched += 1
            versions.setdefault(version_group(e["user_agent"]), [0] * len(OS))[i] += 1

    return {
        "scan": os.path.basename(scan_path),
        "os": OS,
        "reachable": len(rows),
        "ases": sorted(ases.values(), key=lambda a: -len(a["nodes"])),
        "versions": {"matched": matched,
                     "groups": [{"name": n, "counts": versions[n]} for n in sorted(versions, key=version_order)]}
                    if matched else None,
    }


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--out", required=True, help="directory to write one JSON per scan into")
    p.add_argument("scans", nargs="+")
    args = p.parse_args()
    os.makedirs(args.out, exist_ok=True)
    for scan in args.scans:
        m = SCAN_RE.search(scan)
        enrich = os.path.join(os.path.dirname(scan), f"enrich-{m[1]}.csv") if m else None
        if not enrich or not os.path.exists(enrich):
            continue
        data = build(scan, enrich)
        with open(os.path.join(args.out, data["scan"].replace(".csv", ".json")), "w") as f:
            json.dump(data, f, separators=(",", ":"))
        print(f"build_site_data: {data['scan']}: {data['reachable']} reachable, {len(data['ases'])} ASes")


if __name__ == "__main__":
    main()
