import argparse
import concurrent.futures
import csv
import ipaddress
import subprocess
from collections import defaultdict
import xml.etree.ElementTree as ET


def ip_version(address):
    try:
        return ipaddress.ip_address(address).version
    except ValueError:
        return None


def group_by_port(csv_file):
    groups = defaultdict(lambda: {4: set(), 6: set()})
    with open(csv_file, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            version = ip_version(row["ip_address"])
            if version is None:
                continue
            groups[row["port"]][version].add(row["ip_address"])
    return groups


def run_nmap(ip, port, host_timeout, ipv6=False):
    cmd = [
        "nmap", "-O", "--osscan-guess", "-T4",
        "-PS" + str(port),
        "--host-timeout", host_timeout,
        "-p", port, "-oX", "-", ip,
    ]
    if ipv6:
        cmd.insert(2, "-6")
        cmd.append("--send-eth")
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    return result.stdout


def extraports_state(host):
    extraports = host.find("ports/extraports")
    if extraports is None:
        return "", ""
    reason = ""
    extrareasons = extraports.find("extrareasons")
    if extrareasons is not None:
        reason = extrareasons.get("reason", "")
    return extraports.get("state", ""), reason


def xml_to_row(xml_output, ip, port):
    if not xml_output.strip():
        return [ip, port, "", "", "no-response", "", ""]

    root = ET.fromstring(xml_output)
    host = root.find("host")
    if host is None:
        return [ip, port, "", "", "down", "", ""]

    status = host.find("status")
    host_state = status.get("state") if status is not None else ""

    ports_by_id = {p.get("portid"): p for p in host.findall("ports/port")}

    port_state, port_reason = "", ""
    if str(port) in ports_by_id:
        state = ports_by_id[str(port)].find("state")
        port_state, port_reason = state.get("state"), state.get("reason")
    else:
        port_state, port_reason = extraports_state(host)

    osmatch = host.find("os/osmatch")
    name = osmatch.get("name") if osmatch is not None else ""
    accuracy = osmatch.get("accuracy") if osmatch is not None else ""

    return [ip, port, name, accuracy, host_state, port_state, port_reason]


CSV_HEADER = [
    "ip_address", "port", "os_name", "accuracy",
    "host_state", "port_state", "port_reason",
]


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("csv_file")
    parser.add_argument("--out")
    parser.add_argument("--host-timeout", default="60s")
    parser.add_argument("--concurrency", type=int, default=4)
    args = parser.parse_args()

    groups = group_by_port(args.csv_file)

    targets = []
    for port, ips in groups.items():
        for ip in ips[4]:
            targets.append((ip, port, False))
        for ip in ips[6]:
            targets.append((ip, port, True))

    print(f"{len(targets)} total targets to scan, concurrency={args.concurrency}")

    with open(args.out, "w", newline="") as out_file:
        writer = csv.writer(out_file)
        writer.writerow(CSV_HEADER)

        completed = 0
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrency) as executor:
            futures = {
                executor.submit(run_nmap, ip, port, args.host_timeout, ipv6): (ip, port)
                for ip, port, ipv6 in targets
            }
            for future in concurrent.futures.as_completed(futures):
                ip, port = futures[future]
                xml_output = future.result()
                writer.writerow(xml_to_row(xml_output, ip, port))
                out_file.flush()
                completed += 1
                if completed % 100 == 0:
                    print(f"{completed}/{len(targets)} done")

    print(f"{completed}/{len(targets)} done. Wrote {args.out}")
