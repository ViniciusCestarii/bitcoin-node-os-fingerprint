import argparse
import csv
import re

# Keywords that indicate the OS guess is very likely NOT the Bitcoin node
# itself, but a router/firewall/printer/appliance/gateway answering on the
# port instead (e.g. port forwarding, NAT device, captive middlebox, etc.)
DEVICE_KEYWORDS = [
    "router", "firewall", "wap", "wireless", "modem", "switch", "printer",
    "gateway", "load balancer", "vpn", "controller", "nas", "adapter",
    "bridge", "access point", "wlan", "plc", "utm", "camera", "tv",
    "dashboard", "console", "player", "endpoint", "logger", "panel",
    "interface module", "storage central", "cable modem", "adsl",
    "fritz!box", "xpanel", "sonicwall", "fortigate", "checkpoint",
    "check point", "sonicos", "cisco", "juniper", "netgear", "asus",
    "d-link", "tp-link", "zyxel", "aruba", "aerohive", "mikrotik",
    "ubiquiti", "sonos", "xbox", "blu-ray", "iphone", "apple ios",
    "micropython", "monitor", "storage array", "netapp", "voip",
    "mobile phone", "google home", "ibm i", "datalogger", "extreme networks extremeos",
    "lancom lcos"
]

DEVICE_KEYWORD_PATTERN = re.compile(
    r"\b(" + "|".join(re.escape(keyword) for keyword in DEVICE_KEYWORDS) + r")\b",
    re.I,
)

OS_CLASS_PATTERNS = [
    ("Android", re.compile(r"\bandroid\b", re.I)),
    ("Linux", re.compile(r"\blinux\b", re.I)),
    ("BSD", re.compile(r"\b(free|open|net)bsd\b", re.I)),
    ("Windows", re.compile(r"\bwindows\b", re.I)),
    ("macOS", re.compile(r"\b(mac ?os|darwin)\b", re.I)),
    ("Solaris", re.compile(r"\bsolaris\b", re.I)),
]


def classify(os_name: str) -> str:
    if not os_name:
        return "Unknown"

    if DEVICE_KEYWORD_PATTERN.search(os_name):
        return "Other/Device"

    for label, pattern in OS_CLASS_PATTERNS:
        if pattern.search(os_name):
            return label

    return "Other"


HOST_STATE_MAP = {
    "up": "reachable",
    "down": "unreachable",
}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("in_path", help="raw scan CSV to read")
    parser.add_argument("out_path", help="filtered CSV to write")
    args = parser.parse_args()

    with open(args.in_path, newline="") as f_in, open(args.out_path, "w", newline="") as f_out:
        reader = csv.DictReader(f_in)
        writer = csv.writer(f_out)
        writer.writerow(["ip_address", "port", "os_class", "accuracy", "host_state"])

        count = 0
        for row in reader:
            os_class = classify(row["os_name"])
            if os_class != "Unknown" and row["accuracy"] and int(row["accuracy"]) < 70:
                os_class = "Unknown" # accuracy is too low

            writer.writerow([
                row["ip_address"],
                row["port"],
                os_class,
                row["accuracy"],
                HOST_STATE_MAP.get(row["host_state"], row["host_state"]),
            ])
            count += 1

    print(f"Wrote {count} rows to {args.out_path}")


if __name__ == "__main__":
    main()
