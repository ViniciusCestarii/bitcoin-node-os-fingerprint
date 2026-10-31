import csv
import json
import sys

nodes = json.load(open(sys.argv[1]))["nodes"]
with open(sys.argv[2], "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["ip_address", "port"])
    for addr in nodes:
        host, port = addr.rsplit(":", 1)
        w.writerow([host.strip("[]"), port])
