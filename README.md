# OS Fingerprinting of Bitcoin Nodes

Scans public Bitcoin nodes with `nmap` to guess their operating system and groups the results into OS classes (Linux, BSD, Windows, macOS, Android, Solaris, etc.).

**Results:** https://viniciuscestarii.github.io/bitcoin-node-os-fingerprint

These are best-effort guesses. Read [docs/limitations.md](docs/limitations.md) before drawing conclusions.

## Data

Published scans are in [`data/`](data) as `scan-*.csv`:

| column | values |
| --- | --- |
| `ip_address` | IPv4 or IPv6 address |
| `port` | advertised Bitcoin port |
| `os_class` | `Linux`, `Android`, `BSD`, `Windows`, `macOS`, `Solaris`, `Other/Device`, `Other`, `Unknown` |
| `accuracy` | nmap confidence in its raw guess (0-100), empty if no guess |
| `host_state` | `reachable`, `unreachable`, `timeout` |

- `Unknown`: no guess, or accuracy below 70%. `accuracy` is kept, so a low value explains the downgrade.
- `Other/Device`: router, firewall, printer or similar, likely a middlebox in front of the node.
- `Other`: an OS outside the tracked classes.
- `timeout`: nmap was killed before reporting. The host was never measured, so exclude it from reachability ratios.

## Usage

Requires `nmap` and root.

1. Build a node list from the live
   [btcnodes.io snapshot](https://btcnodes.io/api/v1/snapshots/latest/)
   (see `scripts/monthly_scan.sh`), or use any CSV with `ip_address` and
   `port` columns.

2. Scan:

   ```
   sudo python3 os_fingerprint.py nodes.csv --out data/raw-scan.csv
   ```

   Flags: `--concurrency N` (default 4), `--host-timeout` (default `60s`).

3. Filter and classify:

   ```
   cd data
   python3 filter_scan.py raw-scan.csv filtered-scan.csv
   ```

4. Print stats:

   ```
   python3 analyse_scan.py filtered-scan.csv
   ```

## Scan responsibly

`os_fingerprint.py` [sends crafted TCP, UDP and ICMP packets](https://nmap.org/book/osdetect-methods.html) to every target. Careless use looks like abusive scanning, can trip IDS alerts and get your IP blocklisted.

- Keep `--concurrency` low.
- Don't scan more often than monthly.
- Use it for aggregate statistics, not for building target lists.

## License

[MIT](LICENSE)
