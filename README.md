# OS Fingerprinting of Bitcoin Nodes

Scans publicly reachable Bitcoin nodes with `nmap -O` to guess their operating
system, then aggregates the results into general OS classes (Linux, BSD,
Windows, macOS, Solaris, etc.) for statistics.

## Methodology limitations

- **nmap's OS detection is a best-effort guess, not a fact.** It matches the
  target's TCP/IP stack behavior against a signature database and returns the
  closest match with a confidence score. A large `Unknown` bucket in the
  results is expected, it means nmap couldn't find a signature it was
  confident enough in, not that something went wrong.

- **Many results reflect a firewall/gateway/NAT device, not the node itself.**
  If a home router, firewall, or other middlebox answers (or intercepts) the
  probes in front of the actual node, the fingerprint can describe that
  device instead of the machine actually running the Bitcoin software.

- **Scans only probe the single Bitcoin port, not a second reference port.**
  Earlier versions of `os_fingerprint.py` also probed port 1 as a "closed
  port" reference, since nmap's documentation recommends pairing one open
  and one closed port for OS detection. Testing that against a single-port
  scan of the same hosts showed the opposite of what nmap's general advice
  suggests: of 422 hosts that got no OS match at all with the reference
  port included, 91% had a perfectly normal `closed/reset` response on that
  port, yet still failed to match, while removing it and scanning only the
  real port let nmap match most of them. The likely reason: many Bitcoin
  nodes sit behind a middlebox with port forwarding configured only for
  the Bitcoin port. The open-port probe gets forwarded through to the real
  node, but port 1 is almost never forwarded, so that probe (and its
  closed/reset response) came from the router/middlebox itself, not the
  node. Nmap ended up building one fingerprint out of TCP/IP stack
  behavior from two different devices, which is internally inconsistent
  enough that it matches no single-OS signature. Scans from before this
  change (`scan-2026-07-06-legacy.csv`, `scan-2026-07-07-legacy.csv`) used the two-port
  method and anything scanned after use the single-port method. The old files
  are left as-is rather than retroactively rescanned.

- **A large share of nodes were unreachable.** Many hosts in the source list
  are down, offline, or configured to refuse inbound connections entirely
  (e.g. outbound-only nodes) by the time they were scanned. These show up
  with `host_state = unreachable` and no OS guess.

- **Only IPv4 and IPv6 addresses are considered**, for the obvious reason
  that those are the only address families that Bitcoin supports that can map 
  cleanly to the actual node running Bitcoin.

- **Low-confidence guesses are discarded.** Any OS match under 70% accuracy
  is downgraded to `Unknown` rather than kept as a shaky classification.

- **Fingerprints for the same host aren't fully reproducible across scans.**
  On one host nmap returned `Synology DiskStation Manager 5.2-5644` on one
  run and `Linux 3.4 - 3.10` on another, same IP, same port, same 97%
  accuracy. Synology's DSM is Linux-based, so scan-to-scan noise is enough
  to flip which signature scores marginally higher, which also flips the
  `os_class` bucket (`Linux` vs `Other/Device`) for the same physical box. Across
  the two legacy scans, 256 of 10,302 hosts reachable on both days (~2.5%)
  flipped `os_class` this way, mostly `Linux ↔ Unknown` and `Linux ↔
  Other/Device`. Treat per-class *proportions* as the reliable signal, not
  any single row's classification.

- **No OS version information is published.** The filtered dataset only
  keeps a general OS class (e.g. `Linux`, `Windows`), never the specific
  version nmap guessed, since a specific version guess is even less accurate, 
  and publishing it would effectively hand out a list of hosts running 
  known-unpatched software versions ripe for exploitation.

## Data

Scan output and the processing scripts live in [`data/`](data). See that
directory for the CSV, and the scripts that produce them.

## Analysis

The two-port method was retired in favor of the single-port method (see
above), so its two legacy runs (`scan-2026-07-06-legacy.csv` and
`scan-2026-07-07-legacy.csv`) are omitted here. For the record: they landed
within about a percentage point of each other on every OS class (reachable
ratio 64.1% vs 63.8%, Linux 62.7% vs 62.6%, Windows 4.3% vs 4.3%, and so
on) despite being one day apart against independently-fetched Bitnodes
exports, individual hosts can flip classification between runs (see the
Synology example above), but the aggregate distribution is stable, which is
what makes it usable as a statistic in the first place. Their raw output is
still in `data/` if you want the numbers.

```
python3 analyse_scan.py scan-2026-07-08.csv

============================================================
Scan file: scan-2026-07-08.csv
Total records: 16795
============================================================

Host state (reachable vs unreachable)
------------------------------------------------------------
  reachable             10645   63.4%  [###################-----------]
  unreachable            6150   36.6%  [##########--------------------]

OS class among reachable nodes (n=10645)
------------------------------------------------------------
  Linux                  7544   70.9%  [#####################---------]
  Unknown                1978   18.6%  [#####-------------------------]
  Windows                 483    4.5%  [#-----------------------------]
  Other/Device            272    2.6%  [------------------------------]
  BSD                     177    1.7%  [------------------------------]
  macOS                    95    0.9%  [------------------------------]
  Android                  95    0.9%  [------------------------------]
  Solaris                   1    0.0%  [------------------------------]

Accuracy by OS class (reachable nodes with a guess)
------------------------------------------------------------
  Linux                n=7544  min=71   avg= 95.4  max=100
  Windows              n=483   min=81   avg= 92.5  max=100
  Other/Device         n=272   min=85   avg= 93.5  max=100
  BSD                  n=177   min=85   avg= 91.4  max=100
  macOS                n=95    min=85   avg= 93.2  max=100
  Android              n=95    min=87   avg= 91.9  max=100
  Unknown              n=24    min=1    avg= 20.9  max=66
  Solaris              n=1     min=87   avg= 87.0  max=87

Legend
------------------------------------------------------------
  Unknown: nmap had no OS guess, or the guess scored below 70% accuracy.
  Other/Device: guess matched a router/firewall/printer/appliance or similar, likely a middlebox in front of the node rather than the node itself.
  Other: guess matched an OS outside the tracked classes (Linux, Android, BSD, Windows, macOS, Solaris).
```

This is the first scan run with the single-port method (see above) and
nmap version 7.99, which is why `Unknown` drops sharply (26.8% → 18.6%) and
`Linux` rises (62.6% → 70.9%) compared to the two legacy runs: those runs
were suppressing correct matches by mixing in a middlebox's TCP/IP behavior
via the reference port. It isn't directly comparable to the two legacy runs
above for that reason, future single-port scans should be compared against
this one instead.

That stability is also the reason **not** to run this scan daily, or on any
tight recurring schedule. A one-off or occasional scan is enough to get a
representative picture; scanning the same set of thousands of nodes
repeatedly doesn't meaningfully improve the numbers, but it does repeatedly
put unsolicited probe traffic on every node operator's network. Re-scan
only when you actually need a fresh snapshot, not on a cron job.

## Scan responsibly

`os_fingerprint.py` doesn't just read data, it actively [sends crafted TCP, UDP and ICMP](https://nmap.org/book/osdetect-methods.html)
packets to every host in your target list. Used carelessly this is indistinguishable
from noisy/abusive scanning traffic and can trip IDS/abuse alerts, get your
scanning IP blocklisted, or in aggregate put load on hosts and networks that
never opted into being probed. Before pointing this at a large list:

- Keep `--concurrency` and scan rate modest, don't scan faster than you need
  to.
- This tool is for aggregate research/statistics, not for building a
  per-target list of exploitable hosts, that's why the published dataset
  strips versions down to general OS classes.

## Reusing this on other data

`os_fingerprint.py` isn't Bitcoin-specific: it'll scan any CSV that has
`ip_address` and `port` columns, so you can point it at scan target lists
from an unrelated project too.

## Running it

1. **Get a list of nodes to scan.** Download the current node list CSV from
   the [Bitnodes node explorer](https://bitnod.es/node_explorer.php) (the
   download link is at the bottom of the page) or any csv that contains
   `ip_address` and `port` columns.

2. **Run the scan** (requires `nmap` and `sudo`):

   ```
   sudo python3 os_fingerprint.py <bitnodes.csv> --out data/raw-scan.csv
   ```

   Useful flags: `--concurrency N` (parallel nmap processes, default 4) and
   `--host-timeout` (per-host nmap timeout, default `60s`).

3. **Filter and classify the raw scan** into the safe-to-share and cleaner dataset:

   ```
   cd data
   python3 filter_scan.py raw-scan.csv filtered-scan.csv
   ```

4. **Print statistics** from the filtered dataset:

   ```
   cd data
   python3 analyse_scan.py filtered-scan.csv
   ```