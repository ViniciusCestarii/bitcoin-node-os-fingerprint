# OS Fingerprinting of Bitcoin Nodes

Scans publicly reachable Bitcoin nodes with `nmap -O` to guess their operating
system, then aggregates the results into general OS classes (Linux, BSD,
Windows, macOS, Android, etc.) for statistics.

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

- **nmap performs best with one open port and one closed port to compare.**
  Many hosts here have the open Bitcoin port but no genuinely *closed*
  reference port, connections to a second port are simply dropped (filtered)
  by a firewall instead of being actively rejected (closed). Filtered
  reference ports give nmap less signal, which lowers confidence and
  increases the `Unknown` rate (but this is a good signal that operators are 
  configuring a firewall for their bitcoin nodes).

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
  On one host I observed nmap return `Synology DiskStation Manager 5.2-5644`
  on one run and `Linux 3.4 - 3.10` on another, same IP, same port, same 97%
  accuracy. Synology's DSM is Linux-based, so its real fingerprint sits
  almost exactly between those two signatures in nmap's database; small
  scan-to-scan network noise (timing jitter, retransmissions) is enough to
  flip which one scores marginally higher. That flip also changes the
  `os_class` bucket entirely (`Linux` vs `Other`), same physical box, two
  different classes, purely from measurement noise. Individual rows can be
  noisy like this; day-over-day runs still land within roughly a percentage
  point on every OS class in aggregate, so treat the per-class *proportions*
  as the reliable signal, not any single row's classification.

- **No OS version information is published.** The filtered dataset only
  keeps a general OS class (e.g. `Linux`, `Windows`), never the specific
  version nmap guessed, since a specific version guess is even less accurate, 
  and publishing it would effectively hand out a list of hosts running 
  known-unpatched software versions ripe for exploitation.

## Data

Scan output and the processing scripts live in [`data/`](data). See that
directory for the CSV, and the scripts that produce them.

## Analysis

```
python3 analyse_scan.py scan-2026-07-06.csv

============================================================
Scan file: scan-2026-07-06.csv
Total records: 16516
============================================================

Host state (reachable vs unreachable)
------------------------------------------------------------
  reachable             10580   64.1%  [###################-----------]
  unreachable            5936   35.9%  [##########--------------------]

OS class among reachable nodes (n=10580)
------------------------------------------------------------
  Linux                  6645   62.8%  [##################------------]
  Unknown                2836   26.8%  [########----------------------]
  Windows                 452    4.3%  [#-----------------------------]
  Other/Device            310    2.9%  [------------------------------]
  BSD                     194    1.8%  [------------------------------]
  macOS                    95    0.9%  [------------------------------]
  Android                  47    0.4%  [------------------------------]
  Solaris                   1    0.0%  [------------------------------]

Accuracy by OS class (reachable nodes with a guess)
------------------------------------------------------------
  Linux                n=6645  min=70   avg= 94.6  max=100
  Windows              n=452   min=80   avg= 90.8  max=100
  Other/Device         n=310   min=85   avg= 91.4  max=100
  BSD                  n=194   min=85   avg= 90.0  max=100
  macOS                n=95    min=85   avg= 90.0  max=100
  Android              n=47    min=86   avg= 90.4  max=95
  Unknown              n=21    min=6    avg= 46.8  max=69
  Solaris              n=1     min=87   avg= 87.0  max=87

Legend
------------------------------------------------------------
  Unknown: nmap had no OS guess, or the guess scored below 70% accuracy.
  Other/Device: guess matched a router/firewall/printer/appliance or similar, likely a middlebox in front of the node rather than the node itself.
  Other: guess matched an OS outside the tracked classes (Linux, BSD, Windows, macOS, Android, Solaris).
```

```
python3 analyse_scan.py scan-2026-07-07.csv

============================================================
Scan file: scan-2026-07-07.csv
Total records: 16662
============================================================

Host state (reachable vs unreachable)
------------------------------------------------------------
  reachable             10625   63.8%  [###################-----------]
  unreachable            6037   36.2%  [##########--------------------]

OS class among reachable nodes (n=10625)
------------------------------------------------------------
  Linux                  6665   62.7%  [##################------------]
  Unknown                2852   26.8%  [########----------------------]
  Windows                 453    4.3%  [#-----------------------------]
  Other/Device            310    2.9%  [------------------------------]
  BSD                     194    1.8%  [------------------------------]
  macOS                    95    0.9%  [------------------------------]
  Android                  46    0.4%  [------------------------------]
  Other                     8    0.1%  [------------------------------]
  Solaris                   2    0.0%  [------------------------------]

Accuracy by OS class (reachable nodes with a guess)
------------------------------------------------------------
  Linux                n=6665  min=72   avg= 94.6  max=100
  Windows              n=453   min=79   avg= 90.9  max=100
  Other/Device         n=310   min=85   avg= 91.2  max=100
  BSD                  n=194   min=85   avg= 90.1  max=100
  macOS                n=95    min=85   avg= 90.2  max=100
  Android              n=46    min=87   avg= 90.8  max=93
  Unknown              n=24    min=6    avg= 46.6  max=69
  Other                n=8     min=86   avg= 92.6  max=100
  Solaris              n=2     min=87   avg= 88.0  max=89

Legend
------------------------------------------------------------
  Unknown: nmap had no OS guess, or the guess scored below 70% accuracy.
  Other/Device: guess matched a router/firewall/printer/appliance or similar, likely a middlebox in front of the node rather than the node itself.
  Other: guess matched an OS outside the tracked classes (Linux, BSD, Windows, macOS, Android, Solaris).
```

These two runs are one day apart, against independently-fetched Bitnodes
exports, and every OS class lands within about a percentage point of the
other run (reachable ratio 64.1% vs 63.8%, Linux 62.8% vs 62.7%, Windows
4.3% vs 4.3%, and so on). That's the expected outcome: individual hosts can
flip classification between runs (see the Synology example above), but the
aggregate distribution is stable, which is what makes it usable as a
statistic in the first place.

That stability is also the reason **not** to run this scan daily, or on any
tight recurring schedule. A one-off or occasional scan is enough to get a
representative picture; scanning the same set of thousands of nodes
repeatedly doesn't meaningfully improve the numbers, but it does repeatedly
put unsolicited probe traffic on every node operator's network. Re-scan
only when you actually need a fresh snapshot, not on a cron job.

## Scan responsibly

`os_fingerprint.py` doesn't just read data, it actively sends crafted TCP and UDP 
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