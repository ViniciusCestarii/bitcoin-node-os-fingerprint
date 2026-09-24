# Limitations

## OS detection is a guess

nmap matches a host's TCP/IP stack behavior against a signature database and
returns the closest match with a confidence score. It is not a fact.

- **Unknown is expected.** It means nmap found no match it was confident in.
- **Low-confidence guesses are dropped.** Anything under 70% accuracy becomes
  `Unknown`.
- **Middleboxes may distort fingerprints.** A router, firewall or NAT in front
  of the node may answer or alter some probes, mixing its fingerprint with the
  real machine's. This can lower accuracy and push more hosts into `Unknown`.
- **Shared kernels blur classes.** Android shares Linux's kernel, macOS/iOS
  share XNU, so nmap can confuse them.

## Results for one host are noisy

The same host can get a different classification on another run. One host
returned `Synology DiskStation Manager 5.2-5644` on one scan and
`Linux 3.4 - 3.10` on another, same IP, same port, same 97% accuracy. DSM is
Linux-based, so small noise flips which signature wins, and with it the
`os_class` (`Other/Device` vs `Linux`).

Across the two legacy scans, 256 of 10,302 hosts reachable on both days
(~2.5%) flipped `os_class`, mostly `Linux ↔ Unknown` and
`Linux ↔ Other/Device`.

Treat per-class proportions as the signal, not any single row.

## Aggregates are stable

`scan-2026-07-08.csv` and `scan-2026-07-09.csv` are single-port runs against
independently fetched Bitnodes exports one day apart:

| | 2026-07-08 | 2026-07-09 |
| --- | --- | --- |
| Reachable | 63.4% | 62.8% |
| Linux | 70.9% | 71.0% |
| Unknown | 18.6% | 18.3% |
| Windows | 4.5% | 4.7% |

Every class is within about half a point. This is also why scanning daily is
pointless: it barely changes the numbers but keeps sending unsolicited probes
to every node operator. Monthly is enough.

## Coverage

- **Many nodes are unreachable.** Hosts that are down or refuse inbound
  connections (e.g. outbound-only nodes) show up as `unreachable` with no guess.
- **Only IPv4 and IPv6.** Other Bitcoin address types (Tor, I2P, CJDNS) don't
  map to the real machine running the node.
- **Only the Bitcoin port is probed.** Earlier scans also probed a closed
  reference port, which suppressed correct matches (see
  [`CHANGELOG.md`](../CHANGELOG.md)). The two scans made that way
  (`scan-2026-07-06-legacy.csv`, `scan-2026-07-07-legacy.csv`) are kept as-is.

## No OS versions are published

The dataset only keeps the general OS class. Version guesses are even less
accurate, and publishing them would hand out a list of hosts running known
vulnerable software.
