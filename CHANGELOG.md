# Changelog

## Single-port scanning replaces the two-port method (2026-07-07)

`os_fingerprint.py` originally probed two ports per host: the actual
Bitcoin port, and port 1 as a "closed port" reference, since nmap's own
documentation recommends pairing one open and one closed port for OS
detection.

Testing that against a single-port scan of the same hosts on just one day
appart showed the opposite of what that general advice suggests: of 422 hosts
that got no OS match at all with the reference port included, 91% had a
perfectly normal `closed/reset` response on port 1, yet nmap still failed
to match them. Removing the reference port and scanning only the real port
let nmap match most of those same hosts.

The likely reason: many Bitcoin nodes sit behind a middlebox with port
forwarding configured only for the Bitcoin port. The open-port probe gets
forwarded through to the real node, but port 1 is almost never forwarded,
so that probe (and its `closed/reset` response) came from the
router/middlebox itself, not the node. nmap ended up building one
fingerprint out of TCP/IP stack behavior from two different devices, which
is internally inconsistent enough that it matches no single-OS signature.

Also new scans use nmap version 7.99 which has a more up to date os fingerprint
db.

**Files affected**: `scan-2026-07-06-legacy.csv` and
`scan-2026-07-07-legacy.csv` were scanned with the two-port method and are
left as-is (not retroactively rescanned). `scan-2026-07-08.csv` onward use
the single-port method. See the Analysis section in `README.md` for the 
actual day-over-day stability comparison.
