# WiFiAngel quality / logic / performance pass

## Findings to fix

- [x] Initialize `_networks_lock` at startup; snapshot scan UI under the lock
- [x] Detect monitor mode via `iw` type, not `endswith("mon")`
- [x] Guard stale `selected_network` (KeyError)
- [x] Dictionary attack: hashcat mode 22000 for `.22000`; implement advertised WPA3 option; stop global `pkill`
- [x] Handshake parser: accept 2+ handshakes, not only `"1 handshake"`
- [x] PMKID/hybrid: convert/deauth on an interval; handle capture process exit
- [x] WPS: argv list, merge stderr, set channel first
- [x] Required tools: match README (hostapd/reaver/macchanger optional)
- [x] Cleanup: drop `pkill -f air` / `hcx` / `defunct`
- [x] Channel set: prefer `iw`, report failure; 5 GHz in channel optimizer
- [x] Signal analyzer: read live scan data
- [x] Hidden SSID restore: use adapter manager
- [x] Tests for the above
- [x] Review section after verification

## Review

- `python -m compileall` on the tree: clean
- `python -m pytest -q`: **124 passed** (was 98)
- Follow-up from architecture and wifi/tests audits: ToDS/FromDS, WPS ESSID false positive, hashcat JSON round-trip, monitor NM rollback, sequential auto-hack, pcap caps, tools 17–19.
- Evil Twin NAT uses dedicated `WIFIANGEL_ET_FWD` / `WIFIANGEL_ET_NAT` chains; jumps match only `192.168.1.0/24`. Teardown deletes those jumps and chains. Host filter/nat tables are not flushed.
- MITM still uses `iptables-restore` with a global `iptables -F` fallback (separate from Evil Twin).
- Scope: quality, logic, functionality, and performance of existing modules. No new attack capabilities.
- Remaining hardware-dependent flows (aireplay, hostapd, bettercap, reaver) need a root Linux adapter to exercise live; command builders and parsers are covered by unit tests.
