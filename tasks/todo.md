# Feature roadmap (priority order)

Authorized lab TUI only. No new exploit engines; extend existing scan → target → capture/crack → report flow.

## P1 — Assessment playbook (done)

- [x] Playbook, PMF/SAE passive, HTML section, Attacks 9 hashcat (prior slice)

## P2 — Hashcat queue on Attacks menu (done)

- [x] Rules / mask / restore argv (prior slice)

## P3 — Probe SSIDs + Evil Twin default (done)

- [x] Rank SSIDs from airodump-ng Probed ESSIDs, including unassociated stations
- [x] Tools 20 table; scan stores `app.probe_ssids`
- [x] Evil Twin SSID: selected broadcast name, else most-probed usable SSID

## P4 — Dual NIC + runtime adapter (done)

- [x] Roles: capture vs AP (`adapter_roles`)
- [x] Adapter settings 4/5: switch capture/AP PHY without restarting the TUI
- [x] Evil Twin: dedicated AP radio stays managed; capture radio not forced to managed

## P5 — Evil Twin captive portal + isolation test (done)

- [x] Optional HTTP captive portal on existing dnsmasq DNS sink
- [x] Client-isolation toggle and two-lease reachability check
- [x] Keep WIFIANGEL_ET_* iptables chains (no global flush)

## P6 — Enterprise path (done)

- [x] Detect 802.1X/MGT/EAP in playbook (P1)
- [x] Optional EAP lab AP on hostapd (separate Attacks 10 entry; local eap_server, no RADIUS relay)

## P7 — Session browser (done this slice)

- [x] Browse `handshake/`, `auto_hack_sessions/`, `logs/mitm/`, hashcat jobs
- [x] Re-validate artifact, queue hashcat, attach to HTML report

## Out of scope

Beacon flood / mdk4, SAE CVE-specific tools, Bluetooth attacks, GPS maps.

## Review

- `python -m pytest -q`: **166 passed**
- Landed: Tools 21 session browser; Tools 19 HTML report includes attached lab sessions.
- Roadmap P1–P7 complete.
