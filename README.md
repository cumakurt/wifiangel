# WiFiAngel

WiFiAngel is an interactive terminal application for **authorized** wireless security assessments on Linux. It combines a Rich-based TUI with common Wi-Fi tooling (aircrack-ng, hcxdumptool, hashcat, hostapd, dnsmasq, and others) to scan networks, capture material for offline analysis, and run controlled lab-style scenarios.

**Use only on networks and equipment you own or have explicit written permission to test.** Unauthorized access to communications systems is illegal in most jurisdictions.

## Requirements

- **OS:** Linux with a visible wireless interface (not WSL without USB passthrough; virtual machines need the adapter passed through).
- **Privileges:** root (`sudo`).
- **Python:** 3.8 or newer recommended.

### Python dependencies

```bash
pip install -r requirements.txt
```

### System tools (minimum session set)

At startup, the app checks that these binaries are on `PATH`:

- `airmon-ng`, `airodump-ng`, `aireplay-ng`
- `hashcat`
- `hcxdumptool`

Other features need additional packages, for example:

| Feature area | Typical packages (Debian/Ubuntu examples) |
|--------------|-------------------------------------------|
| Core Wi-Fi | `aircrack-ng` |
| Handshake / capture | `aircrack-ng` |
| PMKID | `hcxdumptool`; hash conversion may use `hcxpcapngtool` (often from `hcxtools`) |
| Cracking | `hashcat` |
| Evil Twin | `hostapd`, `dnsmasq`; `iptables` / `ip` for NAT |
| WPS | `reaver` (or equivalent) |
| Optionals | `bettercap`, `curl`, `nmcli`, `macchanger` |

Install examples:

```bash
sudo apt update
sudo apt install -y aircrack-ng hashcat hcxdumptool hcxtools hostapd dnsmasq macchanger reaver
```

Optional: `sudo apt install -y bettercap wireless-tools` if you rely on legacy helpers.

## Quick start

From the repository root:

```bash
sudo python3 wifiangel.py
```

The launcher validates root, OS, Python imports, creates runtime folders, warns about optional missing tools, then starts the interactive menu.

## What the tool does (overview)

- **Network discovery:** Passive scan using `airodump-ng` CSV export, merged into a live results table (monitor mode).
- **Attacks menu:** Handshake capture, deauthentication, PMKID capture, dictionary attacks, hybrid flows, WPS, Evil Twin lab, and MITM-oriented workflows that depend on external tools.
- **Evil Twin:** Raises an AP with DHCP/DNS via `hostapd` and `dnsmasq`. When a **separate uplink** exists (e.g. Ethernet with a default route), the app configures IPv4 forwarding and NAT so associated clients can reach the internet through your host.
- **Reports:** Session logs and HTML summaries are written under configurable paths (see below).

Exact behavior depends on hardware, drivers, regulator domain, and which optional tools are installed.

## Repository layout (high level)

| Path | Role |
|------|------|
| `wifiangel.py` | Entry point: `app.main` |
| `app/wifi_angel.py` | Main controller and menus |
| `app/ui/` | Rich theme and shared UI components |
| `adapters/system_tools/` | Command runners, Wi-Fi adapter helpers |
| `attacks/` | Command builders and parsers for external tools |
| `wifi/` | Frame/CSV helpers (e.g. `airodump-ng` CSV parsing) |
| `config/` | Defaults, paths, environment checks |
| `reports/` | Report generation |
| `tests/` | `pytest` suite |

## Runtime directories

Created or used at run time (under the working directory unless configured otherwise):

- `logs/` - session logs and reports
- `handshake/` - captures and PMKID-related outputs
- `tmp/` - temporary scan prefixes and similar files
- `auto_hack_sessions/` - automated session artifacts

## Development

Run tests:

```bash
python -m pytest
```

## License

This project is licensed under the **GNU General Public License v3.0**. See the `LICENSE` file.

## Disclaimer

The authors and contributors are not responsible for misuse. You are solely responsible for complying with applicable laws and for obtaining proper authorization before testing any network.
