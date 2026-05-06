# WiFiAngel

![WiFiAngel banner](banner.png)

WiFiAngel is an interactive **terminal (TUI)** application for **authorized** wireless security work on Linux. It uses [Rich](https://github.com/Textualize/rich) for menus and live tables, and orchestrates common Wi‑Fi and lab tools: **aircrack-ng**, **hcxdumptool** / **hcxtools**, **hashcat**, **hostapd**, **dnsmasq**, **bettercap**, **reaver**, and others.

**Use only on networks and equipment you own or have explicit written permission to test.** Unauthorized interception of networks or traffic is illegal in most jurisdictions.

---

## Contents

- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Quick start](#quick-start)
- [Using the application](#using-the-application)
- [Runtime files and reports](#runtime-files-and-reports)
- [Repository layout](#repository-layout)
- [Development](#development)
- [License and disclaimer](#license-and-disclaimer)

---

## Features

### Core workflow

| Area | What it does |
|------|----------------|
| **Monitor mode** | Puts the chosen adapter into monitor mode via `airmon-ng` / `iw`, with interface resolution (e.g. `wlan0` → `wlan0mon`) through `WiFiAdapterManager`. |
| **Network discovery** | Passive scan using **`airodump-ng`** CSV export (`--band abg`), parsed and merged into an in-memory AP list with SSID, BSSID, channel, security, signal, clients, and WPS hints where available. |
| **Live scan UI** | While scanning from the main menu, a live Rich **table** updates; you can return to the main menu and stop the scan with the same menu option. |
| **Target selection** | Choose a BSSID from discovered networks for attacks that require a selected AP. |

### Attack techniques menu

All attack flows assume a **selected target** where applicable. The app shows legal / lab-oriented warnings before destructive or intrusive actions.

| # | Feature | Summary |
|---|---------|---------|
| **1** | **WPA / WPA2 / WPA3 handshake capture** | `airodump-ng` capture on the target BSSID/channel, deauthentication to provoke handshakes, optional verification with `aircrack-ng`, saving captures under `handshake/`. |
| **2** | **Deauthentication** | Submenu: broadcast deauth to all associated clients, or targeted deauth to one client MAC (`aireplay-ng`). |
| **3** | **PMKID capture** | `hcxdumptool` capture to `pcapng`, conversion with **`hcxpcapngtool`** to **22000** hash format, optional PMKID verification helpers. |
| **4** | **Dictionary attack** | Run **`aircrack-ng`** (or related flow) against a captured handshake using a wordlist (defaults under `config/defaults.py`). |
| **5** | **Hybrid (handshake + PMKID)** | Combined capture path: handshake and PMKID in one workflow, then crack attempts as data becomes available. |
| **6** | **WPS attack** | **`reaver`**: Pixie Dust (`-K 1`) or PIN brute force, with live output in the TUI (requires WPS-enabled target). |
| **7** | **Evil Twin lab** | **`hostapd`** + **`dnsmasq`** fake AP: DHCP, DNS, optional **client isolation** awareness, uplink checks. With a **non‑Wi‑Fi default route** (e.g. Ethernet), the tool can enable **IP forwarding**, **iptables NAT**, DHCP renew on uplink, and show activity (e.g. **dnsmasq** queries, **conntrack** / **ss**-style stats) for lab observation. |
| **8** | **Man-in-the-Middle toolkit** | Requires **`bettercap`**: interface + gateway selection, optional **ping sweep** for targets, ARP spoof + sniff caplet, Rich **Live** dashboard (session, traffic digest, ARP clients, pattern alerts). Session logs under `logs/mitm/<timestamp>/`. |

### Tools menu

| # | Feature | Summary |
|---|---------|---------|
| **1** | **Wi-Fi adapter settings** | Toggle **monitor / managed** mode, **set channel**, show adapter info (`iwconfig` / related). |
| **2** | **Network statistics** | Table of discovered networks: channels, security, signal, clients, data packet counts, first/last seen (requires prior scan data). |
| **3** | **Client analysis** | Lists client MACs observed per network with security context. |
| **4** | **MAC address changer** | Wrapper around **`macchanger`**: show, random, custom, restore. |
| **5** | **Signal analyzer** | Signal-strength oriented view for scanned APs. |
| **6** | **Channel optimizer** | Channel recommendation / analysis helpers for 2.4/5 GHz scans. |
| **7** | **Security audit** | High-level security posture summary from scan-derived data. |
| **8** | **Hidden SSID discovery** | Workflows to infer or surface hidden SSIDs where frames allow. |
| **9** | **Bluetooth and IoT scan** | **`bleak`**-based BLE discovery (requires Python dependency); lists nearby BLE devices when available. |
| **10** | **Network speed test** | Upload/download probes via **`curl`** (or configured runners), with formatted throughput and simple recommendations. |

### Auto Hack workflow

Automated **lab-style** pipeline (with disclaimers and confirmations):

1. **Legal disclaimer** and optional **3-minute confirmation** window before attacks.
2. **Monitor mode** via the same adapter path as the main menu (`WiFiAdapterManager`).
3. **Discovery** — **60 seconds** of **`airodump-ng`** (same backend as menu scan, optional `live_table=False` so the countdown **Live** panel does not fight the Rich console).
4. **Prioritization** — scores networks (clients, signal, cipher family, WPS, etc.) and shows a **prioritized table**.
5. **User selection** — comma-separated indices or `all`; another timed confirmation.
6. **Parallel attacks** — only networks **with observed clients**; per-network worker runs **airodump** + **hcxdumptool**, **deauth** bursts, **3–5 minute** capture window (configurable in code), then **`aircrack-ng`** / **`hashcat`** as appropriate. **Live** status panel shows **per-target heartbeat** so long captures do not look “stuck at 0%”.
7. **Results table** and summary statistics; artifacts under **`auto_hack_sessions/<timestamp>/`** and log append to the session report.

### Logging and reports

- **`Logger`** writes timestamped logs under **`logs/<timestamp>/`** (main, attacks, networks, clients, evil twin, DNS, traffic helpers).
- **`generate_report()`** can produce security-oriented **HTML** output via the `reports` package.
- MITM runs create **`logs/mitm/<timestamp>/`** (caplets, stdout/stderr, traffic/sensitive logs).

---

## Requirements

- **OS:** Linux with a real wireless adapter (not WSL without USB passthrough; VMs need the device passed through).
- **Privileges:** **root** (`sudo`).
- **Python:** 3.8+ recommended (3.10+ well tested).

### Python dependencies

```bash
pip install -r requirements.txt
```

### System tools

**Checked at session start** (must be on `PATH`): `airmon-ng`, `airodump-ng`, `aireplay-ng`, `hashcat`, `hcxdumptool`.

**Commonly required for full feature set:**

| Area | Typical packages (Debian/Ubuntu) |
|------|----------------------------------|
| Core Wi‑Fi / crack | `aircrack-ng`, `hashcat`, `hcxdumptool`, `hcxtools` (`hcxpcapngtool`) |
| Evil Twin | `hostapd`, `dnsmasq`; `iptables`, `iproute2` |
| WPS | `reaver` |
| MITM | `bettercap` |
| Optional helpers | `curl`, `nmcli`, `macchanger`, `net-tools` (`ifconfig`), `wpaclean` |

Example:

```bash
sudo apt update
sudo apt install -y aircrack-ng hashcat hcxdumptool hcxtools hostapd dnsmasq macchanger reaver curl iproute2 iptables
# Optional
sudo apt install -y bettercap network-manager
```

On startup, **`app.main`** also runs **`warn_optional_missing_tools`** so you see which optional binaries are missing before using specific menus.

---

## Installation

```bash
git clone <repository-url>
cd wifiangel
pip install -r requirements.txt
```

---

## Quick start

From the repository root:

```bash
sudo python3 wifiangel.py
```

The launcher:

1. Verifies **root**, **OS**, and **Python imports**
2. Creates **runtime directories** (`logs`, `tmp`, `handshake`, `auto_hack_sessions`)
3. Warns about **optional** missing tools
4. Shows the **welcome banner** and **main menu**

---

## Using the application

### Main menu

| Key | Action |
|-----|--------|
| **1** | Start **monitor mode** on the configured adapter |
| **2** | **Start or stop** network scan (**airodump-ng** CSV loop + live table) |
| **3** | **Select target network** from the current scan results |
| **4** | Open **Attack techniques** submenu |
| **5** | Open **Tools** submenu |
| **6** | Run **Auto hack workflow** |
| **0** | **Exit** (stops an active scan if needed) |

**Ctrl+C** from the main menu stops an active scan or exits / returns depending on context.

### Typical manual flow

1. Choose adapter at startup (if prompted).
2. **1** — monitor mode (or rely on **2** to auto-enable when scanning).
3. **2** — run scan; press **Enter** when done reviewing the live table.
4. **3** — pick target AP.
5. **4** — run a specific attack or lab module.

### Wordlists

Default paths are defined in **`config/defaults.py`** (e.g. `wordlists/10-million-password-list-top-1000000.txt`, fallback hints to `/usr/share/wordlists/rockyou.txt`). Dictionary and Auto Hack flows prompt or fall back if files are missing.

---

## Runtime files and reports

| Path | Purpose |
|------|---------|
| `logs/` | Per-run log trees (`main.log`, `attacks.log`, …) |
| `handshake/` | Handshake `.cap` / related capture material |
| `tmp/` | Temporary **`airodump-ng`** prefixes and scratch files |
| `auto_hack_sessions/` | Timestamped Auto Hack outputs and reports |
| `logs/mitm/` | Bettercap-centric MITM session folders |

---

## Repository layout

| Path | Role |
|------|------|
| `wifiangel.py` | Entry point → `app.main:main` |
| `app/wifi_angel.py` | Main controller, menus, Evil Twin, MITM, Auto Hack |
| `app/main.py` | Environment checks and app bootstrap |
| `app/ui/` | Rich theme (`theme.py`) and shared widgets (`components.py`) |
| `app/logger.py` | File logging and report hook |
| `adapters/system_tools/` | `CommandRunner`, `WiFiAdapterManager`, speed/ping helpers |
| `attacks/` | External command builders and output parsers |
| `wifi/` | `airodump-ng` CSV parsing, frame helpers |
| `config/` | Defaults, `PATH` checks, runtime dir creation |
| `reports/` | HTML / security report generation |
| `tests/` | `pytest` suite |
| `wordlists/` | Bundled or placeholder wordlists (large lists may be gitignored) |

---

## Development

```bash
python -m pytest
```

---

## License and disclaimer

This project is licensed under the **GNU General Public License v3.0**. See the `LICENSE` file.

The authors and contributors are **not** responsible for misuse. You alone are responsible for complying with applicable laws and for obtaining **proper authorization** before testing any network.
