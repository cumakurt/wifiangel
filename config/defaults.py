"""Project-wide defaults and dependency declarations."""

from __future__ import annotations

from pathlib import Path


CHANNELS_2GHZ = tuple(range(1, 14))
# Busy 2.4 GHz channels first for faster useful results while hopping.
CHANNELS_2GHZ_SCAN_ORDER = (1, 6, 11, 2, 7, 3, 8, 4, 9, 5, 10, 12, 13)
CHANNELS_5GHZ = (
    36,
    40,
    44,
    48,
    52,
    56,
    60,
    64,
    100,
    104,
    108,
    112,
    116,
    120,
    124,
    128,
    132,
    136,
    140,
    144,
    149,
    153,
    157,
    161,
    165,
)

DEFAULT_WORDLIST = Path("wordlists/10-million-password-list-top-1000000.txt")
ROCKYOU_WORDLIST = Path("/usr/share/wordlists/rockyou.txt")

LOGS_ROOT = Path("logs")
TMP_DIR = Path("tmp")
HANDSHAKE_DIR = Path("handshake")
AUTO_HACK_SESSIONS_DIR = Path("auto_hack_sessions")

RUNTIME_DIRS = (
    LOGS_ROOT,
    TMP_DIR,
    HANDSHAKE_DIR,
    AUTO_HACK_SESSIONS_DIR,
)

# Must be on PATH after check_required_packages(); verified again at WiFiAngel startup for UX.
WIFI_ANGEL_SESSION_BINARIES = (
    "airmon-ng",
    "airodump-ng",
    "aireplay-ng",
    "hashcat",
    "hcxdumptool",
)

REQUIRED_SYSTEM_TOOLS = {
    "aircrack-ng": ("aircrack-ng", "airmon-ng", "airodump-ng", "aireplay-ng"),
    "hashcat": ("hashcat",),
    "hcxdumptool": ("hcxdumptool",),
    "hostapd": ("hostapd",),
    "dnsmasq": ("dnsmasq",),
    "macchanger": ("macchanger",),
    "reaver": ("reaver",),
}

OPTIONAL_SYSTEM_TOOLS = {
    "bettercap": ("bettercap",),
    "hcxpcapngtool": ("hcxpcapngtool",),
    "wpaclean": ("wpaclean",),
    "curl": ("curl",),
    "net-tools": ("ifconfig", "netstat", "arp"),
    "network-manager": ("nmcli",),
}
