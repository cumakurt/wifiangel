"""System command adapters."""

from .bettercap import bettercap_command, bettercap_stdin_eval_command
from .network import (
    arp_lookup_command,
    normalize_mac_address,
    parse_mac_from_arp_output,
    ping_probe_command,
)
from .runner import CommandResult, CommandRunner
from .speed import (
    DOWNLOAD_TEST_BYTES,
    UPLOAD_TEST_BYTES,
    PingStats,
    build_speed_recommendations,
    bytes_to_mbytes_per_second,
    curl_download_command,
    curl_upload_command,
    download_speed_rating,
    estimate_upload_mbytes_per_second,
    fallback_upload_mbytes_per_second,
    mbytes_to_mbits,
    parse_ping_stats,
    ping_command,
    speed_gauge_blocks,
    upload_speed_rating,
)
from .wifi import (
    WiFiAdapterManager,
    managed_name_from_monitor,
    parse_iwconfig_monitor_interface,
    parse_iwconfig_wireless_interfaces,
)

__all__ = [
    "CommandResult",
    "CommandRunner",
    "DOWNLOAD_TEST_BYTES",
    "UPLOAD_TEST_BYTES",
    "PingStats",
    "WiFiAdapterManager",
    "arp_lookup_command",
    "bettercap_command",
    "bettercap_stdin_eval_command",
    "build_speed_recommendations",
    "bytes_to_mbytes_per_second",
    "curl_download_command",
    "curl_upload_command",
    "download_speed_rating",
    "estimate_upload_mbytes_per_second",
    "fallback_upload_mbytes_per_second",
    "managed_name_from_monitor",
    "mbytes_to_mbits",
    "normalize_mac_address",
    "parse_mac_from_arp_output",
    "parse_ping_stats",
    "parse_iwconfig_monitor_interface",
    "parse_iwconfig_wireless_interfaces",
    "ping_probe_command",
    "ping_command",
    "speed_gauge_blocks",
    "upload_speed_rating",
]
