"""Command builders for wireless attack tools.

These helpers return argv lists only. Process execution stays behind
CommandRunner/subprocess callers so command construction can be tested without
root privileges or Wi-Fi hardware.
"""

from __future__ import annotations

from pathlib import Path
from typing import List, Optional, Union


PathLike = Union[str, Path]


def aircrack_check(capture_file: PathLike) -> List[str]:
    return ["aircrack-ng", str(capture_file)]


def aircrack_crack(capture_file: PathLike, wordlist: PathLike, essid: Optional[str] = None) -> List[str]:
    command = ["aircrack-ng", "-a", "2", "-w", str(wordlist)]
    if essid:
        command.extend(["-e", essid])
    command.append(str(capture_file))
    return command


def hashcat_crack(
    hash_file: PathLike,
    wordlist: Optional[PathLike] = None,
    *,
    mode: int = 22000,
    workload: int = 3,
    force: bool = False,
    status: bool = False,
    potfile_disable: bool = False,
    attack_mode: int = 0,
    rules: Optional[PathLike] = None,
    mask: Optional[str] = None,
) -> List[str]:
    command = ["hashcat", "-m", str(mode), "-a", str(int(attack_mode))]
    if workload:
        command.extend(["-w", str(workload)])
    if force:
        command.append("--force")
    command.append(str(hash_file))
    if int(attack_mode) == 3:
        command.append(str(mask or ""))
    else:
        command.append(str(wordlist or ""))
        if rules:
            command.extend(["-r", str(rules)])
    if status:
        command.append("--status")
    if potfile_disable:
        command.append("--potfile-disable")
    return command


def hashcat_restore(session: str) -> List[str]:
    return ["hashcat", "--session", str(session), "--restore"]


def hashcat_mode_for_hash_file(hash_file: PathLike) -> int:
    """Select hashcat mode from hash file suffix (hcxpcapngtool emits 22000)."""
    suffix = Path(hash_file).suffix.lower()
    if suffix == ".16800":
        return 16800
    return 22000


def hcxpcapngtool_convert(output_file: PathLike, input_file: PathLike) -> List[str]:
    return ["hcxpcapngtool", "-o", str(output_file), str(input_file)]


def hcxpcapngtool_info(pcapng_file: PathLike) -> List[str]:
    return ["hcxpcapngtool", "-i", str(pcapng_file), "--info=1"]


def hcxdumptool_capture(interface: str, output_file: PathLike, channel: Optional[int] = None) -> List[str]:
    command = ["hcxdumptool", "-i", interface, "-w", str(output_file)]
    if channel is not None:
        command.extend(["-c", str(channel)])
    return command


def airodump_network_discovery(
    interface: str,
    output_prefix: PathLike,
    *,
    write_interval: int = 1,
) -> List[str]:
    """Passive scan: channel hop 2.4 + 5 GHz, write CSV for parsers."""
    return [
        "airodump-ng",
        "-w",
        str(output_prefix),
        "--output-format",
        "csv",
        "--write-interval",
        str(write_interval),
        "--band",
        "abg",
        "--wps",
        interface,
    ]


def airodump_capture(
    interface: str,
    *,
    channel: int,
    bssid: str,
    output_prefix: PathLike,
    wpa3: bool = False,
) -> List[str]:
    command = [
        "airodump-ng",
        "-c",
        str(channel),
        "--bssid",
        bssid,
        "-w",
        str(output_prefix),
    ]
    if wpa3:
        command.append("--wpa3")
    command.append(interface)
    return command


def aireplay_deauth(
    interface: str,
    *,
    bssid: str,
    count: int = 2,
    client: Optional[str] = None,
) -> List[str]:
    command = ["aireplay-ng", "-0", str(count), "-a", bssid]
    if client:
        command.extend(["-c", client])
    command.append(interface)
    return command
