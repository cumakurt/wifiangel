"""BetterCAP command builders."""

from __future__ import annotations

from typing import List, Optional


def bettercap_command(interface: str, caplet_path: Optional[str] = None) -> List[str]:
    command = ["bettercap", "-iface", interface]
    if caplet_path:
        command.extend(["-caplet", str(caplet_path)])
    return command


def bettercap_stdin_eval_command(interface: str) -> List[str]:
    return ["bettercap", "-iface", interface, "-no-history", "-eval-"]
