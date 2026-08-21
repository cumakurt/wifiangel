"""Shared runtime helpers for locks, target selection, and WPA3 detection."""

from __future__ import annotations

import threading
from typing import Any, Optional


def ensure_networks_lock(app) -> threading.Lock:
    """Return the networks lock, creating it once if missing."""
    lock = getattr(app, "_networks_lock", None)
    if lock is None:
        lock = threading.Lock()
        app._networks_lock = lock
    return lock


def snapshot_networks(app) -> list[tuple[str, dict[str, Any]]]:
    """Copy network records for UI rendering without holding the lock long."""
    lock = ensure_networks_lock(app)
    with lock:
        items = list(getattr(app, "networks", {}).items())
        snapshot = []
        for bssid, data in items:
            row = dict(data)
            clients = data.get("clients")
            if isinstance(clients, (set, list, tuple)):
                row["clients"] = set(clients)
            probes = data.get("probes")
            if isinstance(probes, (set, list, tuple)):
                row["probes"] = set(probes)
            snapshot.append((bssid, row))
        return snapshot


def selected_network_record(app) -> Optional[tuple[str, dict[str, Any]]]:
    """Return (bssid, network) for the current selection, or None if stale/missing."""
    bssid = getattr(app, "selected_network", None)
    if not bssid:
        return None
    networks = getattr(app, "networks", None) or {}
    network = networks.get(bssid)
    if network is None:
        return None
    return str(bssid), network


def require_selected_network(app) -> Optional[tuple[str, dict[str, Any]]]:
    """Require a live selected network; clear stale selections and notify the user."""
    record = selected_network_record(app)
    if record is not None:
        return record
    if getattr(app, "selected_network", None):
        app.selected_network = None
        app.console.print("[bold red]Selected network is no longer in scan results. Select a target again.[/]")
    else:
        app.console.print("[bold red]Please select a target network first![/]")
    return None


def skip_psk_for_target(app, network: dict[str, Any], *, action: str) -> bool:
    """Return True when the playbook says not to run PSK capture/crack."""
    from app.ui import render_playbook_panel
    from wifi.playbook import recommend_assessment

    playbook = recommend_assessment(network)
    if not playbook.skip_psk_capture:
        return False
    render_playbook_panel(app.console, playbook)
    app.console.print(
        f"[warning]Playbook skipped {action} for this target. Use {playbook.menu_label} instead.[/]"
    )
    return True


def network_is_wpa3(network: Optional[dict[str, Any]]) -> bool:
    """True when cipher/security fields mention WPA3 (scan stores this on `cipher`)."""
    if not network:
        return False
    blobs: list[str] = []
    for key in ("cipher", "security"):
        value = network.get(key)
        if isinstance(value, str):
            blobs.append(value)
        elif isinstance(value, (list, tuple, set)):
            blobs.extend(str(item) for item in value)
    return any("WPA3" in blob.upper() for blob in blobs)
