"""Network scan and packet aggregation services."""

from __future__ import annotations

import os
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path
from typing import Optional

from adapters.system_tools import terminate_process
from attacks.commands import airodump_network_discovery
from app.services.runtime_helpers import ensure_networks_lock, snapshot_networks
from app.ui import create_scan_results_table
from config import TMP_DIR
from wifi.airodump_csv import (
    ap_row_to_network_fields,
    parse_airodump_csv,
    probed_essids_by_bssid,
    station_client_signals,
)
from wifi.probes import summarize_probe_ssids
from wifi.packets import get_security_info as packet_get_security_info
from wifi.packets import parse_client_observation, parse_network_observation


def run_airodump_scan_loop(app) -> None:
    """Passive discovery via airodump-ng CSV (--band abg); merge rows into app.networks."""
    tmp = Path(TMP_DIR)
    tmp.mkdir(parents=True, exist_ok=True)
    prefix = tmp / f"wa_scan_{os.getpid()}_{threading.get_ident()}_{int(time.time() * 1000)}"
    csv_path = Path(f"{prefix}-01.csv")
    argv = airodump_network_discovery(app.interface_name, prefix, write_interval=1)
    proc: Optional[subprocess.Popen] = None
    last_stat: Optional[tuple[int, int]] = None
    try:
        proc = subprocess.Popen(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        while app.scanning:
            time.sleep(1.05)
            if proc.poll() is not None:
                app.logger.error(f"airodump-ng exited unexpectedly (code {proc.returncode})")
                break
            if not csv_path.is_file():
                continue
            try:
                stat = csv_path.stat()
                current = (int(stat.st_mtime_ns), int(stat.st_size))
                if last_stat == current:
                    continue
                last_stat = current
                aps, stas = parse_airodump_csv(csv_path)
                station_signals = station_client_signals(stas)
                by_bssid = {bssid: set(macs) for bssid, macs in station_signals.items()}
                probed_map = probed_essids_by_bssid(stas)
                probe_stats = summarize_probe_ssids(stas)
                now = datetime.now()
                with ensure_networks_lock(app):
                    app.probe_ssids = probe_stats
                    for ap in aps:
                        fields = ap_row_to_network_fields(ap)
                        if not fields:
                            continue
                        bssid = fields["bssid"]
                        ch = int(fields["channel"] or 0)
                        ssid_val = fields["ssid"]
                        sig = int(fields["signal"])
                        cipher_str = str(fields["cipher"])
                        beacons = int(fields["beacons"])
                        wps = bool(fields["wps"])
                        data_packets = int(fields.get("data_packets") or 0)
                        st_clients = by_bssid.get(bssid, set())
                        client_signals = dict(station_signals.get(bssid, {}))
                        probes = set(probed_map.get(bssid, set()))
                        if bssid not in app.networks:
                            app.networks[bssid] = {
                                "ssid": ssid_val,
                                "signal": sig,
                                "cipher": cipher_str,
                                "clients": set(st_clients),
                                "client_signals": client_signals,
                                "probes": probes,
                                "channel": ch if ch > 0 else 0,
                                "first_seen": now,
                                "last_seen": now,
                                "packets": beacons,
                                "data_packets": data_packets,
                                "wps": wps,
                            }
                        else:
                            prev = app.networks[bssid]
                            merged_clients = set(prev["clients"])
                            merged_clients.update(st_clients)
                            merged_signals = dict(prev.get("client_signals") or {})
                            merged_signals.update(client_signals)
                            merged_probes = set(prev.get("probes") or set())
                            merged_probes.update(probes)
                            upd = {
                                "last_seen": now,
                                "signal": sig,
                                "packets": max(prev["packets"], beacons),
                                "data_packets": max(prev.get("data_packets", 0), data_packets),
                                "cipher": cipher_str,
                                "wps": wps or prev.get("wps", False),
                                "clients": merged_clients,
                                "client_signals": merged_signals,
                                "probes": merged_probes,
                            }
                            if ch > 0:
                                upd["channel"] = ch
                            if (
                                ssid_val
                                and ssid_val != "<Hidden Network>"
                                and prev.get("ssid") == "<Hidden Network>"
                            ):
                                upd["ssid"] = ssid_val
                            app.networks[bssid].update(upd)
            except Exception as exc:
                if app.scanning:
                    app.logger.error(f"airodump CSV merge error: {exc}")
    finally:
        terminate_process(proc, timeout=3)
        try:
            for p in prefix.parent.glob(prefix.name + "*"):
                p.unlink(missing_ok=True)
        except OSError:
            pass


def run_results_updater(app) -> None:
    while app.scanning:
        try:
            render_results_table(app)
            time.sleep(0.3)
        except Exception as exc:
            app.logger.error(f"Results update error: {exc}")
            time.sleep(0.1)


def run_scan_networks(app, *, live_table: bool = True) -> None:
    if not live_table:
        app.logger.info("Network scan requested without live table; forcing live table on")
        live_table = True
    app.logger.info("Starting network scan (live_table=%s)", live_table)
    app._suppress_live_updates = not live_table
    if live_table:
        try:
            app.live.start()
        except Exception:
            pass

    ensure_networks_lock(app)

    max_workers = 2 if live_table else 1
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(run_airodump_scan_loop, app)]
        if live_table:
            futures.append(executor.submit(run_results_updater, app))
        try:
            while app.scanning:
                time.sleep(0.1)
                for future in futures:
                    if future.done() and future.exception():
                        app.logger.error(f"Scan thread error: {future.exception()}")
                        app.scanning = False
                        break
        except KeyboardInterrupt:
            app.scanning = False
            app.console.print("\n[bold yellow]Stopping network scan...[/]")
        finally:
            if live_table:
                try:
                    app.live.stop()
                except Exception:
                    pass
            app._suppress_live_updates = False
            for future in futures:
                try:
                    future.result(timeout=2.0)
                except Exception:
                    pass
            app.logger.info("Network scan stopped")


def handle_packet(app, pkt) -> None:
    try:
        network_observation = parse_network_observation(pkt)
        if network_observation:
            with ensure_networks_lock(app):
                bssid = network_observation.bssid
                ch = network_observation.channel
                if ch <= 0:
                    ch = int(getattr(app, "_current_scan_channel", 0) or 0)
                ssid_val = network_observation.ssid
                if bssid not in app.networks:
                    app.networks[bssid] = {
                        "ssid": ssid_val,
                        "signal": network_observation.signal,
                        "cipher": "/".join(network_observation.security),
                        "clients": set(),
                        "channel": ch,
                        "first_seen": datetime.now(),
                        "last_seen": datetime.now(),
                        "packets": 1,
                        "data_packets": 0,
                        "wps": network_observation.wps,
                    }
                    app.logger.debug(f"New network found: {network_observation.ssid} ({bssid})")
                else:
                    prev = app.networks[bssid]
                    upd = {
                        "last_seen": datetime.now(),
                        "signal": network_observation.signal,
                        "packets": prev["packets"] + 1,
                    }
                    if ch > 0:
                        upd["channel"] = ch
                    if (
                        ssid_val
                        and ssid_val != "<Hidden Network>"
                        and prev.get("ssid") == "<Hidden Network>"
                    ):
                        upd["ssid"] = ssid_val
                    app.networks[bssid].update(upd)
            return

        client_observation = parse_client_observation(pkt)
        if not client_observation:
            return

        with ensure_networks_lock(app):
            bssid = client_observation.bssid
            if bssid in app.networks:
                app.networks[bssid]["data_packets"] += 1

                src = client_observation.src
                dst = client_observation.dst

                if src and src != bssid and src not in app.networks[bssid]["clients"]:
                    app.networks[bssid]["clients"].add(src)
                    app.logger.debug(f"New client found: {src} -> {app.networks[bssid]['ssid']}")

                if dst and dst != bssid and dst not in app.networks[bssid]["clients"]:
                    app.networks[bssid]["clients"].add(dst)
                    app.logger.debug(f"New client found: {dst} -> {app.networks[bssid]['ssid']}")
    except Exception as exc:
        app.logger.error(f"Packet processing error: {exc}")


def get_security(pkt):
    return "/".join(packet_get_security_info(pkt))


def render_results_table(app) -> None:
    if getattr(app, "_suppress_live_updates", False):
        return
    table = create_scan_results_table()

    for idx, (bssid, data) in enumerate(snapshot_networks(app), 1):
        table.add_row(
            str(idx),
            bssid,
            data["ssid"],
            str(data["channel"]),
            data["cipher"],
            str(data["signal"]),
            str(len(data["clients"])),
        )

    try:
        app.live.update(table)
        app.live.refresh()
    except Exception:
        pass
