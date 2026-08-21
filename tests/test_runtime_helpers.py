from types import SimpleNamespace

from app.services.runtime_helpers import (
    ensure_networks_lock,
    network_is_wpa3,
    require_selected_network,
    selected_network_record,
    snapshot_networks,
)


class _Console:
    def __init__(self):
        self.messages = []

    def print(self, message):
        self.messages.append(str(message))


def test_ensure_networks_lock_creates_once():
    app = SimpleNamespace()
    first = ensure_networks_lock(app)
    second = ensure_networks_lock(app)
    assert first is second
    assert app._networks_lock is first


def test_selected_network_record_and_stale_clear():
    app = SimpleNamespace(
        selected_network="aa:bb:cc:dd:ee:ff",
        networks={},
        console=_Console(),
    )
    assert selected_network_record(app) is None
    assert require_selected_network(app) is None
    assert app.selected_network is None
    assert app.console.messages


def test_snapshot_networks_copies_clients():
    clients = {"11:22:33:44:55:66"}
    signals = {"11:22:33:44:55:66": -40}
    app = SimpleNamespace(
        networks={"aa:bb:cc:dd:ee:ff": {"ssid": "Lab", "clients": clients, "client_signals": signals}}
    )
    snapshot = snapshot_networks(app)
    assert snapshot[0][1]["clients"] == clients
    snapshot[0][1]["clients"].add("00:00:00:00:00:00")
    snapshot[0][1]["client_signals"]["11:22:33:44:55:66"] = -10
    assert "00:00:00:00:00:00" not in clients
    assert signals["11:22:33:44:55:66"] == -40


def test_selected_network_record_copies_under_lock():
    clients = {"11:22:33:44:55:66"}
    app = SimpleNamespace(
        selected_network="aa:bb:cc:dd:ee:ff",
        networks={"aa:bb:cc:dd:ee:ff": {"ssid": "Lab", "clients": clients}},
        console=_Console(),
    )
    record = selected_network_record(app)
    assert record is not None
    record[1]["clients"].add("00:00:00:00:00:00")
    assert "00:00:00:00:00:00" not in clients


def test_network_is_wpa3_reads_cipher_field():
    assert network_is_wpa3({"cipher": "WPA3-SAE"})
    assert network_is_wpa3({"security": ["WPA2", "WPA3"]})
    assert not network_is_wpa3({"cipher": "WPA2"})
    assert not network_is_wpa3(None)
