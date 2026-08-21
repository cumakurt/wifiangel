"""Smoke tests for startup helpers."""

from __future__ import annotations

import config.bootstrap as bootstrap


def test_ensure_runtime_dirs_respects_patched_paths(tmp_path, monkeypatch):
    dirs = (tmp_path / "logs", tmp_path / "tmp")
    monkeypatch.setattr(bootstrap, "RUNTIME_DIRS", dirs)
    bootstrap.ensure_runtime_dirs()
    assert all(p.is_dir() for p in dirs)


def test_wifi_angel_session_binaries_subset_of_required_tools():
    from config.defaults import REQUIRED_SYSTEM_TOOLS, WIFI_ANGEL_SESSION_BINARIES

    available = set()
    for cmds in REQUIRED_SYSTEM_TOOLS.values():
        available.update(cmds)
    for binary in WIFI_ANGEL_SESSION_BINARIES:
        assert binary in available, f"{binary} should be covered by REQUIRED_SYSTEM_TOOLS"


def test_lab_tools_are_optional_not_required():
    from config.defaults import OPTIONAL_SYSTEM_TOOLS, REQUIRED_SYSTEM_TOOLS

    for package in ("hostapd", "dnsmasq", "openssl", "macchanger", "reaver"):
        assert package not in REQUIRED_SYSTEM_TOOLS
        assert package in OPTIONAL_SYSTEM_TOOLS
