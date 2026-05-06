"""Application package (lazy exports to avoid importing WiFiAngel until needed)."""

from __future__ import annotations

__all__ = ["WiFiAngel", "main"]


def __getattr__(name: str):
    if name == "WiFiAngel":
        from .wifi_angel import WiFiAngel as _WiFiAngel

        return _WiFiAngel
    if name == "main":
        from .main import main as _main

        return _main
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
