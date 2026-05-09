"""Runtime state and shared dependencies for WiFiAngel flows."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class RuntimeState:
    """Lightweight context container for controllers/services."""

    console: Any
    logger: Any
    command_runner: Any
    wifi_adapter: Any
