"""Cleanup path helpers."""

from __future__ import annotations

from pathlib import Path
from typing import Optional


def resolve_evil_twin_log_dir(base_log_dir: Path, log_dir: Optional[Path] = None) -> Path:
    if log_dir is not None:
        return log_dir
    return base_log_dir / "evil_twin"
