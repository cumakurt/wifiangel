"""Startup checks and environment preparation."""

from __future__ import annotations

import os
import platform as system_platform
import shutil
import sys

from rich.console import Console

from .defaults import OPTIONAL_SYSTEM_TOOLS, REQUIRED_SYSTEM_TOOLS, RUNTIME_DIRS


def check_root(console: Console) -> None:
    if os.geteuid() != 0:
        console.print("[bold red]❌ Root privileges are required to run this application!")
        console.print("[yellow]Please run with 'sudo'.[/]")
        sys.exit(1)


def check_os(console: Console) -> None:
    os_name = system_platform.system().lower()
    if os_name != "linux":
        console.print("[bold red]❌ This application only runs on Linux operating systems!")
        console.print(f"[yellow]Detected operating system: {system_platform.system()}[/]")
        sys.exit(1)

    try:
        with open("/etc/os-release") as f:
            os_info = f.read()
            if (
                "kali" not in os_info.lower()
                and "debian" not in os_info.lower()
                and "ubuntu" not in os_info.lower()
            ):
                console.print(
                    "[bold yellow]⚠️ Warning: This application has been tested on Kali Linux. "
                    "Unexpected issues may occur on other Linux distributions.[/]"
                )
    except OSError:
        pass


def check_required_packages(console: Console) -> None:
    missing_packages: list[str] = []
    for package, commands in REQUIRED_SYSTEM_TOOLS.items():
        for cmd in commands:
            if shutil.which(cmd) is None:
                missing_packages.append(package)
                break

    if missing_packages:
        console.print("[bold red]❌ Missing packages:[/]")
        for pkg in missing_packages:
            console.print(f"   - {pkg}")

        console.print("\n[yellow]To install missing packages:[/]")
        console.print(
            f"[white]sudo apt update && sudo apt install -y {' '.join(missing_packages)}[/]"
        )
        sys.exit(1)


def ensure_runtime_dirs() -> None:
    for directory in RUNTIME_DIRS:
        directory.mkdir(parents=True, exist_ok=True)


def warn_optional_missing_tools(console: Console) -> None:
    missing: list[str] = []
    for package, commands in OPTIONAL_SYSTEM_TOOLS.items():
        if any(shutil.which(cmd) is None for cmd in commands):
            missing.append(package)
    if not missing:
        return
    console.print("[bold yellow]⚠️ Some optional tools are missing (certain features may be limited):[/]")
    for pkg in missing:
        console.print(f"   - {pkg}")
