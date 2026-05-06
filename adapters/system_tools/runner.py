"""Small wrapper around system commands.

The project runs as root and talks to many Linux networking tools. Keeping
subprocess handling behind one object makes dry-runs, logging and tests much
easier without changing every feature at once.
"""

from __future__ import annotations

from dataclasses import dataclass
import shlex
import shutil
import subprocess
from typing import Iterable, Mapping, Optional, Sequence, Union


Command = Union[Sequence[str], str]


@dataclass(frozen=True)
class CommandResult:
    args: tuple[str, ...]
    returncode: int
    stdout: str = ""
    stderr: str = ""
    dry_run: bool = False

    @property
    def ok(self) -> bool:
        return self.returncode == 0


class CommandRunner:
    """Execute external commands through a single, testable boundary."""

    def __init__(self, dry_run: bool = False, logger=None):
        self.dry_run = dry_run
        self.logger = logger

    def which(self, command: str) -> Optional[str]:
        return shutil.which(command)

    def run(
        self,
        command: Command,
        *,
        capture_output: bool = False,
        text: bool = True,
        stdout=None,
        stderr=None,
        input: Union[str, bytes, None] = None,
        timeout: Optional[float] = None,
        check: bool = False,
    ) -> CommandResult:
        args = self._normalize(command)
        self._log("debug", f"run: {self.format(args)}")

        if self.dry_run:
            return CommandResult(args=args, returncode=0, dry_run=True)

        completed = subprocess.run(
            list(args),
            capture_output=capture_output,
            text=text,
            stdout=stdout,
            stderr=stderr,
            input=input,
            timeout=timeout,
            check=check,
        )
        return CommandResult(
            args=args,
            returncode=completed.returncode,
            stdout=completed.stdout or "",
            stderr=completed.stderr or "",
        )

    def check_output(
        self,
        command: Command,
        *,
        stderr=None,
        text: bool = True,
        timeout: Optional[float] = None,
    ) -> str:
        args = self._normalize(command)
        self._log("debug", f"check_output: {self.format(args)}")

        if self.dry_run:
            return ""

        output = subprocess.check_output(list(args), stderr=stderr, text=text, timeout=timeout)
        return output

    def popen(
        self,
        command: Command,
        *,
        stdout=None,
        stderr=None,
        text: Optional[bool] = None,
        universal_newlines: Optional[bool] = None,
        bufsize: int = -1,
        env: Optional[Mapping[str, str]] = None,
    ) -> Optional[subprocess.Popen]:
        args = self._normalize(command)
        self._log("debug", f"popen: {self.format(args)}")

        if self.dry_run:
            return None

        kwargs = {
            "stdout": stdout,
            "stderr": stderr,
            "bufsize": bufsize,
            "env": env,
        }
        if text is not None:
            kwargs["text"] = text
        if universal_newlines is not None:
            kwargs["universal_newlines"] = universal_newlines

        return subprocess.Popen(list(args), **kwargs)

    def kill_processes(self, process_names: Iterable[str], *, force: bool = True) -> None:
        for process_name in process_names:
            self.run(["pkill", "-f", process_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if force:
                self.run(["pkill", "-9", "-f", process_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def set_wireless_channel(self, interface: str, channel: int | str) -> CommandResult:
        return self.run(
            ["iwconfig", interface, "channel", str(channel)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

    def _normalize(self, command: Command) -> tuple[str, ...]:
        if isinstance(command, str):
            return tuple(shlex.split(command))
        return tuple(str(part) for part in command)

    def _log(self, level: str, message: str) -> None:
        if self.logger and hasattr(self.logger, level):
            getattr(self.logger, level)(message)

    @staticmethod
    def format(command: Sequence[str]) -> str:
        return " ".join(shlex.quote(str(part)) for part in command)
