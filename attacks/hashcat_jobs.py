"""Hashcat job queue and command metadata helpers."""

from __future__ import annotations

import hashlib
import json
from dataclasses import MISSING, asdict, dataclass, fields
from datetime import datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

from app.safety import sanitize_filename
from attacks.commands import hashcat_crack, hashcat_restore


@dataclass(frozen=True)
class HashcatJob:
    job_id: str
    hash_file: str
    wordlist: str
    mode: int
    workload: int
    session: str
    potfile_disable: bool
    status: str
    hash_sha256: str
    created_at: str
    updated_at: str
    attack_mode: int = 0
    rules: str = ""
    mask: str = ""

    def command(self) -> list[str]:
        command = hashcat_crack(
            self.hash_file,
            self.wordlist or None,
            mode=self.mode,
            workload=self.workload,
            status=True,
            potfile_disable=self.potfile_disable,
            attack_mode=self.attack_mode,
            rules=self.rules or None,
            mask=self.mask or None,
        )
        return insert_hashcat_session(command, self.session)

    def restore_command(self) -> list[str]:
        return hashcat_restore(self.session)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["command"] = self.command()
        data["restore_command"] = self.restore_command()
        return data


class HashcatJobStore:
    def __init__(self, path: Path):
        self.path = path

    def list_jobs(self) -> list[HashcatJob]:
        if not self.path.exists():
            return []
        raw = json.loads(self.path.read_text(encoding="utf-8"))
        jobs = []
        for item in raw:
            if isinstance(item, dict):
                jobs.append(job_from_mapping(item))
        return jobs

    def create_job(
        self,
        *,
        hash_file: Path,
        wordlist: Path,
        mode: int = 22000,
        workload: int = 3,
        potfile_disable: bool = False,
        session: str | None = None,
        attack_mode: int = 0,
        rules: str = "",
        mask: str = "",
    ) -> HashcatJob:
        digest = file_sha256(hash_file)
        duplicate = self.find_duplicate(
            digest,
            str(wordlist),
            mode,
            attack_mode=int(attack_mode),
            rules=str(rules or ""),
            mask=str(mask or ""),
        )
        if duplicate:
            return duplicate

        now = datetime.now().isoformat(timespec="seconds")
        job = HashcatJob(
            job_id=uuid4().hex[:12],
            hash_file=str(hash_file),
            wordlist=str(wordlist),
            mode=int(mode),
            workload=int(workload),
            session=sanitize_filename(session or f"wifiangel_{hash_file.stem}_{mode}", fallback="wifiangel_hashcat"),
            potfile_disable=bool(potfile_disable),
            status="queued",
            hash_sha256=digest,
            created_at=now,
            updated_at=now,
            attack_mode=int(attack_mode),
            rules=str(rules or ""),
            mask=str(mask or ""),
        )
        jobs = self.list_jobs()
        jobs.append(job)
        self.save_jobs(jobs)
        return job

    def update_status(self, job_id: str, status: str) -> HashcatJob | None:
        jobs = self.list_jobs()
        now = datetime.now().isoformat(timespec="seconds")
        updated = None
        out = []
        for job in jobs:
            if job.job_id == job_id:
                updated = HashcatJob(**{**asdict(job), "status": status, "updated_at": now})
                out.append(updated)
            else:
                out.append(job)
        if updated:
            self.save_jobs(out)
        return updated

    def find_duplicate(
        self,
        hash_sha256: str,
        wordlist: str,
        mode: int,
        *,
        attack_mode: int = 0,
        rules: str = "",
        mask: str = "",
    ) -> HashcatJob | None:
        terminal = {"complete", "completed", "failed", "cancelled"}
        for job in self.list_jobs():
            if job.status.lower() in terminal:
                continue
            if (
                job.hash_sha256 == hash_sha256
                and job.wordlist == wordlist
                and job.mode == int(mode)
                and job.attack_mode == int(attack_mode)
                and job.rules == str(rules or "")
                and job.mask == str(mask or "")
            ):
                return job
        return None

    def save_jobs(self, jobs: list[HashcatJob]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(
            json.dumps([asdict(job) for job in jobs], indent=2, sort_keys=True),
            encoding="utf-8",
        )


def job_from_mapping(item: dict[str, Any]) -> HashcatJob:
    """Build a job from persisted JSON, ignoring computed keys like command/restore_command."""
    payload: dict[str, Any] = {}
    for field in fields(HashcatJob):
        if field.name in item:
            payload[field.name] = item[field.name]
        elif field.default is not MISSING:
            payload[field.name] = field.default
        elif field.default_factory is not MISSING:  # type: ignore[misc]
            payload[field.name] = field.default_factory()
    return HashcatJob(**payload)


def file_sha256(path: Path, *, chunk_size: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(chunk_size), b""):
            h.update(chunk)
    return h.hexdigest()


def insert_hashcat_session(command: list[str], session: str) -> list[str]:
    """Insert ``--session`` after ``hashcat -m MODE -a 0`` without slicing option flags."""
    if not command:
        return ["hashcat", "--session", session]
    if "--session" in command:
        return list(command)
    if len(command) >= 5 and command[0] == "hashcat" and command[1] == "-m" and command[3] == "-a":
        return command[:5] + ["--session", session] + command[5:]
    return [command[0], "--session", session, *command[1:]]
