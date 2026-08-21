"""Discover lab sessions under handshake, auto-hack, MITM, and hashcat stores."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Mapping, Optional, Sequence

from wifi.artifacts import SUPPORTED_ARTIFACT_SUFFIXES

KIND_HANDSHAKE = "handshake"
KIND_AUTO_HACK = "auto_hack"
KIND_MITM = "mitm"
KIND_HASHCAT = "hashcat"

HASH_SUFFIXES = {".22000", ".16800", ".hash", ".hc22000"}


@dataclass(frozen=True)
class LabSession:
    kind: str
    path: str
    label: str
    modified: float
    status: str
    hash_file: str
    detail: str

    def to_report_row(self) -> dict[str, str]:
        return {
            "kind": self.kind,
            "label": self.label,
            "path": self.path,
            "status": self.status,
            "hash_file": self.hash_file,
            "detail": self.detail,
        }


def discover_lab_sessions(
    *,
    handshake_dir: Path,
    auto_hack_dir: Path,
    mitm_dir: Path,
    hashcat_jobs: Sequence[Any] = (),
) -> list[LabSession]:
    sessions: list[LabSession] = []
    sessions.extend(_handshake_sessions(handshake_dir))
    sessions.extend(_directory_sessions(auto_hack_dir, kind=KIND_AUTO_HACK, report_names=("auto_hack_report.html", "auto_hack_report.txt")))
    sessions.extend(_directory_sessions(mitm_dir, kind=KIND_MITM, report_names=("redacted_findings.log", "traffic.txt", "events.log")))
    sessions.extend(sessions_from_hashcat_jobs(hashcat_jobs))
    sessions.sort(key=lambda item: item.modified, reverse=True)
    return sessions[:80]


def sessions_from_hashcat_jobs(jobs: Sequence[Any]) -> list[LabSession]:
    rows: list[LabSession] = []
    for job in jobs:
        job_id = str(getattr(job, "job_id", "") or "")
        hash_file = str(getattr(job, "hash_file", "") or "")
        status = str(getattr(job, "status", "queued") or "queued")
        created = str(getattr(job, "created_at", "") or "")
        attack_mode = getattr(job, "attack_mode", 0)
        mode = getattr(job, "mode", 22000)
        path = hash_file or job_id
        rows.append(
            LabSession(
                kind=KIND_HASHCAT,
                path=path,
                label=job_id or Path(path).name,
                modified=_mtime_from_iso(created, Path(hash_file).stat().st_mtime if hash_file and Path(hash_file).exists() else 0.0),
                status=status,
                hash_file=hash_file,
                detail=f"hashcat -m {mode} -a {attack_mode}",
            )
        )
    return rows


def pick_hash_file(root: Path, preferred: str = "") -> str:
    if preferred:
        candidate = Path(preferred)
        if candidate.is_file():
            return str(candidate)
    if root.is_file():
        return str(root) if root.suffix.lower() in HASH_SUFFIXES | SUPPORTED_ARTIFACT_SUFFIXES else ""
    if not root.is_dir():
        return ""
    hashes: list[Path] = []
    captures: list[Path] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        suffix = path.suffix.lower()
        if suffix in HASH_SUFFIXES:
            hashes.append(path)
        elif suffix in SUPPORTED_ARTIFACT_SUFFIXES:
            captures.append(path)
    if hashes:
        return str(hashes[0])
    if captures:
        return str(captures[0])
    return ""


def attach_session(existing: Sequence[Mapping[str, str]], session: LabSession) -> list[dict[str, str]]:
    row = session.to_report_row()
    key = (row["kind"], row["path"])
    out = [dict(item) for item in existing]
    if any((item.get("kind"), item.get("path")) == key for item in out):
        return out
    out.append(row)
    return out


def revalidate_session(
    session: LabSession,
    *,
    analyzer: Optional[Callable[[Path], Any]] = None,
) -> dict[str, Any]:
    if session.kind == KIND_MITM:
        root = Path(session.path)
        count = sum(1 for item in root.rglob("*") if item.is_file()) if root.is_dir() else 0
        return {"status": "logged", "score": 0, "path": session.path, "detail": f"{count} MITM log file(s)"}

    target = pick_hash_file(Path(session.path), session.hash_file)
    if not target:
        return {"status": "no-artifact", "score": 0, "path": session.path, "detail": "No capture or hash file"}
    path = Path(target)
    if not path.is_file():
        return {"status": "missing", "score": 0, "path": target, "detail": "Artifact path is missing"}
    if analyzer is None:
        from wifi.capture_quality import analyze_capture_quality

        report = analyze_capture_quality(path)
    else:
        report = analyzer(path)
    reasons = getattr(report, "reasons", ())
    detail = "; ".join(str(item) for item in reasons[:3]) if reasons else str(getattr(report, "verdict", ""))
    return {
        "status": str(getattr(report, "verdict", "unknown")),
        "score": int(getattr(report, "score", 0) or 0),
        "path": str(path),
        "detail": detail,
    }


def _handshake_sessions(root: Path) -> list[LabSession]:
    if not root.is_dir():
        return []
    sessions: list[LabSession] = []
    for child in sorted(root.iterdir()):
        try:
            modified = child.stat().st_mtime
        except OSError:
            continue
        if child.is_dir():
            sessions.append(_handshake_dir_session(child, modified))
        elif child.is_file() and child.suffix.lower() in SUPPORTED_ARTIFACT_SUFFIXES:
            hash_file = str(child) if child.suffix.lower() in HASH_SUFFIXES else ""
            sessions.append(
                LabSession(
                    kind=KIND_HANDSHAKE,
                    path=str(child),
                    label=child.name,
                    modified=modified,
                    status="file",
                    hash_file=hash_file,
                    detail="loose capture",
                )
            )
    return sessions


def _handshake_dir_session(child: Path, modified: float) -> LabSession:
    manifest_path = child / "capture_manifest.json"
    label = child.name
    status = "session"
    hash_file = ""
    detail = ""
    if manifest_path.is_file():
        payload = _read_json(manifest_path)
        target = payload.get("target") if isinstance(payload.get("target"), dict) else {}
        ssid = str(target.get("ssid") or payload.get("ssid") or "")
        bssid = str(target.get("bssid") or payload.get("bssid") or "")
        label = ssid or child.name
        status = str(payload.get("status") or payload.get("best_verdict") or "session")
        hash_file = str(payload.get("hash_file") or "")
        verdict = str(payload.get("best_verdict") or "")
        job_id = str(payload.get("hashcat_job_id") or "")
        detail_parts = [part for part in (bssid, verdict, f"job {job_id}" if job_id else "") if part]
        detail = " · ".join(detail_parts)
    if not hash_file or not Path(hash_file).is_file():
        hash_file = pick_hash_file(child, hash_file)
    return LabSession(
        kind=KIND_HANDSHAKE,
        path=str(child),
        label=label,
        modified=modified,
        status=status,
        hash_file=hash_file,
        detail=detail,
    )


def _directory_sessions(
    root: Path,
    *,
    kind: str,
    report_names: tuple[str, ...],
) -> list[LabSession]:
    if not root.is_dir():
        return []
    sessions: list[LabSession] = []
    for child in sorted(root.iterdir()):
        if not child.is_dir():
            continue
        try:
            modified = child.stat().st_mtime
        except OSError:
            continue
        files = []
        try:
            files = [item.name for item in child.iterdir() if item.is_file()]
        except OSError:
            continue
        marker = next((name for name in report_names if name in files), "")
        hash_file = pick_hash_file(child) if kind == KIND_AUTO_HACK else ""
        sessions.append(
            LabSession(
                kind=kind,
                path=str(child),
                label=child.name,
                modified=modified,
                status="report" if marker else "logs",
                hash_file=hash_file,
                detail=marker or f"{len(files)} file(s)",
            )
        )
    return sessions


def _read_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _mtime_from_iso(value: str, fallback: float) -> float:
    if not value:
        return fallback
    try:
        return datetime.fromisoformat(value).timestamp()
    except ValueError:
        return fallback
