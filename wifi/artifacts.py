"""Capture artifact indexing and deduplication."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Callable

from wifi.capture_quality import CaptureQualityReport, analyze_capture_quality


SUPPORTED_ARTIFACT_SUFFIXES = {".cap", ".pcap", ".pcapng", ".22000", ".16800", ".hash", ".hc22000"}


@dataclass(frozen=True)
class CaptureArtifact:
    path: str
    sha256: str
    size: int
    modified: float
    inferred_bssid: str
    inferred_ssid: str
    quality_score: int
    verdict: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def index_capture_artifacts(
    root: Path,
    *,
    index_path: Path | None = None,
    analyzer: Callable[[Path], CaptureQualityReport] | None = None,
) -> list[CaptureArtifact]:
    """Build a deduplicated artifact index under root."""
    analyzer = analyzer or (lambda path: analyze_capture_quality(path))
    artifacts: list[CaptureArtifact] = []
    seen_hashes: set[str] = set()

    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in SUPPORTED_ARTIFACT_SUFFIXES:
            continue
        digest = sha256_file(path)
        if digest in seen_hashes:
            continue
        seen_hashes.add(digest)
        stat = path.stat()
        inferred_bssid, inferred_ssid = infer_artifact_identity(path)
        try:
            quality = analyzer(path)
            score = quality.score
            verdict = quality.verdict
        except Exception:
            score = 0
            verdict = "unknown"
        artifacts.append(
            CaptureArtifact(
                path=str(path),
                sha256=digest,
                size=stat.st_size,
                modified=stat.st_mtime,
                inferred_bssid=inferred_bssid,
                inferred_ssid=inferred_ssid,
                quality_score=score,
                verdict=verdict,
            )
        )

    if index_path:
        index_path.parent.mkdir(parents=True, exist_ok=True)
        index_path.write_text(
            json.dumps([artifact.to_dict() for artifact in artifacts], indent=2, sort_keys=True),
            encoding="utf-8",
        )
    return artifacts


def best_artifacts_by_identity(artifacts: list[CaptureArtifact]) -> dict[str, CaptureArtifact]:
    """Return the highest-scoring artifact for each inferred identity."""
    best: dict[str, CaptureArtifact] = {}
    for artifact in artifacts:
        key = artifact.inferred_bssid or artifact.inferred_ssid or artifact.sha256
        prior = best.get(key)
        if prior is None or (artifact.quality_score, artifact.modified) > (prior.quality_score, prior.modified):
            best[key] = artifact
    return best


def infer_artifact_identity(path: Path) -> tuple[str, str]:
    name = path.stem
    bssid = ""
    match = re.search(r"(?i)([0-9a-f]{2}[:_-]?){5}[0-9a-f]{2}", name)
    if match:
        plain = re.sub(r"[^0-9a-fA-F]", "", match.group(0)).lower()
        if len(plain) == 12:
            bssid = ":".join(plain[i : i + 2] for i in range(0, 12, 2))

    ssid = name
    for prefix in ("handshake_", "pmkid_", "capture_"):
        if ssid.startswith(prefix):
            ssid = ssid[len(prefix) :]
            break
    ssid = re.sub(r"_[0-9]{8}_[0-9]{6}.*$", "", ssid)
    if bssid:
        ssid = ssid.replace(bssid.replace(":", ""), "")
    ssid = ssid.strip("_-.") or "Unknown"
    return bssid, ssid


def sha256_file(path: Path, *, chunk_size: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(chunk_size), b""):
            h.update(chunk)
    return h.hexdigest()
