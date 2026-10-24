"""File import connector: collects output that another tool already produced. No network.

Used for scanner results (Checkov, tfsec, KICS, kube-linter, ...) that the operator runs
themselves. The file is copied byte-for-byte into <run_dir>/raw/ before anything parses it,
with its original path, timestamp and SHA-256. AuditForge never runs the scanner, so the
evidence shows exactly what the scanner reported, not a re-interpretation of it.
"""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from pathlib import Path

from auditforge.connectors.github import utc_now
from auditforge.models import Evidence, RawResponse
from auditforge.paths import RAW_DIRNAME

MAX_BYTES = 200 * 1024 * 1024  # scanner output larger than this is almost certainly the wrong file


class FileImportError(RuntimeError):
    """A file could not be imported as evidence."""


class FileImporter:
    def __init__(self, run_dir: Path) -> None:
        self.run_dir = run_dir
        self.raw_dir = run_dir / RAW_DIRNAME
        self.raw_dir.mkdir(parents=True, exist_ok=True)
        self.evidence: list[Evidence] = []

    def import_json(self, path: Path, label: str) -> RawResponse:
        """Copy a JSON (or SARIF) file into the run as evidence and return it parsed."""
        if not path.is_file():
            raise FileImportError(f"No file at {path}")
        if path.stat().st_size > MAX_BYTES:
            raise FileImportError(f"{path} is larger than {MAX_BYTES // (1024 * 1024)} MB")
        body = path.read_bytes()
        safe = re.sub(r"[^A-Za-z0-9._-]", "_", label)
        target = self.raw_dir / f"{safe}{path.suffix or '.json'}"
        target.write_bytes(body)
        evidence = Evidence(
            evidence_id=uuid.uuid4().hex,
            source_uri=f"file {path.resolve()}",
            http_status=None,
            collected_at=utc_now(),
            sha256=hashlib.sha256(body).hexdigest(),
            file_path=target.relative_to(self.run_dir).as_posix(),
        )
        self.evidence.append(evidence)
        try:
            parsed = json.loads(body.decode("utf-8-sig"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise FileImportError(f"{path} is not JSON: {exc}") from None
        return RawResponse(evidence, parsed)
