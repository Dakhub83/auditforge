"""GitHub connector: collects only.

Every response is saved byte-for-byte to <run_dir>/raw/ before anything parses
it, with its source URI, timestamp, HTTP status and SHA-256. The connector only
issues GET requests, and the token lives in the session headers and nowhere
else: it is never logged, saved, or included in evidence or errors.
"""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import quote

import requests

from auditforge import __version__
from auditforge.models import Evidence, RawResponse
from auditforge.paths import RAW_DIRNAME

API = "https://api.github.com"
REPO_PATTERN = re.compile(r"^(?!\.{1,2}/)[A-Za-z0-9_.-]+/(?!\.{1,2}$)[A-Za-z0-9_.-]+$")


class GitHubAuthError(RuntimeError):
    """GitHub rejected the token (HTTP 401)."""


def utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


class GitHubConnector:
    def __init__(self, token: str, run_dir: Path, session: requests.Session | None = None) -> None:
        self.session = session or requests.Session()
        self.session.headers.update(
            {
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": f"AuditForge/{__version__}",
            }
        )
        self.run_dir = run_dir
        self.raw_dir = run_dir / RAW_DIRNAME
        self.raw_dir.mkdir(parents=True, exist_ok=True)
        self.evidence: list[Evidence] = []

    def get(self, path: str, label: str) -> RawResponse:
        url = f"{API}{path}"
        resp = self.session.get(url, timeout=20)
        body = resp.content
        raw_file = self.raw_dir / f"{label}.json"
        raw_file.write_bytes(body)
        evidence = Evidence(
            evidence_id=uuid.uuid4().hex,
            source_uri=f"GET {url}",
            http_status=resp.status_code,
            collected_at=utc_now(),
            sha256=hashlib.sha256(body).hexdigest(),
            file_path=raw_file.relative_to(self.run_dir).as_posix(),
        )
        self.evidence.append(evidence)
        if resp.status_code == 401:
            raise GitHubAuthError("GitHub rejected the token (401). Check GITHUB_TOKEN.")
        try:
            parsed = json.loads(body)
        except ValueError:
            parsed = None
        return RawResponse(evidence, parsed)

    def branch_protection(self, repo: str, branch: str) -> tuple[RawResponse, RawResponse]:
        """Classic branch protection and the rulesets that apply to the branch."""
        if not REPO_PATTERN.match(repo):
            raise ValueError(f"Expected owner/repo, got {repo!r}")
        # Branch names can contain '/', which must be encoded as one path segment.
        b = quote(branch, safe="")
        classic = self.get(f"/repos/{repo}/branches/{b}/protection", "classic_protection")
        rules = self.get(f"/repos/{repo}/rules/branches/{b}", "rulesets")
        return classic, rules
