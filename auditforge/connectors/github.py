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
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlencode

import requests

from auditforge import __version__
from auditforge.models import Evidence, RawResponse
from auditforge.paths import RAW_DIRNAME

API = "https://api.github.com"
REPO_PATTERN = re.compile(r"^(?!\.{1,2}/)[A-Za-z0-9_.-]+/(?!\.{1,2}$)[A-Za-z0-9_.-]+$")
# SHAs come from API responses and are put back into URL paths, so they are
# validated rather than trusted.
SHA_PATTERN = re.compile(r"^[0-9a-f]{40}$")


class GitHubAuthError(RuntimeError):
    """GitHub rejected the token (HTTP 401)."""


class GitHubResponseError(RuntimeError):
    """A response could not be followed safely (e.g. a pagination link off api.github.com)."""


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
        return self._fetch(f"{API}{path}", label)[0]

    def get_pages(
        self, path: str, label: str, stop: Callable[[Any], bool] | None = None
    ) -> list[RawResponse]:
        """Follow Link: rel="next" until the last page, a non-200 page, or stop(body) is true.

        Every page is saved as its own evidence file (<label>_p1.json, _p2, ...).
        """
        pages: list[RawResponse] = []
        url: str | None = f"{API}{path}"
        while url:
            page, url = self._fetch(url, f"{label}_p{len(pages) + 1}")
            pages.append(page)
            if page.status != 200 or (stop is not None and stop(page.body)):
                break
            # The token is sent with every request, so never follow a link elsewhere.
            if url and not url.startswith(f"{API}/"):
                raise GitHubResponseError("Refusing to follow a pagination link outside api.github.com")
        return pages

    def _fetch(self, url: str, label: str) -> tuple[RawResponse, str | None]:
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
        next_url = resp.links.get("next", {}).get("url")
        return RawResponse(evidence, parsed), next_url

    def branch_protection(self, repo: str, branch: str) -> tuple[RawResponse, RawResponse]:
        """Classic branch protection and the rulesets that apply to the branch."""
        _check_repo(repo)
        # Branch names can contain '/', which must be encoded as one path segment.
        b = quote(branch, safe="")
        classic = self.get(f"/repos/{repo}/branches/{b}/protection", "classic_protection")
        rules = self.get(f"/repos/{repo}/rules/branches/{b}", "rulesets")
        return classic, rules

    # --- Change management (Module A) -------------------------------------------------

    def closed_pulls(self, repo: str, branch: str, since: str) -> list[RawResponse]:
        """Every closed PR into `branch` that could have been merged at or after `since` (ISO, UTC).

        Sorted by last update, newest first. Merging a PR updates it, so a PR merged at time T has
        updated_at >= T. Once a page ends with a PR last updated before `since`, no later page can
        hold a PR merged in the period, and paging stops. This is what makes the population complete.
        """
        _check_repo(repo)
        query = urlencode(
            {"state": "closed", "base": branch, "sort": "updated", "direction": "desc", "per_page": 100}
        )

        def past_start(body: Any) -> bool:
            return isinstance(body, list) and (not body or body[-1].get("updated_at", "") < since)

        return self.get_pages(f"/repos/{repo}/pulls?{query}", "pulls", stop=past_start)

    def pull_reviews(self, repo: str, number: int) -> list[RawResponse]:
        _check_repo(repo)
        return self.get_pages(
            f"/repos/{repo}/pulls/{int(number)}/reviews?per_page=100", f"pr_{number}_reviews"
        )

    def check_runs(self, repo: str, sha: str, label: str) -> list[RawResponse]:
        """GitHub Checks results (e.g. Actions jobs) on a commit. Needs 'Checks: read'."""
        _check_repo(repo)
        _check_sha(sha)
        return self.get_pages(f"/repos/{repo}/commits/{sha}/check-runs?per_page=100", f"{label}_check_runs")

    def combined_status(self, repo: str, sha: str, label: str) -> RawResponse:
        """Legacy commit statuses (e.g. Jenkins, CircleCI). Needs 'Commit statuses: read'."""
        _check_repo(repo)
        _check_sha(sha)
        return self.get(f"/repos/{repo}/commits/{sha}/status?per_page=100", f"{label}_status")

    def branch(self, repo: str, branch: str) -> RawResponse:
        """The branch and its current tip commit. 404 means the branch does not exist."""
        _check_repo(repo)
        return self.get(f"/repos/{repo}/branches/{quote(branch, safe='')}", "branch")

    def branch_commits(self, repo: str, branch: str, since: str) -> list[RawResponse]:
        """Commits reachable from the branch tip with a committer date at or after `since`."""
        _check_repo(repo)
        query = urlencode({"sha": branch, "since": since, "per_page": 100})
        return self.get_pages(f"/repos/{repo}/commits?{query}", "commits")

    def commit_pulls(self, repo: str, sha: str) -> RawResponse:
        """The merged PR(s) that introduced a commit; an empty list means it arrived some other way."""
        _check_repo(repo)
        _check_sha(sha)
        return self.get(f"/repos/{repo}/commits/{sha}/pulls", f"commit_{sha[:12]}_pulls")


def _check_repo(repo: str) -> None:
    if not REPO_PATTERN.match(repo):
        raise ValueError(f"Expected owner/repo, got {repo!r}")


def _check_sha(sha: str) -> None:
    if not SHA_PATTERN.match(sha):
        raise GitHubResponseError(f"Unexpected commit SHA in API response: {sha!r}")
