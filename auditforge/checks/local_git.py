"""Change management checks from a local git clone (GIT-CM-01..03). No network, no API.

Pure functions over the output of read-only git commands a connector saved. No
framework IDs. These mirror GH-CM-01..03, but git only records what landed on a
branch and who committed it, so the evidence supports less:

- GIT-CM-03 (no changes outside a PR) is decidable. When GitHub merges a pull
  request (merge, squash or rebase), it creates the landing commit itself: the
  committer is GitHub and the commit is signed with GitHub's web-flow key. A
  commit on the branch with any other committer was made on someone's machine
  and pushed directly. The committer name and email can be typed by anyone, so
  only a good signature from GitHub's key counts as proof.
- GIT-CM-01 (independent approval) and GIT-CM-02 (CI passed) are not in git at
  all. They are always MANUAL_REVIEW, listing every change that landed in the
  period, which is the population a reviewer must check in GitHub.

Known limits:
- The clone is analysed as last fetched; changes pushed since then are not seen.
- Commit dates are set by the client, so a backdated direct push can fall outside the period.
- A merge through GitHub proves the change went through a pull request, not that the PR was
  approved or that an admin did not bypass review when merging (that is GIT-CM-01).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from auditforge.checks.population import (
    EXCEPTION,
    MAX_LISTED,
    OK,
    REVIEW,
    AuditPeriod,
    ItemResult,
    population_status,
    summary,
)
from auditforge.connectors.git import LOG_FIELDS
from auditforge.models import CommandOutput, Finding, Status

GITHUB_MERGE_COMMITTER_EMAIL = "noreply@github.com"
# Long key IDs of GitHub's web-flow keys, which sign the commits github.com creates when it
# merges a PR: 4AEE18F83AFDEB23 until January 2024, B5690EEEBB952194 since. The public keys are
# published at https://github.com/web-flow.gpg; import them into gpg once so git can check them.
GITHUB_WEB_FLOW_KEYS = ("B5690EEEBB952194", "4AEE18F83AFDEB23")
# git's %G? codes for a cryptographically good signature: G good, U good but key trust unknown,
# X good but signature expired, Y good but key expired (the pre-2024 web-flow key has expired).
_GOOD_SIGNATURE = {"G", "U", "X", "Y"}
# GitHub's default merge and squash messages carry the PR number; rebase merges carry none.
_PR_NUMBER = re.compile(r"(?:^Merge pull request #(\d+)\b)|(?:\(#(\d+)\)$)")


@dataclass(frozen=True)
class GitEvidence:
    shallow: CommandOutput
    ref: CommandOutput
    remote: CommandOutput
    log: CommandOutput | None  # None if the ref did not resolve


def parse_log(text: str) -> list[dict[str, Any]]:
    """Commits from LOG_FORMAT output, newest first. Malformed records raise ValueError."""
    names = [name for name, _ in LOG_FIELDS]
    commits = []
    for record in text.split("\x1e"):
        record = record.strip("\r\n")
        if not record:
            continue
        fields = record.split("\x1f")
        if len(fields) != len(names):
            raise ValueError(f"Unexpected git log record with {len(fields)} fields")
        commit: dict[str, Any] = dict(zip(names, fields, strict=True))
        commit["parents"] = commit["parents"].split()
        commits.append(commit)
    return commits


def pr_number(subject: str) -> int | None:
    match = _PR_NUMBER.search(subject)
    return int(match.group(1) or match.group(2)) if match else None


def _history_problem(ev: GitEvidence) -> str | None:
    if not ev.ref.ok or ev.log is None:
        return f"the ref could not be resolved ({ev.ref.error or 'no output'})"
    if not ev.log.ok:
        return f"git log failed with exit code {ev.log.evidence.exit_code} ({ev.log.error})"
    if ev.shallow.text.strip() != "false":
        return "the clone is shallow, so older history may be missing (run: git fetch --unshallow)"
    return None


def landing_result(
    commit: dict[str, Any],
    trusted_keys: tuple[str, ...] = GITHUB_WEB_FLOW_KEYS,
    merge_committer_email: str = GITHUB_MERGE_COMMITTER_EMAIL,
) -> ItemResult:
    number = pr_number(commit["subject"])
    facts = {
        "sha": commit["sha"],
        "committed_at": commit["committed_at"],
        "author": f"{commit['author_name']} <{commit['author_email']}>",
        "committer": f"{commit['committer_name']} <{commit['committer_email']}>",
        "signature": commit["signature"],
        "signing_key": commit["signing_fingerprint"] or commit["signing_key"],
        "subject": commit["subject"],
        "pull_request": number,
    }
    sha, sig, key = commit["sha"], commit["signature"], facts["signing_key"].upper()
    if commit["committer_email"].lower() != merge_committer_email:
        return ItemResult(
            sha,
            EXCEPTION,
            f"direct push: committed by {commit['committer_name']}, not by GitHub's merge",
            facts,
        )
    trusted = bool(key) and any(key.endswith(k) for k in trusted_keys)
    if sig in _GOOD_SIGNATURE and trusted:
        via = f"#{number}" if number else "a pull request (rebase merge)"
        return ItemResult(sha, OK, f"merged through GitHub from {via}", facts)
    if sig == "B" or (sig in _GOOD_SIGNATURE and not trusted):
        return ItemResult(
            sha,
            EXCEPTION,
            "names GitHub as committer but is not signed by GitHub's key; possibly forged",
            facts,
        )
    if sig == "E":
        return ItemResult(
            sha,
            REVIEW,
            "signature could not be checked; import GitHub's web-flow key into gpg and re-run",
            facts,
        )
    if sig == "N":
        return ItemResult(
            sha,
            REVIEW,
            "names GitHub as committer but is unsigned; confirm in GitHub it came from a PR",
            facts,
        )
    return ItemResult(sha, REVIEW, f"signature status {sig!r} (e.g. revoked key); confirm in GitHub", facts)


def evaluate(
    ev: GitEvidence,
    resource: str,
    period: AuditPeriod,
    trusted_keys: tuple[str, ...] = GITHUB_WEB_FLOW_KEYS,
    merge_committer_email: str = GITHUB_MERGE_COMMITTER_EMAIL,
) -> list[Finding]:
    problem = _history_problem(ev)
    landed = [] if problem or ev.log is None else parse_log(ev.log.text)
    landed = [c for c in landed if period.contains(c["committed_at"])]
    landings = [landing_result(c, trusted_keys, merge_committer_email.lower()) for c in landed]

    evidence_ids = [o.evidence.evidence_id for o in (ev.shallow, ev.ref, ev.remote, ev.log) if o is not None]
    observed = {
        "period": period.label,
        "source": "local git clone",
        "ref_commit": ev.ref.text.strip() if ev.ref.ok else None,
        "remote": ev.remote.text.strip() if ev.remote.ok else None,
    }

    def finding(check_id: str, title: str, results: list[ItemResult], status: Status, detail: str) -> Finding:
        return Finding(
            check_id=check_id,
            title=title,
            resource=resource,
            status=status,
            detail=detail,
            observed={**observed, **summary(results)},
            evidence_ids=list(evidence_ids),
        )

    if problem:
        blocked = (Status.MANUAL_REVIEW, f"Branch history could not be analysed: {problem}.")
        cm01 = cm02 = cm03 = blocked
    elif not landed:
        empty = (
            Status.MANUAL_REVIEW,
            f"No commits landed on the branch in {period.label}. Confirm the period and ref are right, "
            "and that the clone was fetched after the period ended.",
        )
        cm01 = cm02 = cm03 = empty
    else:
        listing = _listing(landings)
        cm01 = (
            Status.MANUAL_REVIEW,
            f"Approvals are recorded in GitHub, not in git, so a local clone cannot show them. Confirm in "
            f"GitHub that each of the {len(landings)} changes that landed in {period.label} was approved by "
            f"someone other than its author, on the final commit: {listing}.",
        )
        cm02 = (
            Status.MANUAL_REVIEW,
            f"CI results are recorded in GitHub or the CI system, not in git. Confirm CI passed on "
            f"the merged commit for each of the {len(landings)} changes that landed in "
            f"{period.label}: {listing}.",
        )
        cm03 = population_status(
            landings,
            "commits landed on the branch",
            "were merged through GitHub, signed with GitHub's key",
            "were not merged through GitHub",
        )
        if cm03[0] is Status.FAIL:
            cm03 = (
                cm03[0],
                cm03[1] + " Direct pushes to a protected branch indicate an admin or ruleset bypass.",
            )

    # Every landed change needs a human check for approvals and CI, so they are all REVIEW items.
    to_check = [
        ItemResult(r.item, REVIEW, "check approval and CI in GitHub", {**r.facts, "landing": r.outcome})
        for r in landings
    ]
    return [
        finding("GIT-CM-01", "Every merged change independently approved", to_check, *cm01),
        finding("GIT-CM-02", "Every merged change passed CI", to_check, *cm02),
        finding("GIT-CM-03", "No changes reached the branch outside a pull request", landings, *cm03),
    ]


def _listing(results: list[ItemResult]) -> str:
    labels = [f"#{r.facts['pull_request']}" if r.facts["pull_request"] else r.item[:12] for r in results]
    more = len(labels) - MAX_LISTED
    return ", ".join(labels[:MAX_LISTED]) + (
        f", and {more} more (see observed in report.json)" if more > 0 else ""
    )
