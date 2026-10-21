"""Change management integrity checks (GH-CM-01..03), tested over the full population.

Pure functions over the raw GitHub responses a connector collected. No network
access, no framework IDs. Where GH-BP-* tests how a branch is configured (control
design), these test what actually happened to every change in the audit period
(operating effectiveness).

The population is every pull request merged into the branch during the period.
It is rebuilt here from the saved PR list pages, so an auditor can re-derive it
from the evidence instead of trusting the tool's selection.

- GH-CM-01: each merged PR was approved by someone other than its author, on the commit that merged.
- GH-CM-02: CI passed on each merged PR's final commit.
- GH-CM-03: every commit that landed on the branch in the period came through a merged PR, so
  nobody pushed around review. This is the trace a direct-push admin bypass leaves.

Known limits (each shows up as MANUAL_REVIEW or in the finding detail, never as a silent PASS):
- The PR API does not say whether a merge bypassed branch protection. A bypassed merge shows up
  here as a PR merged without an independent approval (GH-CM-01) or with failing CI (GH-CM-02).
- Commit dates are set by the client. A direct push with a backdated committer date can fall
  outside the window GH-CM-03 walks. The org audit log (GitHub Enterprise) is authoritative for pushes.
- Check results are read as they are now, not as they were at merge time.
- GH-CM-01 compares approvers to the PR author only. A reviewer who pushed commits to the PR and
  then approved it is not detected; GitHub's "require approval of the most recent reviewable push"
  setting prevents that.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from auditforge.checks.population import (
    EXCEPTION,
    OK,
    REVIEW,
    AuditPeriod,
    ItemResult,
    parse_ts,
    population_status,
    summary,
)
from auditforge.models import Finding, RawResponse, Status

# A check run with one of these conclusions did not block the change. "skipped" and
# "neutral" are how CI reports jobs that legitimately didn't apply (e.g. path filters).
_PASSING_CONCLUSIONS = {"success", "neutral", "skipped"}
# Review states that change a reviewer's standing verdict. COMMENTED does not.
_VERDICT_STATES = {"APPROVED", "CHANGES_REQUESTED", "DISMISSED"}


@dataclass(frozen=True)
class PullDetail:
    """Per-PR evidence: reviews, and the CI results on the PR's final (merged) head commit."""

    reviews: list[RawResponse]
    check_runs: list[RawResponse]
    status: RawResponse


@dataclass(frozen=True)
class ChangeEvidence:
    pull_pages: list[RawResponse]
    details: dict[int, PullDetail]
    branch: RawResponse
    commit_pages: list[RawResponse]
    commit_pulls: dict[str, RawResponse]  # sha -> /commits/{sha}/pulls, for commits not matched to a PR


def _pages_ok(pages: list[RawResponse]) -> bool:
    return bool(pages) and all(p.status == 200 and isinstance(p.body, list) for p in pages)


def _pages_problem(pages: list[RawResponse], what: str) -> str:
    bad = next((p for p in pages if p.status != 200 or not isinstance(p.body, list)), None)
    if bad is None:
        return f"no {what} pages were collected"
    return f"{what} page {pages.index(bad) + 1} returned HTTP {bad.status}"


def _items(pages: list[RawResponse]) -> list[dict[str, Any]]:
    return [item for p in pages if isinstance(p.body, list) for item in p.body]


def merged_pulls(pull_pages: list[RawResponse]) -> list[dict[str, Any]]:
    return [pr for pr in _items(pull_pages) if pr.get("merged_at")]


def population(pull_pages: list[RawResponse], period: AuditPeriod) -> list[dict[str, Any]]:
    """PRs merged into the branch during the period, oldest merge first.

    Closed-but-unmerged PRs are excluded: nothing from them reached the branch.
    """
    in_period = [pr for pr in merged_pulls(pull_pages) if period.contains(pr["merged_at"])]
    return sorted(in_period, key=lambda pr: (parse_ts(pr["merged_at"]), pr["number"]))


def landed_commits(
    branch: RawResponse, commit_pages: list[RawResponse], period: AuditPeriod
) -> list[dict[str, Any]]:
    """Commits that landed on the branch itself in the period, newest first.

    Walks first parents from the branch tip (git log --first-parent). A merge commit's other
    parents are the PR's own commits; they are covered by whoever approved that merge, so only
    the first-parent chain shows how each change reached the branch.
    """
    if branch.status != 200 or not isinstance(branch.body, dict):
        return []
    by_sha = {c["sha"]: c for c in _items(commit_pages)}
    chain: list[dict[str, Any]] = []
    sha = (branch.body.get("commit") or {}).get("sha")
    while sha in by_sha:
        commit = by_sha[sha]
        chain.append(commit)
        parents = commit.get("parents") or []
        sha = parents[0]["sha"] if parents else None
    return [c for c in chain if period.contains(_committed_at(c))]


def _committed_at(commit: dict[str, Any]) -> str | None:
    return ((commit.get("commit") or {}).get("committer") or {}).get("date")


def commits_to_trace(
    branch: RawResponse, commit_pages: list[RawResponse], pull_pages: list[RawResponse], period: AuditPeriod
) -> list[str]:
    """Landed commits that are not the merge commit of a known merged PR, so need a PR lookup.

    Squash and merge-commit merges land exactly one commit, the PR's merge_commit_sha. A rebase
    merge lands several, and only the last one is the merge_commit_sha.
    """
    merge_shas = {pr.get("merge_commit_sha") for pr in merged_pulls(pull_pages)}
    return [c["sha"] for c in landed_commits(branch, commit_pages, period) if c["sha"] not in merge_shas]


# --- Per-item evaluation --------------------------------------------------------------


def _login(user: dict[str, Any] | None) -> str | None:
    return (user or {}).get("login")


def _pr_facts(pr: dict[str, Any]) -> dict[str, Any]:
    return {
        "number": pr["number"],
        "title": pr.get("title"),
        "author": _login(pr.get("user")),
        "merged_at": pr.get("merged_at"),
        "head_sha": (pr.get("head") or {}).get("sha"),
        "merge_commit_sha": pr.get("merge_commit_sha"),
    }


def approval_result(pr: dict[str, Any], detail: PullDetail | None) -> ItemResult:
    facts = _pr_facts(pr)
    item = f"#{pr['number']}"
    if detail is None or not _pages_ok(detail.reviews):
        problem = _pages_problem(detail.reviews, "reviews") if detail else "reviews were not collected"
        return ItemResult(item, REVIEW, f"reviews could not be read ({problem})", facts)
    author = facts["author"]
    if not author:
        return ItemResult(
            item, REVIEW, "author account no longer exists; confirm who wrote the change", facts
        )

    # Each reviewer's latest verdict counts: a later "changes requested" or a dismissal
    # replaces an earlier approval.
    latest: dict[str, dict[str, Any]] = {}
    reviews = sorted(_items(detail.reviews), key=lambda r: r.get("submitted_at") or "")
    for review in reviews:
        login = _login(review.get("user"))
        if login and review.get("state") in _VERDICT_STATES:
            latest[login.lower()] = review
    approvals = [r for r in latest.values() if r["state"] == "APPROVED"]
    # Independent = a human other than the author. A bot approval is automation, not review.
    independent = [
        r
        for r in approvals
        if r["user"]["login"].lower() != author.lower() and r["user"].get("type") != "Bot"
    ]
    current = [r for r in independent if r.get("commit_id") == facts["head_sha"]]
    facts["approvers"] = sorted(r["user"]["login"] for r in current)
    facts["approvers_of_earlier_commits"] = sorted(
        r["user"]["login"] for r in independent if r not in current
    )

    if current:
        return ItemResult(item, OK, f"approved by {', '.join(facts['approvers'])}", facts)
    if independent:
        # Often just "Update branch" after approval, which changes the head but not the diff.
        # Telling that apart needs the diff, so a human decides.
        return ItemResult(
            item,
            REVIEW,
            "approved on an earlier commit than the one merged; confirm later commits were only "
            "base-branch updates or were re-reviewed",
            facts,
        )
    if approvals:
        return ItemResult(item, EXCEPTION, "only approval came from a bot account", facts)
    return ItemResult(item, EXCEPTION, "merged without an independent approval", facts)


def ci_result(pr: dict[str, Any], detail: PullDetail | None) -> ItemResult:
    facts = _pr_facts(pr)
    item = f"#{pr['number']}"
    if detail is None:
        return ItemResult(item, REVIEW, "CI results were not collected", facts)

    unreadable: list[str] = []
    runs: list[dict[str, Any]] = []
    if all(p.status == 200 and isinstance(p.body, dict) for p in detail.check_runs) and detail.check_runs:
        runs = [r for p in detail.check_runs for r in p.body.get("check_runs") or []]
    else:
        unreadable.append("check runs (token needs 'Checks: read')")
    statuses: list[dict[str, Any]] = []
    if detail.status.status == 200 and isinstance(detail.status.body, dict):
        statuses = detail.status.body.get("statuses") or []
    else:
        unreadable.append("commit statuses (token needs 'Commit statuses: read')")

    # A run still in progress has conclusion None, so it counts as not passed.
    failing = [
        f"{r.get('name')}={r.get('conclusion') or r.get('status')}"
        for r in runs
        if r.get("conclusion") not in _PASSING_CONCLUSIONS
    ]
    failing += [f"{s.get('context')}={s.get('state')}" for s in statuses if s.get("state") != "success"]
    facts["checks_total"] = len(runs) + len(statuses)
    facts["checks_not_passed"] = failing

    if failing:
        return ItemResult(item, EXCEPTION, f"merged with CI not passing: {', '.join(failing)}", facts)
    if unreadable:
        return ItemResult(item, REVIEW, f"could not read {' or '.join(unreadable)}", facts)
    if not runs and not statuses:
        return ItemResult(
            item,
            REVIEW,
            "no CI results on the merged commit; if CI runs outside GitHub, obtain its results",
            facts,
        )
    return ItemResult(item, OK, f"{facts['checks_total']} check(s) passed", facts)


def landing_result(
    commit: dict[str, Any], merged_by_sha: dict[str, int], lookup: RawResponse | None
) -> ItemResult:
    sha = commit["sha"]
    facts = {
        "sha": sha,
        "committed_at": _committed_at(commit),
        "author": _login(commit.get("author"))
        or ((commit.get("commit") or {}).get("author") or {}).get("name"),
        "committer": _login(commit.get("committer")),
        "message": ((commit.get("commit") or {}).get("message") or "").split("\n", 1)[0],
    }
    if sha in merged_by_sha:
        facts["pull_request"] = merged_by_sha[sha]
        return ItemResult(sha, OK, f"merge of #{merged_by_sha[sha]}", facts)
    if lookup is None or lookup.status != 200 or not isinstance(lookup.body, list):
        status = "not collected" if lookup is None else f"HTTP {lookup.status}"
        return ItemResult(sha, REVIEW, f"could not look up the PR for this commit ({status})", facts)
    merged = [p for p in lookup.body if p.get("merged_at")]
    if merged:
        facts["pull_request"] = merged[0]["number"]
        return ItemResult(sha, OK, f"introduced by #{merged[0]['number']}", facts)
    return ItemResult(sha, EXCEPTION, "pushed directly, not through a merged pull request", facts)


# --- Population findings --------------------------------------------------------------


def evaluate(ev: ChangeEvidence, resource: str, period: AuditPeriod) -> list[Finding]:
    pulls_complete = _pages_ok(ev.pull_pages)
    pop = population(ev.pull_pages, period)
    pull_page_ids = [p.evidence.evidence_id for p in ev.pull_pages]
    base_observed = {"period": period.label, "pull_list_pages": len(ev.pull_pages)}

    def pr_finding(
        check_id: str, title: str, results: list[ItemResult], passed: str, failed: str, detail_ids: list[str]
    ) -> Finding:
        if not pulls_complete:
            status, detail = (
                Status.MANUAL_REVIEW,
                "The merged-PR population could not be established: "
                f"{_pages_problem(ev.pull_pages, 'PR list')} "
                "(the token needs 'Pull requests: read').",
            )
        elif not results:
            status, detail = (
                Status.MANUAL_REVIEW,
                f"No pull requests were merged in {period.label}. Confirm the period and branch are right, "
                "and that changes did not reach the branch some other way (see GH-CM-03).",
            )
        else:
            status, detail = population_status(results, "merged PRs", passed, failed)
        return Finding(
            check_id=check_id,
            title=title,
            resource=resource,
            status=status,
            detail=detail,
            observed={**base_observed, **summary(results)},
            evidence_ids=pull_page_ids + detail_ids,
        )

    approvals = [approval_result(pr, ev.details.get(pr["number"])) for pr in pop]
    review_ids = [p.evidence.evidence_id for d in ev.details.values() for p in d.reviews]
    ci = [ci_result(pr, ev.details.get(pr["number"])) for pr in pop]
    ci_ids = [p.evidence.evidence_id for d in ev.details.values() for p in [*d.check_runs, d.status]]

    return [
        pr_finding(
            "GH-CM-01",
            "Every merged change independently approved",
            approvals,
            "were approved by someone other than the author, on the commit that merged",
            "were merged without an independent approval of the final code",
            review_ids,
        ),
        pr_finding(
            "GH-CM-02",
            "Every merged change passed CI",
            ci,
            "passed CI on the merged commit",
            "were merged with CI not passing",
            ci_ids,
        ),
        _landing_finding(ev, resource, period, base_observed, pull_page_ids),
    ]


def _landing_finding(
    ev: ChangeEvidence,
    resource: str,
    period: AuditPeriod,
    base_observed: dict[str, Any],
    pull_page_ids: list[str],
) -> Finding:
    evidence_ids = [
        ev.branch.evidence.evidence_id,
        *(p.evidence.evidence_id for p in ev.commit_pages),
        *(r.evidence.evidence_id for r in ev.commit_pulls.values()),
        *pull_page_ids,
    ]
    landed = landed_commits(ev.branch, ev.commit_pages, period)
    merged_by_sha = {
        pr["merge_commit_sha"]: pr["number"]
        for pr in merged_pulls(ev.pull_pages)
        if pr.get("merge_commit_sha")
    }
    results = [landing_result(c, merged_by_sha, ev.commit_pulls.get(c["sha"])) for c in landed]
    observed = {**base_observed, "commit_pages": len(ev.commit_pages), **summary(results)}

    if ev.branch.status != 200 or not _pages_ok(ev.commit_pages):
        problem = (
            f"branch lookup returned HTTP {ev.branch.status}"
            if ev.branch.status != 200
            else _pages_problem(ev.commit_pages, "commit history")
        )
        status, detail = (
            Status.MANUAL_REVIEW,
            f"Branch history could not be read ({problem}; the token needs 'Contents: read').",
        )
    elif not results:
        status, detail = (
            Status.MANUAL_REVIEW,
            f"No commits landed on the branch in {period.label}. Confirm the period and branch are right.",
        )
    else:
        status, detail = population_status(
            results,
            "commits landed on the branch",
            "came through a merged pull request",
            "did not come through a merged pull request",
        )
        if status is Status.FAIL:
            detail += " Direct pushes to a protected branch indicate an admin or ruleset bypass."
    return Finding(
        check_id="GH-CM-03",
        title="No changes reached the branch outside a pull request",
        resource=resource,
        status=status,
        detail=detail,
        observed=observed,
        evidence_ids=evidence_ids,
    )
