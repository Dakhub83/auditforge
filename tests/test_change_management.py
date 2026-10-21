"""Pure-function tests for GH-CM-01..03 (no network, no connector)."""

from __future__ import annotations

import copy
import uuid
from datetime import date
from typing import Any

import pytest

from auditforge.checks import change_management as cm
from auditforge.models import Evidence, RawResponse, Status
from tests import change_mgmt_scenario as sc

PERIOD = cm.AuditPeriod.from_dates(date(2026, 1, 1), date(2026, 3, 31))


def raw(body: Any, status: int = 200) -> RawResponse:
    ev = Evidence(
        uuid.uuid4().hex,
        "GET https://api.github.com/x",
        status,
        "2026-04-01T00:00:00+00:00",
        "0" * 64,
        f"raw/{uuid.uuid4().hex}.json",
    )
    return RawResponse(ev, body)


def detail(number: int) -> cm.PullDetail:
    return cm.PullDetail(
        reviews=[raw(sc.REVIEWS[number])],
        check_runs=[raw(sc.CHECK_RUNS[number])],
        status=raw(sc.STATUSES[number]),
    )


def scenario(**overrides: Any) -> cm.ChangeEvidence:
    fields: dict[str, Any] = {
        "pull_pages": [raw(sc.PULLS_PAGE)],
        "details": {n: detail(n) for n in (101, 102, 103)},
        "branch": raw(sc.BRANCH),
        "commit_pages": [raw(sc.COMMITS_PAGE)],
        "commit_pulls": {s: raw(body) for s, body in sc.COMMIT_PULLS.items()},
    }
    return cm.ChangeEvidence(**{**fields, **overrides})


def by_id(findings: list) -> dict:
    return {f.check_id: f for f in findings}


def pr(number: int) -> dict[str, Any]:
    return copy.deepcopy(next(p for p in sc.PULLS_PAGE if p["number"] == number))


# --- Period and population ------------------------------------------------------------


def test_period_end_date_is_inclusive() -> None:
    assert PERIOD.contains("2026-03-31T23:59:59Z")
    assert not PERIOD.contains("2026-04-01T00:00:00Z")
    assert PERIOD.contains("2026-01-01T00:00:00Z")
    assert not PERIOD.contains(None)
    assert PERIOD.label == "2026-01-01 to 2026-03-31"


def test_period_end_before_start_rejected() -> None:
    with pytest.raises(ValueError):
        cm.AuditPeriod.from_dates(date(2026, 2, 1), date(2026, 1, 1))


def test_population_is_merged_in_period_oldest_first() -> None:
    pop = cm.population([raw(sc.PULLS_PAGE)], PERIOD)
    # #104 never merged; #99 and #98 merged before the period even though #99 was updated in it.
    assert [p["number"] for p in pop] == [101, 102, 103]


def test_landed_commits_follow_first_parents_only() -> None:
    landed = cm.landed_commits(raw(sc.BRANCH), [raw(sc.COMMITS_PAGE)], PERIOD)
    assert [c["sha"] for c in landed] == [sc.M103, sc.D1, sc.M102, sc.R1, sc.M101]  # F1 is a PR's own commit


def test_only_non_merge_commits_need_a_pr_lookup() -> None:
    shas = cm.commits_to_trace(raw(sc.BRANCH), [raw(sc.COMMITS_PAGE)], [raw(sc.PULLS_PAGE)], PERIOD)
    assert shas == [sc.D1, sc.R1]


# --- GH-CM-01 approval ----------------------------------------------------------------


def approval(reviews: list[dict[str, Any]], number: int = 101, status: int = 200) -> cm.ItemResult:
    d = cm.PullDetail(reviews=[raw(reviews, status)], check_runs=[], status=raw({}))
    return cm.approval_result(pr(number), d)


def test_independent_approval_on_head_is_ok() -> None:
    result = approval(sc.REVIEWS[101])
    assert result.outcome == cm.OK
    assert result.facts["approvers"] == ["bob"]


def test_later_changes_requested_replaces_approval() -> None:
    reviews = [
        sc.review("bob", "APPROVED", sc.H101, "2026-02-01T10:00:00Z"),
        sc.review("bob", "CHANGES_REQUESTED", sc.H101, "2026-02-01T11:00:00Z"),
    ]
    assert approval(reviews).outcome == cm.EXCEPTION


def test_comment_after_approval_does_not_cancel_it() -> None:
    reviews = [
        sc.review("bob", "APPROVED", sc.H101, "2026-02-01T10:00:00Z"),
        sc.review("bob", "COMMENTED", sc.H101, "2026-02-01T11:00:00Z"),
    ]
    assert approval(reviews).outcome == cm.OK


def test_author_and_bot_approvals_are_not_independent() -> None:
    assert approval([sc.review("ALICE", "APPROVED", sc.H101, "2026-02-01T10:00:00Z")]).outcome == cm.EXCEPTION
    bot = approval([sc.review("autobot[bot]", "APPROVED", sc.H101, "2026-02-01T10:00:00Z", kind="Bot")])
    assert bot.outcome == cm.EXCEPTION
    assert "bot" in bot.note


def test_approval_of_an_earlier_commit_needs_review() -> None:
    result = approval(sc.REVIEWS[102], number=102)
    assert result.outcome == cm.REVIEW
    assert result.facts["approvers_of_earlier_commits"] == ["bob"]


def test_unreadable_reviews_need_review_not_pass() -> None:
    assert approval({"message": "Forbidden"}, status=403).outcome == cm.REVIEW


def test_deleted_author_needs_review() -> None:
    p = pr(101)
    p["user"] = None
    d = cm.PullDetail(reviews=[raw(sc.REVIEWS[101])], check_runs=[], status=raw({}))
    assert cm.approval_result(p, d).outcome == cm.REVIEW


# --- GH-CM-02 CI ----------------------------------------------------------------------


def ci(
    runs: list[dict[str, Any]],
    statuses: list[dict[str, Any]] | None = None,
    runs_status: int = 200,
    state: str = "pending",
) -> cm.ItemResult:
    d = cm.PullDetail(
        reviews=[],
        check_runs=[raw({"total_count": len(runs), "check_runs": runs}, runs_status)],
        status=raw(sc.combined_status(state, statuses or [])),
    )
    return cm.ci_result(pr(101), d)


def test_success_neutral_and_skipped_pass() -> None:
    runs = [sc.check_run("a", "success"), sc.check_run("b", "neutral"), sc.check_run("c", "skipped")]
    assert ci(runs).outcome == cm.OK


@pytest.mark.parametrize("conclusion", ["failure", "cancelled", "timed_out", "action_required"])
def test_non_passing_run_is_exception(conclusion: str) -> None:
    result = ci([sc.check_run("test", conclusion)])
    assert result.outcome == cm.EXCEPTION
    assert f"test={conclusion}" in result.note


def test_run_still_in_progress_is_exception() -> None:
    assert ci([sc.check_run("test", None, status="in_progress")]).outcome == cm.EXCEPTION


def test_failing_legacy_status_is_exception() -> None:
    statuses = [{"context": "jenkins", "state": "failure"}]
    assert ci([sc.check_run("test", "success")], statuses, state="failure").outcome == cm.EXCEPTION


def test_passing_legacy_status_alone_is_ok() -> None:
    assert ci([], [{"context": "jenkins", "state": "success"}], state="success").outcome == cm.OK


def test_no_ci_at_all_needs_review() -> None:
    assert ci([]).outcome == cm.REVIEW


def test_unreadable_check_runs_need_review() -> None:
    result = ci([], [{"context": "jenkins", "state": "success"}], runs_status=403, state="success")
    assert result.outcome == cm.REVIEW
    assert "Checks: read" in result.note


# --- Population findings --------------------------------------------------------------


def test_scenario_findings() -> None:
    findings = by_id(cm.evaluate(scenario(), "acme/payments-api@main", PERIOD))

    cm01 = findings["GH-CM-01"]
    assert cm01.status is Status.FAIL
    assert cm01.detail.startswith("1 of 3 merged PRs")
    assert "#103" in cm01.detail and "A further 1 need manual review" in cm01.detail
    assert cm01.observed["population"] == 3
    assert [i["outcome"] for i in cm01.observed["items"]] == [cm.OK, cm.REVIEW, cm.EXCEPTION]

    cm02 = findings["GH-CM-02"]
    assert cm02.status is Status.FAIL
    assert "#102" in cm02.detail and "test=failure" in cm02.detail

    cm03 = findings["GH-CM-03"]
    assert cm03.status is Status.FAIL
    assert cm03.detail.startswith("1 of 5 commits landed on the branch")
    assert sc.D1[:12] in cm03.detail
    assert "bypass" in cm03.detail


def test_clean_history_passes() -> None:
    pulls = [p for p in sc.PULLS_PAGE if p["number"] in (101, 98)]
    commits = [c for c in sc.COMMITS_PAGE if c["sha"] in (sc.M101, sc.F1)]
    ev = scenario(
        pull_pages=[raw(pulls)],
        details={101: detail(101)},
        branch=raw({"name": "main", "commit": {"sha": sc.M101}}),
        commit_pages=[raw(commits)],
        commit_pulls={},
    )
    findings = cm.evaluate(ev, "acme/payments-api@main", PERIOD)
    assert [f.status for f in findings] == [Status.PASS] * 3
    assert findings[0].detail.startswith("All 1 merged PRs")


def test_unreadable_pr_list_means_no_population() -> None:
    findings = by_id(cm.evaluate(scenario(pull_pages=[raw({"message": "x"}, 403)]), "r@main", PERIOD))
    for check_id in ("GH-CM-01", "GH-CM-02"):
        assert findings[check_id].status is Status.MANUAL_REVIEW
        assert "HTTP 403" in findings[check_id].detail


def test_unreadable_history_needs_review() -> None:
    findings = by_id(cm.evaluate(scenario(commit_pages=[raw({"message": "x"}, 403)]), "r@main", PERIOD))
    assert findings["GH-CM-03"].status is Status.MANUAL_REVIEW
    assert "Contents: read" in findings["GH-CM-03"].detail


def test_empty_period_is_manual_review_not_pass() -> None:
    quiet = cm.AuditPeriod.from_dates(date(2026, 6, 1), date(2026, 6, 30))
    findings = cm.evaluate(scenario(), "r@main", quiet)
    assert [f.status for f in findings] == [Status.MANUAL_REVIEW] * 3


def test_long_exception_lists_are_truncated_in_detail() -> None:
    pulls = [
        sc.pull(n, "alice", "2026-02-01T12:00:00Z", "2026-02-01T12:00:00Z", sc.sha(f"h{n}"), None)
        for n in range(200, 215)
    ]
    details = {
        n: cm.PullDetail(
            reviews=[raw([])], check_runs=[raw(sc.CHECK_RUNS[101])], status=raw(sc.STATUSES[101])
        )
        for n in range(200, 215)
    }
    cm01 = cm.evaluate(scenario(pull_pages=[raw(pulls)], details=details), "r@main", PERIOD)[0]
    assert cm01.detail.startswith("15 of 15")
    assert "and 5 more" in cm01.detail
    assert len(cm01.observed["items"]) == 15


def test_findings_cite_the_evidence_they_rest_on() -> None:
    ev = scenario()
    findings = by_id(cm.evaluate(ev, "r@main", PERIOD))
    list_id = ev.pull_pages[0].evidence.evidence_id
    assert list_id in findings["GH-CM-01"].evidence_ids
    assert ev.details[101].reviews[0].evidence.evidence_id in findings["GH-CM-01"].evidence_ids
    assert ev.details[101].status.evidence.evidence_id in findings["GH-CM-02"].evidence_ids
    assert ev.commit_pulls[sc.D1].evidence.evidence_id in findings["GH-CM-03"].evidence_ids
