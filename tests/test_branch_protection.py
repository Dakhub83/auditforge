from __future__ import annotations

from typing import Any

import pytest

from auditforge.checks.branch_protection import evaluate
from auditforge.models import Evidence, Finding, RawResponse, Status
from tests.conftest import load_fixture

PASS, FAIL, MANUAL = Status.PASS, Status.FAIL, Status.MANUAL_REVIEW


def raw(status: int, body: Any, evidence_id: str) -> RawResponse:
    ev = Evidence(
        evidence_id, "GET test", status, "2026-01-01T00:00:00+00:00", "0" * 64, f"raw/{evidence_id}"
    )
    return RawResponse(ev, body)


def classic(status: int, fixture: str | None = None, body: Any = None) -> RawResponse:
    return raw(status, load_fixture(fixture) if fixture else body, "classic")


def rules(status: int, fixture: str | None = None, body: Any = None) -> RawResponse:
    return raw(status, load_fixture(fixture) if fixture else body, "rules")


def statuses(findings: list[Finding]) -> dict[str, Status]:
    return {f.check_id: f.status for f in findings}


def run(c: RawResponse, r: RawResponse, min_approvals: int = 1) -> dict[str, Status]:
    return statuses(evaluate(c, r, "acme/payments-api@main", min_approvals))


def test_strong_classic_no_rulesets_all_pass() -> None:
    result = run(classic(200, "classic_strong.json"), rules(200, body=[]))
    assert result == dict.fromkeys(result, PASS)


def test_weak_classic_fails_everything() -> None:
    result = run(classic(200, "classic_weak.json"), rules(200, body=[]))
    assert result == dict.fromkeys(result, FAIL)


def test_unprotected_branch_fails_and_admin_needs_review() -> None:
    result = run(classic(404, "not_protected_404.json"), rules(200, body=[]))
    assert result == {
        "GH-BP-01": FAIL,
        "GH-BP-02": FAIL,
        "GH-BP-03": FAIL,
        "GH-BP-04": FAIL,
        "GH-BP-05": MANUAL,
    }


def test_rulesets_only_pass_but_bypass_list_needs_review() -> None:
    result = run(classic(404, "not_protected_404.json"), rules(200, "rulesets_strong.json"))
    assert result == {
        "GH-BP-01": PASS,
        "GH-BP-02": PASS,
        "GH-BP-03": PASS,
        "GH-BP-04": PASS,
        "GH-BP-05": MANUAL,
    }


def test_classic_unreadable_without_rulesets_is_manual_not_fail() -> None:
    # The prototype reported FAIL here even though it never saw classic protection.
    result = run(classic(403, "forbidden_403.json"), rules(200, body=[]))
    assert result == dict.fromkeys(result, MANUAL)


def test_classic_unreadable_detail_names_missing_permission() -> None:
    findings = evaluate(classic(403, "forbidden_403.json"), rules(200, body=[]), "r@main", 1)
    assert "HTTP 403" in findings[0].detail
    assert "Administration: read" in findings[0].detail


def test_classic_unreadable_rulesets_still_prove_pass() -> None:
    result = run(classic(403, "forbidden_403.json"), rules(200, "rulesets_strong.json"))
    assert result == {
        "GH-BP-01": PASS,
        "GH-BP-02": PASS,
        "GH-BP-03": PASS,
        "GH-BP-04": PASS,
        "GH-BP-05": MANUAL,
    }


def test_rulesets_unreadable_with_weak_classic_is_manual() -> None:
    result = run(classic(200, "classic_weak.json"), rules(500, body=None))
    # enforce_admins is explicitly off in classic protection: that is a real FAIL.
    assert result == {
        "GH-BP-01": MANUAL,
        "GH-BP-02": MANUAL,
        "GH-BP-03": MANUAL,
        "GH-BP-04": MANUAL,
        "GH-BP-05": FAIL,
    }


@pytest.mark.parametrize(("threshold", "expected"), [(1, PASS), (2, PASS), (3, FAIL)])
def test_approval_threshold(threshold: int, expected: Status) -> None:
    # classic_strong requires 2 approvals.
    result = run(classic(200, "classic_strong.json"), rules(200, body=[]), min_approvals=threshold)
    assert result["GH-BP-02"] is expected


def test_approvals_take_max_across_sources() -> None:
    weak_pr = {"required_pull_request_reviews": {"required_approving_review_count": 0}}
    result = run(classic(200, body=weak_pr), rules(200, "rulesets_strong.json"))
    assert result["GH-BP-02"] is PASS


def test_admin_enforced_but_rulesets_present_needs_review() -> None:
    result = run(classic(200, "classic_strong.json"), rules(200, "rulesets_strong.json"))
    assert result["GH-BP-05"] is MANUAL


def test_admin_enforced_rulesets_unreadable_needs_review() -> None:
    result = run(classic(200, "classic_strong.json"), rules(403, body=None))
    assert result["GH-BP-05"] is MANUAL


def test_findings_link_both_evidence_items_and_carry_no_framework_ids() -> None:
    findings = evaluate(classic(200, "classic_strong.json"), rules(200, body=[]), "acme/payments-api@main", 1)
    assert len(findings) == 5
    for f in findings:
        assert f.evidence_ids == ["classic", "rules"]
        assert f.resource == "acme/payments-api@main"
        assert "CC8.1" not in repr(f)
    assert len({f.finding_id for f in findings}) == 5
