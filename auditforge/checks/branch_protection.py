"""GitHub branch protection checks (GH-BP-01..05).

Pure functions: they take the raw classic-protection and rulesets responses a
connector collected and return Findings. No network access, no framework IDs.

GitHub has two independent protection mechanisms, classic branch protection
and repository rulesets, and a setting is enforced if either one enforces it.
So a requirement found in one source is a PASS even if the other source could
not be read, but a requirement found in neither is only a FAIL when both
sources were actually readable. Otherwise it is MANUAL_REVIEW.
"""

from __future__ import annotations

from typing import Any

from auditforge.models import Finding, RawResponse, Status

# 404 on the classic endpoint means "branch not protected", which is a real
# answer. Anything else except 200 (typically 403) means we could not see it.
_CLASSIC_READABLE = (200, 404)


def effective_settings(classic: RawResponse, rules: RawResponse) -> dict[str, Any]:
    """Merge classic protection and rulesets into one view of what is enforced."""
    classic_readable = classic.status in _CLASSIC_READABLE
    rules_readable = rules.status == 200 and isinstance(rules.body, list)
    eff: dict[str, Any] = {
        "pr_required": False,
        "approvals": 0,
        "dismiss_stale": False,
        "signed_commits": False,
        "enforce_admins": None,  # None = unknown; only classic protection exposes this
        "ruleset_rules_present": None,  # None = rulesets unreadable
        "sources": [],
        "classic_http_status": classic.status,
        "rules_http_status": rules.status,
        "classic_readable": classic_readable,
        "rules_readable": rules_readable,
    }

    if classic.status == 200 and isinstance(classic.body, dict):
        eff["sources"].append("classic_branch_protection")
        pr = classic.body.get("required_pull_request_reviews")
        if pr:
            eff["pr_required"] = True
            eff["approvals"] = pr.get("required_approving_review_count", 0)
            eff["dismiss_stale"] = bool(pr.get("dismiss_stale_reviews"))
        eff["signed_commits"] = bool((classic.body.get("required_signatures") or {}).get("enabled"))
        eff["enforce_admins"] = bool((classic.body.get("enforce_admins") or {}).get("enabled"))

    if rules_readable:
        eff["ruleset_rules_present"] = bool(rules.body)
        if rules.body:
            eff["sources"].append("repository_rulesets")
        for rule in rules.body:
            rtype = rule.get("type")
            params = rule.get("parameters") or {}
            if rtype == "pull_request":
                eff["pr_required"] = True
                eff["approvals"] = max(eff["approvals"], params.get("required_approving_review_count", 0))
                eff["dismiss_stale"] = eff["dismiss_stale"] or bool(
                    params.get("dismiss_stale_reviews_on_push")
                )
            elif rtype == "required_signatures":
                eff["signed_commits"] = True
    return eff


def _blind_spots(eff: dict[str, Any]) -> str:
    parts = []
    if not eff["classic_readable"]:
        parts.append(
            f"classic branch protection returned HTTP {eff['classic_http_status']} "
            "(the token needs 'Administration: read')"
        )
    if not eff["rules_readable"]:
        parts.append(f"repository rulesets returned HTTP {eff['rules_http_status']}")
    return "; ".join(parts)


def _decide(satisfied: bool, eff: dict[str, Any], pass_detail: str, fail_detail: str) -> tuple[Status, str]:
    if satisfied:
        return Status.PASS, pass_detail
    if eff["classic_readable"] and eff["rules_readable"]:
        return Status.FAIL, fail_detail
    return (
        Status.MANUAL_REVIEW,
        f"Not enforced by any source AuditForge could read, but {_blind_spots(eff)}. "
        "Check the branch settings manually before concluding.",
    )


def _admin_enforcement(eff: dict[str, Any]) -> tuple[Status, str]:
    if eff["enforce_admins"] is False:
        return (
            Status.FAIL,
            "Administrators can bypass classic protection, which defeats segregation of duties.",
        )
    if eff["enforce_admins"] is True and eff["ruleset_rules_present"] is False:
        return Status.PASS, "Administrators are subject to the same rules."
    if eff["enforce_admins"] is True:
        # Rulesets have their own bypass list, which this endpoint does not return.
        return (
            Status.MANUAL_REVIEW,
            "Classic protection applies to administrators, but rulesets also apply to this branch (or "
            "could not be read) and their bypass list is not visible here. Review the ruleset bypass list "
            "in Settings > Rules and record who may bypass, with business justification.",
        )
    return (
        Status.MANUAL_REVIEW,
        "Classic protection is absent or unreadable, so administrator enforcement cannot be confirmed. "
        "Review the ruleset bypass list in Settings > Rules and record who may bypass, "
        "with business justification.",
    )


def evaluate(classic: RawResponse, rules: RawResponse, resource: str, min_approvals: int) -> list[Finding]:
    eff = effective_settings(classic, rules)
    observed = {k: v for k, v in eff.items() if k not in ("classic_readable", "rules_readable")}
    evidence_ids = [classic.evidence.evidence_id, rules.evidence.evidence_id]

    results: list[tuple[str, str, tuple[Status, str]]] = [
        (
            "GH-BP-01",
            "Changes require a pull request",
            _decide(
                eff["pr_required"],
                eff,
                "Direct pushes are blocked; changes go through a PR.",
                "No PR requirement found; code can be pushed straight to the branch.",
            ),
        ),
        (
            "GH-BP-02",
            f"At least {min_approvals} approving review(s) before merge",
            _decide(
                eff["approvals"] >= min_approvals,
                eff,
                f"Required approvals configured: {eff['approvals']} (threshold {min_approvals}).",
                f"Required approvals configured: {eff['approvals']} (threshold {min_approvals}).",
            ),
        ),
        (
            "GH-BP-03",
            "Stale approvals dismissed on new commits",
            _decide(
                eff["dismiss_stale"],
                eff,
                "New pushes invalidate earlier approvals.",
                "An approval stays valid after new code is pushed, so unreviewed code can merge.",
            ),
        ),
        (
            "GH-BP-04",
            "Signed commits required",
            _decide(
                eff["signed_commits"],
                eff,
                "Commit signature verification is enforced.",
                "Unsigned commits are accepted; author identity is not cryptographically verified.",
            ),
        ),
        ("GH-BP-05", "Protection enforced for administrators", _admin_enforcement(eff)),
    ]
    return [
        Finding(
            check_id=check_id,
            title=title,
            resource=resource,
            status=status,
            detail=detail,
            observed=dict(observed),
            evidence_ids=list(evidence_ids),
        )
        for check_id, title, (status, detail) in results
    ]
