"""Decide, for each in-scope control, whether it is covered or a gap, then rank and size gaps.

Pure functions: inputs are collected elsewhere (latest automated results, latest attestation,
linked risks), so every decision here can be tested and explained without a database.

Decision rules, in order:
1. failing      - any latest automated result is FAIL, or the latest valid attestation is FAIL.
                  A person's PASS cannot override an automated FAIL; the conflict is reported.
2. covered      - a valid PASS attestation dated on or after the latest MANUAL_REVIEW run, or
                  every automated result is PASS.
3. needs_review - automation reached MANUAL_REVIEW and no later attestation resolves it.
4. no_evidence  - no automated result and no valid attestation (an expired one is noted).

Finding exceptions are applied first: an automated FAIL or MANUAL_REVIEW on a check/resource
with an active, approved exception is set aside. If nothing else keeps the control failing or
awaiting review, it is `accepted`: not a gap to fix, but listed with who approved it and until
when, so the accepted risk stays visible.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from auditforge.gap.attest import Attestation

METHOD_FILE = "gap_method.yaml"
GAP_TYPES = ("failing", "no_evidence", "needs_review")
LABELS = {
    "covered": "Covered",
    "accepted": "Accepted (exception)",
    "failing": "Failing",
    "needs_review": "Needs review",
    "no_evidence": "No evidence",
}


class MethodError(ValueError):
    pass


@dataclass(frozen=True)
class GapMethod:
    gap_weights: dict[str, int]
    risk_weight: float
    tiers: tuple[tuple[str, int, str], ...]  # (name, min points, meaning), descending
    sizes: dict[str, str]
    review_size: str
    default_size: str
    rules: tuple[tuple[str, str], ...]  # (prefix, size)
    file_hash: str

    @classmethod
    def load(cls, mappings_dir: Path) -> GapMethod:
        raw = (mappings_dir / METHOD_FILE).read_bytes()
        doc: dict[str, Any] = yaml.safe_load(raw) or {}
        effort = doc.get("effort") or {}
        method = cls(
            gap_weights={k: int(v) for k, v in (doc.get("gap_weights") or {}).items()},
            risk_weight=float(doc.get("risk_weight", 1)),
            tiers=tuple((t["name"], int(t["min"]), t.get("meaning", "")) for t in doc.get("tiers") or []),
            sizes={str(k): str(v) for k, v in (effort.get("sizes") or {}).items()},
            review_size=str(effort.get("review", "")),
            default_size=str(effort.get("default", "")),
            rules=tuple((r["prefix"], r["size"]) for r in effort.get("rules") or []),
            file_hash=hashlib.sha256(raw).hexdigest(),
        )
        method.validate()
        return method

    def validate(self) -> None:
        if set(self.gap_weights) != set(GAP_TYPES):
            raise MethodError(f"{METHOD_FILE}: gap_weights must define exactly {', '.join(GAP_TYPES)}")
        mins = [t[1] for t in self.tiers]
        if not mins or mins != sorted(mins, reverse=True) or mins[-1] != 0:
            raise MethodError(f"{METHOD_FILE}: tiers must be in descending order of min, ending at min 0")
        used = {self.review_size, self.default_size, *(size for _, size in self.rules)}
        if not used <= set(self.sizes):
            raise MethodError(
                f"{METHOD_FILE}: effort sizes used but not defined: {', '.join(used - set(self.sizes))}"
            )

    def priority(self, points: float) -> str:
        return next(name for name, minimum, _ in self.tiers if points >= minimum)

    def effort(self, key: str, gap: str) -> str:
        if gap == "needs_review":
            return self.review_size
        return next((size for prefix, size in self.rules if key.startswith(prefix)), self.default_size)


@dataclass(frozen=True)
class ControlInput:
    framework: str
    control_id: str
    title: str
    automated: list[dict[str, str]]  # latest per check/resource: check_id, resource, status, run_id, at
    attestation: Attestation | None  # latest, possibly expired
    risks: list[dict[str, Any]]  # open risks linked to the control: risk_id, title, score, band
    objectives: tuple[str, ...] = ()
    owner: str | None = None
    # Active exceptions by (check_id, resource) -> description, for this control's results.
    exceptions: dict[tuple[str, str], str] = field(default_factory=dict)

    @property
    def key(self) -> str:
        return f"{self.framework} {self.control_id}"


@dataclass
class ControlResult:
    key: str
    framework: str
    control_id: str
    title: str
    status: str  # covered | failing | needs_review | no_evidence
    reasons: list[str]
    owner: str | None
    risks: list[dict[str, Any]]
    automated: list[dict[str, str]]
    attestation_id: int | None
    objectives: list[str]
    points: float | None = None
    priority: str | None = None
    effort: str | None = None
    related: list[str] = field(default_factory=list)

    @property
    def is_gap(self) -> bool:
        return self.status not in ("covered", "accepted")


def _decide(
    c: ControlInput, today: str, automated: list[dict[str, str]]
) -> tuple[str, list[str], Attestation | None]:
    att = c.attestation
    valid = att if att and att.is_valid_on(today) else None
    fails = [a for a in automated if a["status"] == "FAIL"]
    reviews = [a for a in automated if a["status"] == "MANUAL_REVIEW"]

    def auto(a: dict[str, str]) -> str:
        return f"{a['check_id']} {a['status']} on {a['resource']} ({a['at'][:10]})"

    def att_text(a: Attestation) -> str:
        return f"A-{a.attestation_id} {a.result} on {a.tested_on} by {a.tested_by}: {a.procedure}"

    if fails or (valid and valid.result == "FAIL"):
        reasons = [auto(a) for a in fails]
        if valid:
            reasons.append(att_text(valid))
            if valid.result == "PASS":
                reasons.append("A manual PASS does not override an automated FAIL; resolve the conflict")
        return "failing", reasons, valid

    if valid and valid.result == "PASS":
        last_review = max((a["at"][:10] for a in reviews), default=None)
        if last_review and valid.tested_on < last_review:
            return (
                "needs_review",
                [*map(auto, reviews), f"{att_text(valid)} (predates the latest run)"],
                valid,
            )
        reasons = [att_text(valid)] + [f"resolves {auto(a)}" for a in reviews]
        return "covered", reasons, valid

    if automated and not reviews:
        return "covered", [auto(a) for a in automated], valid

    expired = (
        [f"A-{att.attestation_id} {att.result} on {att.tested_on} expired {att.valid_until}"] if att else []
    )
    if reviews:
        return "needs_review", [*map(auto, reviews), *expired], valid
    return (
        "no_evidence",
        ["No automated check maps to this control and no valid attestation", *expired],
        valid,
    )


def _decide_with_exceptions(c: ControlInput, today: str) -> tuple[str, list[str], Attestation | None]:
    accepted = [
        a for a in c.automated
        if a["status"] in ("FAIL", "MANUAL_REVIEW") and (a["check_id"], a["resource"]) in c.exceptions
    ]  # fmt: skip
    remaining = [a for a in c.automated if a not in accepted]
    status, reasons, valid = _decide(c, today, remaining)
    notes = [
        f"{a['check_id']} {a['status']} on {a['resource']} accepted: "
        f"{c.exceptions[(a['check_id'], a['resource'])]}"
        for a in accepted
    ]
    if accepted and status in ("covered", "no_evidence"):
        kept = [] if status == "no_evidence" else reasons
        return "accepted", notes + kept, valid
    return status, reasons + notes, valid


def assess(inputs: list[ControlInput], method: GapMethod, today: str) -> list[ControlResult]:
    """Results for every control: gaps first, highest priority points first; then covered controls."""
    results: list[ControlResult] = []
    for c in inputs:
        status, reasons, valid = _decide_with_exceptions(c, today)
        r = ControlResult(
            key=c.key, framework=c.framework, control_id=c.control_id, title=c.title, status=status,
            reasons=reasons, owner=c.owner, risks=sorted(c.risks, key=lambda x: -x["score"]),
            automated=c.automated, attestation_id=valid.attestation_id if valid else None,
            objectives=list(c.objectives),
        )  # fmt: skip
        if r.is_gap:
            top_risk = max((x["score"] for x in c.risks), default=0)
            r.points = method.gap_weights[status] + method.risk_weight * top_risk
            r.priority = method.priority(r.points)
            r.effort = method.effort(c.key, status)
        results.append(r)

    # Gaps that share an internal control objective can usually be closed together: fixing the
    # objective once produces evidence for every framework control mapped to it.
    gaps = [r for r in results if r.is_gap]
    for r in gaps:
        r.related = sorted(o.key for o in gaps if o is not r and set(o.objectives) & set(r.objectives))
    order = {t[0]: i for i, t in enumerate(method.tiers)}
    gaps.sort(key=lambda r: (order[r.priority], -r.points, r.key))
    return gaps + [r for r in results if not r.is_gap]
