"""Build, sign and write a gap assessment: gap/<run_id>/gap-report.json + gap-report.md.

The report is signed like a check run, and carries the scope file and every attestation
evidence file it relied on under raw/, so `auditforge verify gap-report.json` re-checks them.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import sqlite3
import uuid
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from auditforge import __version__
from auditforge.gap.attest import Attestations
from auditforge.gap.engine import LABELS, ControlInput, ControlResult, GapMethod
from auditforge.gap.scope import Scope
from auditforge.mappings import Mappings
from auditforge.paths import RAW_DIRNAME
from auditforge.report import FRAMEWORK_LABELS
from auditforge.risk.matrix import RiskMatrix
from auditforge.risk.register import RiskRegister
from auditforge.signing import sign_report
from auditforge.store import latest_control_results
from auditforge.workpaper.exceptions import Exceptions

SCHEMA = "auditforge.gap/v1"
REPORT_FILE = "gap-report.json"


def _objectives_by_control(mappings: Mappings) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for objective, spec in mappings.objectives.items():
        for fw, ids in (spec.get("controls") or {}).items():
            for cid in ids:
                out.setdefault(f"{fw} {cid}", []).append(objective)
    return out


def collect(
    conn: sqlite3.Connection, scope: Scope, mappings: Mappings, matrix: RiskMatrix, today: str
) -> tuple[list[ControlInput], Attestations]:
    """Gather, per in-scope control, everything the engine decides on."""
    RiskRegister(conn, matrix)  # ensures the risk tables exist, even in a database with no risks
    attestations = Attestations(conn)
    exceptions = Exceptions(conn)

    def active_exceptions(results: list[dict[str, str]]) -> dict[tuple[str, str], str]:
        out = {}
        for r in results:
            exc = exceptions.active(r["check_id"], r["resource"], today)
            if exc:
                out[(r["check_id"], r["resource"])] = exc.describe()
        return out

    objectives = _objectives_by_control(mappings)
    risks: dict[str, list[dict[str, Any]]] = {}
    for fw, cid, rid, title, score in conn.execute(
        "SELECT rc.framework, rc.control_id, r.risk_id, r.title, "
        "COALESCE(r.residual_score, r.inherent_score) "
        "FROM risk_controls rc JOIN risks r USING (risk_id) WHERE r.status != 'closed'"
    ):
        risks.setdefault(f"{fw} {cid}", []).append(
            {"risk_id": rid, "title": title, "score": score, "band": matrix.band(score)}
        )
    inputs = []
    for fw, cid, title in scope.in_scope(mappings):
        automated = latest_control_results(conn, fw, cid)
        inputs.append(
            ControlInput(
                framework=fw,
                control_id=cid,
                title=title,
                automated=automated,
                attestation=attestations.latest(fw, cid),
                risks=risks.get(f"{fw} {cid}", []),
                objectives=tuple(objectives.get(f"{fw} {cid}", ())),
                owner=scope.owners.get(f"{fw} {cid}"),
                exceptions=active_exceptions(automated),
            )
        )
    return inputs, attestations


def _copy_evidence(src: Path, run_dir: Path, name: str, source_uri: str) -> dict[str, Any]:
    target = run_dir / RAW_DIRNAME / name
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, target)
    return {
        "evidence_id": uuid.uuid4().hex,
        "source_uri": source_uri,
        "http_status": None,
        "exit_code": None,
        "collected_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "sha256": hashlib.sha256(target.read_bytes()).hexdigest(),
        "file_path": target.relative_to(run_dir).as_posix(),
    }


def build(
    results: list[ControlResult],
    scope: Scope,
    method: GapMethod,
    mappings: Mappings,
    attestations: Attestations,
    run_dir: Path,
    run_id: str,
    operator: str,
    today: str,
) -> dict[str, Any]:
    evidence = [_copy_evidence(scope.path, run_dir, "scope.yaml", f"file {scope.path.resolve()}")]
    used = {r.attestation_id for r in results if r.attestation_id is not None}
    attest_rows = [a for a in attestations.all() if a.attestation_id in used]
    for a in attest_rows:
        if a.evidence_path:
            src = Path(a.evidence_path)
            if not src.is_file() or hashlib.sha256(src.read_bytes()).hexdigest() != a.evidence_sha256:
                raise ValueError(
                    f"Evidence for attestation A-{a.attestation_id} is missing or changed: {src}"
                )
            evidence.append(
                _copy_evidence(
                    src, run_dir, f"A-{a.attestation_id}-{src.name}", f"attestation A-{a.attestation_id}"
                )
            )

    frameworks = {}
    for fw in scope.frameworks:
        rows = [r for r in results if r.framework == fw]
        counts = {s: sum(r.status == s for r in rows) for s in LABELS}
        frameworks[fw] = {
            "in_scope": len(rows),
            "excluded": sum(k.startswith(fw + " ") for k in scope.exclusions),
            **counts,
            "coverage_pct": round(100 * counts["covered"] / len(rows), 1) if rows else 0.0,
        }
    gaps = [r for r in results if r.is_gap]
    return {
        "schema": SCHEMA,
        "tool_version": __version__,
        "title": "Gap Assessment — " + ", ".join(FRAMEWORK_LABELS.get(f, f) for f in scope.frameworks),
        "run_id": run_id,
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "as_of": today,
        "operator": operator,
        "scope": {
            "frameworks": list(scope.frameworks),
            "exclusions": scope.exclusions,
            "scope_sha256": scope.sha256,
        },
        "method": {
            "gap_method_sha256": method.file_hash,
            "tiers": [{"name": n, "min": m, "meaning": t} for n, m, t in method.tiers],
            "effort_sizes": method.sizes,
            "mappings": mappings.file_hashes,
        },
        "summary": {
            "frameworks": frameworks,
            "gaps": len(gaps),
            "by_priority": {t[0]: sum(r.priority == t[0] for r in gaps) for t in method.tiers},
        },
        "controls": [asdict(r) for r in results],
        "attestations": [asdict(a) for a in attest_rows],
        "evidence": evidence,
    }


def _cell(text: Any) -> str:
    return str(text).replace("|", "\\|").replace("\n", " ")


def to_markdown(report: dict[str, Any]) -> str:
    s = report["summary"]
    lines = [
        f"# {report['title']}",
        "",
        f"- **Run ID:** `{report['run_id']}` · **As of:** {report['as_of']} · **By:** {report['operator']}",
        f"- **Gaps:** {s['gaps']} (" + ", ".join(f"{k}: {v}" for k, v in s["by_priority"].items()) + ")",
        "",
        "## Coverage",
        "",
        "| Framework | In scope | Covered | Accepted | Failing | Needs review | No evidence | Excluded "
        "| Coverage |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for fw, c in s["frameworks"].items():
        lines.append(
            f"| {FRAMEWORK_LABELS.get(fw, fw)} | {c['in_scope']} | {c['covered']} | {c['accepted']} | "
            f"{c['failing']} | {c['needs_review']} | {c['no_evidence']} | {c['excluded']} | "
            f"{c['coverage_pct']}% |"
        )
    lines.append("")
    lines.append(
        "Coverage counts covered controls only; accepted exceptions are risk the organisation chose to carry."
    )
    lines += [
        "",
        "## Prioritized gaps",
        "",
        "Points = gap weight + highest linked risk score. "
        + " ".join(f"**{t['name']}** ≥ {t['min']}: {t['meaning']}." for t in report["method"]["tiers"]),
        "",
        "| Priority | Points | Control | Gap | Why | Linked risks | Effort | Owner | Close together with |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for c in report["controls"]:
        if c["status"] in ("covered", "accepted"):
            continue
        risks = ", ".join(f"{r['risk_id']} ({r['score']} {r['band']})" for r in c["risks"]) or "—"
        effort = f"{c['effort']} ({report['method']['effort_sizes'][c['effort']]})"
        cells = [
            c["priority"], f"{c['points']:g}", f"{c['key']} {c['title']}", LABELS[c["status"]],
            "; ".join(c["reasons"]), risks, effort, c["owner"] or "—", ", ".join(c["related"]) or "—",
        ]  # fmt: skip
        lines.append("| " + " | ".join(_cell(x) for x in cells) + " |")
    accepted = [c for c in report["controls"] if c["status"] == "accepted"]
    lines += ["", f"## Accepted exceptions ({len(accepted)})", ""]
    lines += [f"- **{c['key']}** {c['title']} — {'; '.join(c['reasons'])}" for c in accepted] or ["None."]
    covered = [c for c in report["controls"] if c["status"] == "covered"]
    lines += ["", f"## Covered controls ({len(covered)})", ""]
    lines += [f"- **{c['key']}** {c['title']} — {'; '.join(c['reasons'])}" for c in covered] or ["None yet."]
    lines += ["", "## Excluded controls (statement of applicability)", ""]
    excl = report["scope"]["exclusions"]
    lines += [f"- **{k}** — {v}" for k, v in excl.items()] or ["None."]
    lines += ["", "## Evidence", "", "| File | Source | SHA-256 |", "|---|---|---|"]
    lines += [
        f"| `{e['file_path']}` | {_cell(e['source_uri'])} | `{e['sha256'][:16]}…` |"
        for e in report["evidence"]
    ]
    sig = report["signature"]
    lines += [
        "",
        "## Integrity",
        "",
        f"Signed with {sig['algorithm']} (key fingerprint `{sig['public_key_fingerprint']}`). Verify with "
        "`auditforge verify gap-report.json --pubkey <operator key>`. Gap method SHA-256 "
        f"`{report['method']['gap_method_sha256'][:16]}…`, "
        f"scope SHA-256 `{report['scope']['scope_sha256'][:16]}…`.",
        "",
    ]
    return "\n".join(lines)


def write(report: dict[str, Any], run_dir: Path, key: Any) -> Path:
    report["signature"] = sign_report(report, key)
    path = run_dir / REPORT_FILE
    path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    (run_dir / "gap-report.md").write_text(to_markdown(report), encoding="utf-8")
    return path
