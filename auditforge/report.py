"""Build report.json (signed separately) and render report.md."""

from __future__ import annotations

import json
import uuid
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from auditforge import __version__
from auditforge.mappings import Mappings
from auditforge.models import Evidence, Finding, Status

SCHEMA = "auditforge.report/v3"  # v3: added "title"

FRAMEWORK_LABELS = {
    "SOC2": "SOC 2",
    "ISO27001:2022": "ISO 27001:2022",
    "NIST-800-53r5": "NIST 800-53 r5",
    "SOX-ITGC": "SOX ITGC",
}
ICONS = {"PASS": "✅", "FAIL": "❌", "MANUAL_REVIEW": "⚠️"}


def new_run_id() -> str:
    return f"{datetime.now(UTC):%Y%m%dT%H%M%SZ}-{uuid.uuid4().hex[:6]}"


def build_report(
    *,
    title: str,
    run_id: str,
    started_at: str,
    collected_at: str,
    operator: str,
    target: dict[str, str],
    parameters: dict[str, Any],
    findings: list[Finding],
    evidence: list[Evidence],
    mappings: Mappings,
) -> dict[str, Any]:
    """Unsigned report. Framework controls are attached here, from the mappings, not by checks."""
    return {
        "schema": SCHEMA,
        "tool_version": __version__,
        "title": title,
        "run_id": run_id,
        "started_at": started_at,
        "collected_at": collected_at,
        "operator": operator,
        "target": target,
        "parameters": parameters,
        # Which mapping files produced the control IDs below, so a later mapping
        # change can't silently reinterpret an old report.
        "mappings": mappings.file_hashes,
        "summary": {
            "pass": sum(f.status is Status.PASS for f in findings),
            "fail": sum(f.status is Status.FAIL for f in findings),
            "manual_review": sum(f.status is Status.MANUAL_REVIEW for f in findings),
        },
        "findings": [
            {
                **asdict(f),
                "status": f.status.value,
                "objectives": mappings.objectives_for(f.check_id),
                "controls": mappings.controls_for(f.check_id),
            }
            for f in findings
        ],
        "evidence": [asdict(e) for e in evidence],
    }


def _cell(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


def to_markdown(report: dict[str, Any]) -> str:
    s = report["summary"]
    frameworks = list(report["findings"][0]["controls"]) if report["findings"] else []
    header = ["Check", "Result", *(FRAMEWORK_LABELS.get(fw, fw) for fw in frameworks), "Detail"]
    lines = [
        f"# {report['title']}",
        "",
        f"- **Run ID:** `{report['run_id']}`",
        f"- **Collected:** {report['collected_at']} by {report['operator']}",
        f"- **Tool:** AuditForge {report['tool_version']}",
        f"- **Result:** {s['pass']} pass · {s['fail']} fail · {s['manual_review']} manual review",
        "",
        "| " + " | ".join(header) + " |",
        "|" + "---|" * len(header),
    ]
    for f in report["findings"]:
        cells = [
            f"{f['check_id']} {f['title']}",
            f"{ICONS[f['status']]} {f['status']}",
            *(", ".join(f["controls"].get(fw, [])) or "—" for fw in frameworks),
            f["detail"],
        ]
        lines.append("| " + " | ".join(_cell(c) for c in cells) + " |")
    lines += ["", "## Evidence", "", "| File | Source | HTTP | SHA-256 |", "|---|---|---|---|"]
    for e in report["evidence"]:
        lines.append(
            f"| `{e['file_path']}` | {e['source_uri']} | {e['http_status']} | `{e['sha256'][:16]}…` |"
        )
    sig = report["signature"]
    lines += [
        "",
        "## Integrity",
        "",
        f"Signed with {sig['algorithm']} (key fingerprint `{sig['public_key_fingerprint']}`). "
        "Verify with `auditforge verify report.json --pubkey signing_key.pub.pem`, using the public key "
        "obtained from the operator, not one shipped alongside the report.",
        "",
    ]
    return "\n".join(lines)


def write_report(run_dir: Path, report: dict[str, Any]) -> tuple[Path, Path]:
    json_path, md_path = run_dir / "report.json", run_dir / "report.md"
    json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    md_path.write_text(to_markdown(report), encoding="utf-8")
    return json_path, md_path
