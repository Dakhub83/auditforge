"""Risk register as a spreadsheet (CSV): one row per risk, for committees and auditors.

The sheet is a read-only view of auditforge.db at the time of export; the database (with its
append-only history) stays the record. Multi-valued cells (assets, controls, mitigations) are
joined with "; " so the sheet stays one row per risk and can be filtered and sorted.
"""

from __future__ import annotations

import csv
from pathlib import Path

from auditforge.risk.register import Risk, RiskRegister

HEADER = [
    "Risk ID", "Title", "Category", "Description", "Owner", "Status", "Treatment", "Review date",
    "Assets (C/I/A)", "Inherent likelihood", "Inherent impact", "Inherent score", "Inherent band",
    "Residual likelihood", "Residual impact", "Residual score", "Residual band", "Above appetite",
    "Controls", "Latest automated evidence", "Mitigations", "Warnings", "Last updated", "Updated by",
]  # fmt: skip

# A cell starting with one of these is run as a formula by Excel/LibreOffice/Sheets
# ("CSV injection"). Register text is typed by people, so it is neutralised with a leading quote.
FORMULA_START = ("=", "+", "-", "@", "\t", "\r")


def _cell(value: object) -> str:
    text = "" if value is None else str(value)
    return "'" + text if text.startswith(FORMULA_START) else text


def _assets(reg: RiskRegister, risk: Risk) -> str:
    names = {a["asset_id"]: a["name"] for a in reg.assets()}
    return "; ".join(
        f"{a.asset_id} {names.get(a.asset_id, '')} ({''.join(t[0].upper() for t in a.impact_types)})"
        for a in risk.assets
    )


def _evidence(reg: RiskRegister, risk: Risk) -> str:
    parts = []
    for c in risk.controls:
        health = reg.control_health(c)
        if not health:
            parts.append(f"{c.framework} {c.control_id}: no automated check")
        parts += [
            f"{c.framework} {c.control_id}: {h['status']} {h['check_id']} {h['resource']} ({h['at'][:10]})"
            for h in health
        ]
    return "; ".join(parts)


def row(reg: RiskRegister, risk: Risk) -> list[str]:
    m = reg.matrix
    assessed = risk.residual_score is not None
    if assessed:
        above = "Yes" if m.above_appetite(risk.residual_score) else "No"
    else:
        above = "Residual not assessed"
    values = [
        risk.risk_id, risk.title, risk.category, risk.description, risk.owner, risk.status,
        risk.treatment, risk.review_date, _assets(reg, risk),
        risk.inherent_likelihood, risk.inherent_impact, risk.inherent_score, m.band(risk.inherent_score),
        risk.residual_likelihood, risk.residual_impact, risk.residual_score,
        m.band(risk.residual_score) if assessed else "",
        above,
        "; ".join(f"{c.framework} {c.control_id}" for c in risk.controls),
        _evidence(reg, risk),
        "; ".join(f"M-{x.mitigation_id} [{x.status}] {x.description} ({x.owner}, due {x.due_date or '-'})"
                  for x in risk.mitigations),
        "; ".join(reg.residual_warnings(risk)),
        risk.updated_at, risk.updated_by,
    ]  # fmt: skip
    return [_cell(v) for v in values]


def write_csv(reg: RiskRegister, path: Path) -> int:
    """Write the register, highest current score first. Returns the number of risks."""
    risks = reg.all()
    path.parent.mkdir(parents=True, exist_ok=True)
    # utf-8-sig: the byte-order mark makes Excel read names like "Søren" correctly.
    with path.open("w", encoding="utf-8-sig", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(HEADER)
        writer.writerows(row(reg, r) for r in risks)
    return len(risks)
