"""`auditforge view`: write the dashboard as one self-contained HTML file. Local only.

The page embeds everything it shows: the risk register (from auditforge.db) and each run's
signed report.json. It loads nothing from the network (no fonts, scripts or images), so it
opens offline and can be attached to a workpaper.

Each run's signature and evidence hashes are re-verified against a trusted public key while
the page is built, so the "verified" badge is a fresh result, not a claim copied from the report.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import asdict
from datetime import UTC, datetime
from importlib.resources import files
from pathlib import Path
from typing import Any

from auditforge import __version__
from auditforge.mappings import Mappings
from auditforge.risk.matrix import RiskMatrix
from auditforge.risk.register import RiskRegister
from auditforge.signing import load_public_key, verify_report
from auditforge.store import Store
from auditforge.workpaper.exceptions import Exceptions
from auditforge.workpaper.signoff import Signoffs

TEMPLATE = "template.html"
PLACEHOLDER = "/*__AUDITFORGE_DATA__*/null"


def report_paths(conn: sqlite3.Connection) -> list[Path]:
    """report.json for each recorded run, newest first. Evidence lives at <run_dir>/raw/<file>."""
    rows = conn.execute(
        "SELECT r.run_id, MIN(e.file_path) FROM runs r JOIN evidence e USING (run_id) "
        "GROUP BY r.run_id ORDER BY r.started_at DESC"
    )
    return [Path(evidence_file).parent.parent / "report.json" for _, evidence_file in rows]


def _reports(conn: sqlite3.Connection, pubkey: Path | None, today: str) -> list[dict[str, Any]]:
    trusted = load_public_key(pubkey) if pubkey and pubkey.is_file() else None
    signoffs, exceptions = Signoffs(conn), Exceptions(conn)
    reports = []
    for path in report_paths(conn):
        if not path.is_file():
            continue  # run folder moved or deleted; the database row alone is not enough to show it
        report = json.loads(path.read_text(encoding="utf-8"))
        if trusted is None:
            report["_verify"] = {"ok": None, "message": "No trusted public key given; not verified."}
        else:
            result = verify_report(path, trusted)
            report["_verify"] = {"ok": result.ok, "message": result.message}
        report["_path"] = str(path)
        _add_workpaper_state(report, signoffs, exceptions, today)
        reports.append(report)
    return reports


def _add_workpaper_state(
    report: dict[str, Any], signoffs: Signoffs, exceptions: Exceptions, today: str
) -> None:
    """Sign-offs and active exceptions, added beside the signed content (keys start with _), never into it."""
    report["_signoffs"] = [
        asdict(s) for s in signoffs.for_report(report["run_id"], report["signature"]["payload_sha256"])
    ]
    for f in report["findings"]:
        exc = exceptions.active(f["check_id"], f["resource"], today) if f["status"] != "PASS" else None
        f["_exception"] = exc.describe() if exc else None


def _register(reg: RiskRegister) -> dict[str, Any]:
    m = reg.matrix
    risks = []
    for r in reg.all():
        d = asdict(r)
        d["inherent_band"] = m.band(r.inherent_score)
        d["residual_band"] = m.band(r.residual_score) if r.residual_score else None
        d["warnings"] = reg.residual_warnings(r)
        d["control_health"] = {f"{c.framework}|{c.control_id}": reg.control_health(c) for c in r.controls}
        d["history"] = [
            {
                "changed_at": h["changed_at"],
                "changed_by": h["changed_by"],
                "action": h["action"],
                "inherent_score": h["snapshot"]["inherent_score"],
                "residual_score": h["snapshot"]["residual_score"],
                "status": h["snapshot"]["status"],
            }
            for h in reg.history(r.risk_id)
        ]
        risks.append(d)
    return {
        "risks": risks,
        "assets": reg.assets(),
        "matrix": {
            "likelihood": {k: v["label"] for k, v in m.likelihood.items()},
            "impact": {k: v["label"] for k, v in m.impact.items()},
            "bands": [{"name": b.name, "min": b.min} for b in m.bands],
            "appetite": m.appetite,
            "sha256": m.file_hash,
        },
    }


def build_data(
    db: Path, mappings_dir: Path, pubkey: Path | None, now: datetime | None = None
) -> dict[str, Any]:
    mappings = Mappings.load(mappings_dir)
    matrix = RiskMatrix.load(mappings_dir)
    generated = now or datetime.now(UTC)
    with Store(db) as store:
        store.sync_mappings(mappings)
        register = _register(RiskRegister(store.conn, matrix))
        reports = _reports(store.conn, pubkey, generated.date().isoformat())
    return {
        "generated_at": generated.isoformat(timespec="seconds"),
        "today": generated.date().isoformat(),
        "tool_version": __version__,
        "database": str(db.resolve()),
        "control_titles": {f"{fw}|{cid}": title for fw, cid, title in mappings.control_catalog()},
        "register": register,
        "reports": reports,
    }


def render(data: dict[str, Any]) -> str:
    template = files("auditforge.ui").joinpath(TEMPLATE).read_text(encoding="utf-8")
    if PLACEHOLDER not in template:
        raise RuntimeError(f"{TEMPLATE} is missing its data placeholder")
    # "</" is escaped so no string in the data can close the <script> element early.
    payload = json.dumps(data, ensure_ascii=False).replace("</", "<\\/")
    return template.replace(PLACEHOLDER, payload, 1)


def write_view(db: Path, out: Path, mappings_dir: Path, pubkey: Path | None) -> dict[str, Any]:
    data = build_data(db, mappings_dir, pubkey)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(render(data), encoding="utf-8")
    return data
