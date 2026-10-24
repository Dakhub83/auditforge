"""Local risk register (Eramba-style) stored in auditforge.db alongside runs and findings.

Concepts, after Eramba's Asset Management / Risk Management / Compliance Management split:
- An asset is something of value (an application, a data set, a vendor) with an owner.
- A risk threatens one or more assets, on named properties (confidentiality, integrity,
  availability), and is scored twice on the 5x5 matrix: inherent (before controls) and
  residual (after the controls and mitigations in place).
- A risk is linked to the framework controls that mitigate it (e.g. SOC 2 CC6.1). Because
  automated checks map to the same controls, the register can show, per risk, whether the
  latest evidence for those controls passed. A residual score that relies on a failing
  control is flagged as possibly understated.
- Mitigations are owned tasks with their own status, separate from the risk's status.

Risk data is entered by people, so unlike findings it is not signed. Every create and update
writes a full snapshot to risk_history, which triggers make append-only; risks are closed,
never deleted.
"""

from __future__ import annotations

import json
import re
import sqlite3
from dataclasses import asdict, dataclass, field
from datetime import UTC, date, datetime
from typing import Any

from auditforge.risk.matrix import RiskMatrix
from auditforge.store import latest_control_results

TREATMENTS = ("mitigate", "accept", "transfer", "avoid")
RISK_STATUSES = (
    "identified",
    "assessed",
    "treatment_planned",
    "treatment_in_progress",
    "monitoring",
    "closed",
)
MITIGATION_STATUSES = ("planned", "in_progress", "implemented", "verified", "cancelled")
ASSET_TYPES = ("application", "data", "infrastructure", "vendor", "people", "process")
CLASSIFICATIONS = ("public", "internal", "confidential", "restricted")
CIA = {"C": "confidentiality", "I": "integrity", "A": "availability"}

RISK_ID = re.compile(r"^R-\d{3,}$")
ASSET_ID = re.compile(r"^AST-\d{3,}$")


def _in(values: tuple[str, ...]) -> str:
    return "(" + ", ".join(f"'{v}'" for v in values) + ")"


SCHEMA = f"""
CREATE TABLE IF NOT EXISTS assets (
    asset_id       TEXT PRIMARY KEY CHECK (asset_id GLOB 'AST-[0-9][0-9][0-9]*'),
    name           TEXT NOT NULL CHECK (length(trim(name)) > 0),
    asset_type     TEXT NOT NULL CHECK (asset_type IN {_in(ASSET_TYPES)}),
    owner          TEXT NOT NULL CHECK (length(trim(owner)) > 0),
    classification TEXT NOT NULL CHECK (classification IN {_in(CLASSIFICATIONS)}),
    description    TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS risks (
    risk_id             TEXT PRIMARY KEY CHECK (risk_id GLOB 'R-[0-9][0-9][0-9]*'),
    title               TEXT NOT NULL CHECK (length(trim(title)) > 0),
    category            TEXT NOT NULL,
    description         TEXT NOT NULL DEFAULT '',
    owner               TEXT NOT NULL CHECK (length(trim(owner)) > 0),
    inherent_likelihood INTEGER NOT NULL CHECK (inherent_likelihood BETWEEN 1 AND 5),
    inherent_impact     INTEGER NOT NULL CHECK (inherent_impact BETWEEN 1 AND 5),
    residual_likelihood INTEGER CHECK (residual_likelihood BETWEEN 1 AND 5),
    residual_impact     INTEGER CHECK (residual_impact BETWEEN 1 AND 5),
    -- Scores are computed by the database, so they can never disagree with L and I.
    inherent_score      INTEGER GENERATED ALWAYS AS (inherent_likelihood * inherent_impact) STORED,
    residual_score      INTEGER GENERATED ALWAYS AS (residual_likelihood * residual_impact) STORED,
    treatment           TEXT NOT NULL CHECK (treatment IN {_in(TREATMENTS)}),
    status              TEXT NOT NULL CHECK (status IN {_in(RISK_STATUSES)}),
    review_date         TEXT,
    created_at          TEXT NOT NULL,
    updated_at          TEXT NOT NULL,
    updated_by          TEXT NOT NULL,
    -- Residual is assessed as a pair, and controls can only lower risk.
    CHECK ((residual_likelihood IS NULL) = (residual_impact IS NULL)),
    CHECK (residual_likelihood IS NULL
           OR residual_likelihood * residual_impact <= inherent_likelihood * inherent_impact)
);
-- Asset impact: which assets a risk threatens, and on which property.
CREATE TABLE IF NOT EXISTS risk_assets (
    risk_id     TEXT NOT NULL REFERENCES risks(risk_id),
    asset_id    TEXT NOT NULL REFERENCES assets(asset_id),
    impact_type TEXT NOT NULL CHECK (impact_type IN ('confidentiality', 'integrity', 'availability')),
    PRIMARY KEY (risk_id, asset_id, impact_type)
);
-- Controls that mitigate the risk; must exist in the controls catalog (crosswalk.yaml).
CREATE TABLE IF NOT EXISTS risk_controls (
    risk_id    TEXT NOT NULL REFERENCES risks(risk_id),
    framework  TEXT NOT NULL,
    control_id TEXT NOT NULL,
    PRIMARY KEY (risk_id, framework, control_id),
    FOREIGN KEY (framework, control_id) REFERENCES controls(framework, control_id)
);
CREATE TABLE IF NOT EXISTS mitigations (
    mitigation_id INTEGER PRIMARY KEY AUTOINCREMENT,
    risk_id       TEXT NOT NULL REFERENCES risks(risk_id),
    description   TEXT NOT NULL CHECK (length(trim(description)) > 0),
    owner         TEXT NOT NULL CHECK (length(trim(owner)) > 0),
    status        TEXT NOT NULL CHECK (status IN {_in(MITIGATION_STATUSES)}),
    due_date      TEXT,
    updated_at    TEXT NOT NULL,
    updated_by    TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS risk_history (
    history_id  INTEGER PRIMARY KEY AUTOINCREMENT,
    risk_id     TEXT NOT NULL REFERENCES risks(risk_id),
    changed_at  TEXT NOT NULL,
    changed_by  TEXT NOT NULL,
    action      TEXT NOT NULL,
    snapshot    TEXT NOT NULL  -- full JSON of the risk after the change
);
CREATE TRIGGER IF NOT EXISTS risk_history_append_only_u BEFORE UPDATE ON risk_history
    BEGIN SELECT RAISE(ABORT, 'risk_history is append-only'); END;
CREATE TRIGGER IF NOT EXISTS risk_history_append_only_d BEFORE DELETE ON risk_history
    BEGIN SELECT RAISE(ABORT, 'risk_history is append-only'); END;
CREATE TRIGGER IF NOT EXISTS risks_no_delete BEFORE DELETE ON risks
    BEGIN SELECT RAISE(ABORT, 'risks are closed (status=closed), not deleted'); END;
"""


class RiskError(ValueError):
    """Invalid input for the register; the message says what to fix."""


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def _check_date(value: str | None, name: str) -> None:
    if value is None:
        return
    try:
        date.fromisoformat(value)
    except ValueError:
        raise RiskError(f"{name} must be a date like 2026-12-31, got {value!r}") from None


@dataclass(frozen=True)
class AssetImpact:
    asset_id: str
    impact_types: tuple[str, ...]  # subset of confidentiality, integrity, availability


@dataclass(frozen=True)
class ControlLink:
    framework: str
    control_id: str


@dataclass
class Mitigation:
    mitigation_id: int
    description: str
    owner: str
    status: str
    due_date: str | None


@dataclass
class Risk:
    risk_id: str
    title: str
    category: str
    owner: str
    inherent_likelihood: int
    inherent_impact: int
    treatment: str
    status: str
    description: str = ""
    residual_likelihood: int | None = None
    residual_impact: int | None = None
    review_date: str | None = None
    inherent_score: int | None = None  # filled from the database
    residual_score: int | None = None
    created_at: str | None = None
    updated_at: str | None = None
    updated_by: str | None = None
    assets: list[AssetImpact] = field(default_factory=list)
    controls: list[ControlLink] = field(default_factory=list)
    mitigations: list[Mitigation] = field(default_factory=list)


# Fields a caller may set through create/update; scores and audit columns are not among them.
EDITABLE = (
    "title", "category", "description", "owner", "inherent_likelihood", "inherent_impact",
    "residual_likelihood", "residual_impact", "treatment", "status", "review_date",
)  # fmt: skip


class RiskRegister:
    def __init__(self, conn: sqlite3.Connection, matrix: RiskMatrix) -> None:
        self.conn = conn
        self.matrix = matrix
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.conn.executescript(SCHEMA)

    # --- Assets -----------------------------------------------------------------------

    def add_asset(
        self,
        asset_id: str,
        name: str,
        asset_type: str,
        owner: str,
        classification: str,
        description: str = "",
    ) -> None:
        if not ASSET_ID.match(asset_id):
            raise RiskError(f"Asset ID must look like AST-001, got {asset_id!r}")
        if asset_type not in ASSET_TYPES:
            raise RiskError(f"Asset type must be one of {', '.join(ASSET_TYPES)}")
        if classification not in CLASSIFICATIONS:
            raise RiskError(f"Classification must be one of {', '.join(CLASSIFICATIONS)}")
        try:
            with self.conn:
                self.conn.execute(
                    "INSERT INTO assets (asset_id, name, asset_type, owner, classification, description) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (asset_id, name, asset_type, owner, classification, description),
                )
        except sqlite3.IntegrityError as exc:
            raise RiskError(f"Could not add {asset_id}: {exc}") from None

    def assets(self) -> list[dict[str, Any]]:
        cur = self.conn.execute("SELECT * FROM assets ORDER BY asset_id")
        cols = [c[0] for c in cur.description]
        return [dict(zip(cols, row, strict=True)) for row in cur]

    # --- Risks ------------------------------------------------------------------------

    def next_risk_id(self) -> str:
        row = self.conn.execute("SELECT MAX(CAST(substr(risk_id, 3) AS INTEGER)) FROM risks").fetchone()
        return f"R-{(row[0] or 0) + 1:03d}"

    def create(
        self,
        fields: dict[str, Any],
        actor: str,
        assets: list[AssetImpact] | None = None,
        controls: list[ControlLink] | None = None,
        risk_id: str | None = None,
    ) -> Risk:
        risk_id = risk_id or self.next_risk_id()
        if not RISK_ID.match(risk_id):
            raise RiskError(f"Risk ID must look like R-001, got {risk_id!r}")
        if self._exists(risk_id):
            raise RiskError(f"{risk_id} already exists; use 'risk update'")
        values = {"description": "", "status": "identified", "treatment": "mitigate", **fields}
        missing = [f for f in ("title", "category", "owner", "inherent_likelihood", "inherent_impact")
                   if values.get(f) in (None, "")]  # fmt: skip
        if missing:
            raise RiskError(f"Missing required field(s): {', '.join(missing)}")
        self._validate(values)
        now = _now()
        cols = [c for c in EDITABLE if c in values]
        with self.conn:
            self.conn.execute(
                f"INSERT INTO risks (risk_id, {', '.join(cols)}, created_at, updated_at, updated_by) "
                f"VALUES (?, {', '.join('?' for _ in cols)}, ?, ?, ?)",
                (risk_id, *(values[c] for c in cols), now, now, actor),
            )
            self._replace_links(risk_id, assets or [], controls or [])
            self._record(risk_id, actor, "create", now)
        return self.get(risk_id)

    def update(
        self,
        risk_id: str,
        changes: dict[str, Any],
        actor: str,
        assets: list[AssetImpact] | None = None,
        controls: list[ControlLink] | None = None,
    ) -> Risk:
        """Apply only the given changes. Passing assets or controls replaces that whole list."""
        current = self.get(risk_id)
        unknown = set(changes) - set(EDITABLE)
        if unknown:
            raise RiskError(f"Cannot set {', '.join(sorted(unknown))}")
        merged = {c: getattr(current, c) for c in EDITABLE} | changes
        self._validate(merged)
        now = _now()
        with self.conn:
            if changes:
                sets = ", ".join(f"{c} = ?" for c in changes)
                self.conn.execute(
                    f"UPDATE risks SET {sets}, updated_at = ?, updated_by = ? WHERE risk_id = ?",
                    (*changes.values(), now, actor, risk_id),
                )
            else:
                self.conn.execute(
                    "UPDATE risks SET updated_at = ?, updated_by = ? WHERE risk_id = ?", (now, actor, risk_id)
                )
            self._replace_links(
                risk_id,
                current.assets if assets is None else assets,
                current.controls if controls is None else controls,
            )
            self._record(risk_id, actor, "update", now)
        return self.get(risk_id)

    def get(self, risk_id: str) -> Risk:
        cur = self.conn.execute("SELECT * FROM risks WHERE risk_id = ?", (risk_id,))
        row = cur.fetchone()
        if row is None:
            raise RiskError(f"No risk {risk_id}")
        risk = Risk(**dict(zip([c[0] for c in cur.description], row, strict=True)))
        impacts: dict[str, list[str]] = {}
        for asset_id, impact_type in self.conn.execute(
            "SELECT asset_id, impact_type FROM risk_assets WHERE risk_id = ? ORDER BY asset_id", (risk_id,)
        ):
            impacts.setdefault(asset_id, []).append(impact_type)
        order = list(CIA.values())
        risk.assets = [AssetImpact(a, tuple(sorted(t, key=order.index))) for a, t in impacts.items()]
        risk.controls = [
            ControlLink(fw, cid)
            for fw, cid in self.conn.execute(
                "SELECT framework, control_id FROM risk_controls WHERE risk_id = ? "
                "ORDER BY framework, control_id",
                (risk_id,),
            )
        ]
        risk.mitigations = [
            Mitigation(*row)
            for row in self.conn.execute(
                "SELECT mitigation_id, description, owner, status, due_date FROM mitigations "
                "WHERE risk_id = ? ORDER BY mitigation_id",
                (risk_id,),
            )
        ]
        return risk

    def all(self) -> list[Risk]:
        ids = [r[0] for r in self.conn.execute(
            "SELECT risk_id FROM risks ORDER BY COALESCE(residual_score, inherent_score) DESC, risk_id"
        )]  # fmt: skip
        return [self.get(i) for i in ids]

    def history(self, risk_id: str) -> list[dict[str, Any]]:
        return [
            {"changed_at": at, "changed_by": by, "action": action, "snapshot": json.loads(snap)}
            for at, by, action, snap in self.conn.execute(
                "SELECT changed_at, changed_by, action, snapshot FROM risk_history WHERE risk_id = ? "
                "ORDER BY history_id",
                (risk_id,),
            )
        ]

    # --- Mitigations ------------------------------------------------------------------

    def add_mitigation(
        self, risk_id: str, description: str, owner: str, actor: str, due_date: str | None = None,
        status: str = "planned",
    ) -> int:  # fmt: skip
        self.get(risk_id)
        _check_date(due_date, "due date")
        if status not in MITIGATION_STATUSES:
            raise RiskError(f"Mitigation status must be one of {', '.join(MITIGATION_STATUSES)}")
        now = _now()
        with self.conn:
            cur = self.conn.execute(
                "INSERT INTO mitigations "
                "(risk_id, description, owner, status, due_date, updated_at, updated_by) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (risk_id, description, owner, status, due_date, now, actor),
            )
            self._record(risk_id, actor, "mitigation_added", now)
        return int(cur.lastrowid)

    def set_mitigation_status(self, mitigation_id: int, status: str, actor: str) -> str:
        if status not in MITIGATION_STATUSES:
            raise RiskError(f"Mitigation status must be one of {', '.join(MITIGATION_STATUSES)}")
        row = self.conn.execute(
            "SELECT risk_id FROM mitigations WHERE mitigation_id = ?", (mitigation_id,)
        ).fetchone()
        if row is None:
            raise RiskError(f"No mitigation M-{mitigation_id}")
        now = _now()
        with self.conn:
            self.conn.execute(
                "UPDATE mitigations SET status = ?, updated_at = ?, updated_by = ? WHERE mitigation_id = ?",
                (status, now, actor, mitigation_id),
            )
            self._record(row[0], actor, "mitigation_status", now)
        return row[0]

    # --- Link to automated evidence ---------------------------------------------------

    def control_health(self, link: ControlLink) -> list[dict[str, str]]:
        """Latest automated result per check and per resource that evidences this control."""
        return latest_control_results(self.conn, link.framework, link.control_id)

    def residual_warnings(self, risk: Risk) -> list[str]:
        """Reasons the residual score may not be credible."""
        warnings = []
        if risk.residual_score is None:
            warnings.append("residual risk not assessed")
        failing = [
            f"{c.framework} {c.control_id} ({h['check_id']})"
            for c in risk.controls
            for h in self.control_health(c)
            if h["status"] == "FAIL"
        ]
        if failing and risk.residual_score is not None and risk.residual_score < risk.inherent_score:
            warnings.append(
                "residual score relies on controls whose latest evidence FAILED: " + ", ".join(failing)
            )
        score = risk.residual_score or risk.inherent_score
        if self.matrix.above_appetite(score) and risk.treatment == "accept":
            warnings.append(f"accepted at {score}, above the risk appetite of {self.matrix.appetite}")
        return warnings

    # --- Internals --------------------------------------------------------------------

    def _exists(self, risk_id: str) -> bool:
        return self.conn.execute("SELECT 1 FROM risks WHERE risk_id = ?", (risk_id,)).fetchone() is not None

    def _validate(self, v: dict[str, Any]) -> None:
        if v.get("category") not in self.matrix.categories:
            raise RiskError(f"Category must be one of: {', '.join(self.matrix.categories)}")
        if v.get("treatment") not in TREATMENTS:
            raise RiskError(f"Treatment must be one of {', '.join(TREATMENTS)}")
        if v.get("status") not in RISK_STATUSES:
            raise RiskError(f"Status must be one of {', '.join(RISK_STATUSES)}")
        for name in ("title", "owner"):
            if not str(v.get(name) or "").strip():
                raise RiskError(f"{name} cannot be empty")
        inherent = self.matrix.score(v["inherent_likelihood"], v["inherent_impact"])
        rl, ri = v.get("residual_likelihood"), v.get("residual_impact")
        if (rl is None) != (ri is None):
            raise RiskError("Give both residual likelihood and residual impact, or neither")
        if rl is not None and self.matrix.score(rl, ri) > inherent:
            raise RiskError(
                f"Residual score {rl * ri} is higher than inherent score {inherent}; "
                "controls can only lower risk"
            )
        _check_date(v.get("review_date"), "review date")

    def _replace_links(self, risk_id: str, assets: list[AssetImpact], controls: list[ControlLink]) -> None:
        self.conn.execute("DELETE FROM risk_assets WHERE risk_id = ?", (risk_id,))
        self.conn.execute("DELETE FROM risk_controls WHERE risk_id = ?", (risk_id,))
        for a in assets:
            if not self.conn.execute("SELECT 1 FROM assets WHERE asset_id = ?", (a.asset_id,)).fetchone():
                raise RiskError(f"Unknown asset {a.asset_id}; add it first with 'asset add'")
            for t in a.impact_types:
                self.conn.execute(
                    "INSERT OR IGNORE INTO risk_assets (risk_id, asset_id, impact_type) VALUES (?, ?, ?)",
                    (risk_id, a.asset_id, t),
                )
        for c in controls:
            known = self.conn.execute(
                "SELECT 1 FROM controls WHERE framework = ? AND control_id = ?", (c.framework, c.control_id)
            ).fetchone()
            if not known:
                raise RiskError(
                    f"Unknown control {c.framework} {c.control_id}; add it to the frameworks catalog "
                    "in mappings/crosswalk.yaml first"
                )
            self.conn.execute(
                "INSERT OR IGNORE INTO risk_controls (risk_id, framework, control_id) VALUES (?, ?, ?)",
                (risk_id, c.framework, c.control_id),
            )

    def _record(self, risk_id: str, actor: str, action: str, at: str) -> None:
        snapshot = json.dumps(asdict(self.get(risk_id)), sort_keys=True)
        self.conn.execute(
            "INSERT INTO risk_history (risk_id, changed_at, changed_by, action, snapshot) "
            "VALUES (?, ?, ?, ?, ?)",
            (risk_id, at, actor, action, snapshot),
        )
