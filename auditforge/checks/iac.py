"""Infrastructure-as-code checks (IAC-ENC/NET/LOG/BAK/PRIV/CFG) over imported scanner output.

Pure functions over files a connector imported unmodified: Checkov JSON, or SARIF 2.1.0 from
any scanner. No network, no framework IDs: each scanner rule is put in a control family by
mappings/iac_rules.yaml, and families map to objectives in checks.yaml.

Every scanner result is one item of the population for its family:
- failed rule           -> exception
- passed rule           -> ok
- suppressed or skipped -> review (a suppression is a decision someone made; an auditor
                           should see the reason rather than have it disappear)
A family with any exception FAILs; with only passes it PASSes; otherwise MANUAL_REVIEW.
A family no scanner rule touched produces no finding: absence of results is not evidence.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from auditforge.checks.population import EXCEPTION, OK, REVIEW, ItemResult, population_status, summary
from auditforge.models import Finding, RawResponse

SARIF_VERSION = "2.1.0"


@dataclass(frozen=True)
class ScanResult:
    tool: str
    rule_id: str
    rule_name: str
    outcome: str  # OK | EXCEPTION | REVIEW
    resource: str
    file: str
    line: int | None
    severity: str | None
    note: str
    evidence_id: str


def detect_format(body: Any) -> str | None:
    """'sarif', 'checkov' or None."""
    if (
        isinstance(body, dict)
        and str(body.get("version")) == SARIF_VERSION
        and isinstance(body.get("runs"), list)
    ):
        return "sarif"
    blocks = body if isinstance(body, list) else [body]
    if blocks and all(isinstance(b, dict) and "check_type" in b for b in blocks):
        return "checkov"
    return None


def parse_checkov(raw: RawResponse) -> list[ScanResult]:
    blocks = raw.body if isinstance(raw.body, list) else [raw.body]
    out = []
    for block in blocks:
        tool = f"checkov/{block.get('check_type', '?')}"
        results = block.get("results") or {}
        for key, outcome in (("failed_checks", EXCEPTION), ("passed_checks", OK), ("skipped_checks", REVIEW)):
            for c in results.get(key) or []:
                check_result = c.get("check_result") or {}
                if outcome == REVIEW:
                    note = f"suppressed in code: {check_result.get('suppress_comment') or 'no reason given'}"
                elif outcome == EXCEPTION:
                    note = c.get("guideline") or "rule failed"
                else:
                    note = "rule passed"
                lines = c.get("file_line_range") or [None]
                out.append(
                    ScanResult(
                        tool=tool,
                        rule_id=str(c.get("check_id", "?")),
                        rule_name=str(c.get("check_name", "")),
                        outcome=outcome,
                        resource=str(c.get("resource", "")),
                        file=str(c.get("repo_file_path") or c.get("file_path") or ""),
                        line=lines[0],
                        severity=c.get("severity"),
                        note=note,
                        evidence_id=raw.evidence.evidence_id,
                    )  # fmt: skip
                )
    return out


def _sarif_location(result: dict[str, Any]) -> tuple[str, int | None, str]:
    loc = (result.get("locations") or [{}])[0]
    physical = loc.get("physicalLocation") or {}
    file = (physical.get("artifactLocation") or {}).get("uri", "")
    line = (physical.get("region") or {}).get("startLine")
    logical = (loc.get("logicalLocations") or [{}])[0]
    resource = logical.get("fullyQualifiedName") or logical.get("name") or file
    return file, line, resource


def parse_sarif(raw: RawResponse) -> list[ScanResult]:
    out = []
    for run in raw.body.get("runs") or []:
        driver = ((run.get("tool") or {}).get("driver")) or {}
        tool = driver.get("name", "sarif")
        rules = {r.get("id"): r for r in driver.get("rules") or []}
        for res in run.get("results") or []:
            rule_id = res.get("ruleId") or (res.get("rule") or {}).get("id") or "?"
            rule = rules.get(rule_id) or {}
            name = (
                (rule.get("shortDescription") or {}).get("text")
                or rule.get("name")
                or (res.get("message") or {}).get("text", "")
            )
            kind = res.get("kind", "fail")  # SARIF's default kind is fail
            if kind == "notApplicable":
                continue
            level = res.get("level") or (rule.get("defaultConfiguration") or {}).get("level") or "warning"
            suppressions = res.get("suppressions") or []
            if suppressions:
                why = "; ".join(s.get("justification") or s.get("kind", "") for s in suppressions)
                outcome, note = REVIEW, f"suppressed: {why or 'no reason given'}"
            elif kind == "pass":
                outcome, note = OK, "rule passed"
            elif kind == "fail":
                outcome, note = EXCEPTION, (res.get("message") or {}).get("text", "rule failed")
            else:  # open, review, informational: the scanner itself could not decide
                outcome, note = REVIEW, f"scanner marked it '{kind}'; decide whether it applies"
            file, line, resource = _sarif_location(res)
            severity = (rule.get("properties") or {}).get("security-severity") or level
            out.append(
                ScanResult(
                    tool,
                    str(rule_id),
                    str(name),
                    outcome,
                    resource,
                    file,
                    line,
                    str(severity),
                    note,
                    raw.evidence.evidence_id,
                )  # fmt: skip
            )
    return out


def parse(raw: RawResponse) -> list[ScanResult]:
    fmt = detect_format(raw.body)
    if fmt == "sarif":
        return parse_sarif(raw)
    if fmt == "checkov":
        return parse_checkov(raw)
    raise ValueError(f"{raw.evidence.file_path} is neither Checkov JSON nor SARIF {SARIF_VERSION}")


def classify(result: ScanResult, cfg: dict[str, Any]) -> tuple[str, str]:
    """(family check ID, why). Explicit rule ID, then first keyword match, then the fallback."""
    explicit = (cfg.get("rules") or {}).get(result.rule_id)
    if explicit:
        return explicit, f"rule {result.rule_id} listed in iac_rules.yaml"
    text = f"{result.rule_name} {result.rule_id}".lower()
    for family, spec in (cfg.get("families") or {}).items():
        for keyword in spec.get("keywords") or []:
            if str(keyword).lower() in text:
                return family, f"keyword '{keyword}'"
    return cfg["fallback"], "no family matched; configuration baseline"


def evaluate(
    files: list[RawResponse], cfg: dict[str, Any], titles: dict[str, str], resource: str
) -> list[Finding]:
    results = [r for f in files for r in parse(f)]
    families: dict[str, list[tuple[ScanResult, str]]] = {}
    for r in results:
        family, why = classify(r, cfg)
        families.setdefault(family, []).append((r, why))

    order = [*(cfg.get("families") or {}), cfg["fallback"]]
    findings = []
    for family in sorted(families, key=lambda f: order.index(f) if f in order else len(order)):
        items = [
            ItemResult(
                item=f"{r.rule_id} {r.resource}".strip(),
                outcome=r.outcome,
                note=r.note,
                facts={
                    "tool": r.tool,
                    "rule_id": r.rule_id,
                    "rule_name": r.rule_name,
                    "resource": r.resource,
                    "file": r.file,
                    "line": r.line,
                    "severity": r.severity,
                    "classified_by": why,
                },  # fmt: skip
            )
            for r, why in families[family]
        ]
        # Failures first, so the detail names them.
        items.sort(key=lambda i: {EXCEPTION: 0, REVIEW: 1, OK: 2}[i.outcome])
        status, detail = population_status(items, "scanner results", "passed", "failed")
        findings.append(
            Finding(
                check_id=family,
                title=titles.get(family, family),
                resource=resource,
                status=status,
                detail=detail,
                observed={"tools": sorted({r.tool for r, _ in families[family]}), **summary(items)},
                evidence_ids=sorted({r.evidence_id for r, _ in families[family]}),
            )
        )
    return findings
