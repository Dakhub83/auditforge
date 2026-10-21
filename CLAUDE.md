# AuditForge

Local GRC compliance automation and evidence-collection CLI. Built by a GRC Analyst / IT Auditor
(former full-stack Java developer) to produce audit-ready, tamper-evident evidence that maps
technical telemetry to SOC 2, ISO/IEC 27001:2022, NIST SP 800-53 Rev 5, and SOX ITGC controls.

## Stack
- Python 3.11+, type hints everywhere, `dataclasses` or Pydantic for models
- CLI: `typer` · HTTP: `requests` · Signing: `cryptography` (Ed25519) · Store: SQLite (stdlib `sqlite3`)
- Packaging: `uv` + `pyproject.toml` · Tests: `pytest` with recorded/mocked API responses (never live calls in tests)
- Lint/format: `ruff`

## Architecture rules
1. **Connectors only collect.** `auditforge/connectors/*` fetch data and save the raw response
   unmodified to `evidence/<run_id>/raw/`, recording source URI, timestamp, HTTP status (or exit
   code for local commands), SHA-256. Local connectors treat the target (e.g. a git clone) as untrusted.
2. **Checks are pure functions.** `auditforge/checks/*` take raw evidence and return `Finding`
   objects. No network calls inside checks.
3. **Mappings are data, not code.** Check → internal control objective in `mappings/checks.yaml`;
   objective → framework control IDs in `mappings/crosswalk.yaml`. Never hardcode framework IDs in checks.
4. **Status is PASS | FAIL | MANUAL_REVIEW.** If automation cannot see enough to decide, return
   MANUAL_REVIEW with what a human must check. Never guess a PASS.
5. **Reports are signed.** Every run produces `report.json` + `report.md`, signed with Ed25519 over
   canonical JSON. `auditforge verify` must re-check the signature and every evidence hash, against a
   trusted public key supplied out of band — never the key embedded in the report.
6. **Read-only by default.** Connectors use least-privilege, read-only credentials. Never write to
   GitHub, AWS, or GCP. Never log or store tokens.
7. **No copyrighted standard text.** Reference control IDs and short paraphrased titles only.

## SQLite schema (auditforge.db)
- runs(run_id PK, started_at, tool_version, operator, signature)
- evidence(evidence_id PK, run_id FK, source_uri, collected_at, sha256, file_path)
- findings(finding_id PK, run_id FK, check_id, resource, status, detail)
- finding_evidence(finding_id FK, evidence_id FK)  — a finding can rest on several evidence items
- controls(control_id, framework, title)  — composite PK (framework, control_id)
- check_control_map(check_id, framework, control_id)
- exceptions(finding_id FK, approved_by, reason, expires_at)  — risk acceptance is human-entered
- Risk register (design: docs/risk-register.md; DDL: auditforge/risk/register.py):
  assets, risks (scores are generated columns L×I; residual ≤ inherent), risk_assets (C/I/A),
  risk_controls (FK → controls), mitigations, risk_history (append-only via triggers)

## Roadmap
- [x] GitHub branch protection (GH-BP-01..05) — classic protection + rulesets, signed report
      (`auditforge check github-branch-protection`; refactored from the `branch_protection_check.py` prototype)
- [x] Module A: Change management integrity (GH-CM-01..03) — full population of merged PRs over an audit period
      (independent approver ≠ author on the merged commit, CI passed, no commits landed outside a PR)
      → SOC 2 CC8.1, ISO A.8.32, NIST CM-3, SOX ITGC program change (`auditforge check github-change-management`)
      Follow-ups: detect approvers who also pushed to the PR; org audit log for pushes/bypasses (Enterprise only)
- [x] Local-only mode (GIT-CM-01..03) — `auditforge check git-change-management` reads a local clone, no network.
      Direct pushes are decidable (GitHub web-flow signature); approvals/CI are MANUAL_REVIEW with the population.
      `--merge-key`/`--merge-committer-email` support GitHub Enterprise Server.
      Follow-up: signed-commit check (GH-BP-04 analogue) from git
- [x] Risk register (Eramba-style) — `auditforge asset|risk ...`: 5x5 inherent/residual scoring
      (method in mappings/risk_matrix.yaml), assets with C/I/A impact, links to catalog controls,
      mitigations with owners, append-only history; flags residual scores resting on FAILing controls
- [x] UI: `auditforge view` — one self-contained HTML file (no network) with dashboard, risk register and
      evidence runs; re-verifies every run's signature + evidence hashes at build time. Theme tokens: auditforge/ui/template.html
- [ ] Module B: Access review — AWS IAM, GCP IAM, GitHub org members; dormant accounts, admin sprawl, MFA gaps,
      orphans vs. HR roster CSV → SOC 2 CC6.1–CC6.3, ISO A.5.15/A.5.18/A.8.2, NIST AC-2/AC-6
- [ ] Module C: Config baseline drift — snapshot + diff security settings per run → SOC 2 CC7.1, ISO A.8.9, NIST CM-2/CM-6
- [ ] Exporters: Excel workpaper (one tab per control, evidence hashes listed)

## Working style
- Small, reviewable changes. Write or update tests with every check.
- Explain control-mapping choices in comments so an auditor can follow the reasoning.
- Ask before adding a new dependency.
