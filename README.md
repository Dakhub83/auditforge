# AuditForge

Local compliance evidence collection. AuditForge reads security settings from your systems
(read-only), saves the raw API responses as hashed evidence, evaluates them, maps each result to
SOC 2, ISO/IEC 27001:2022, NIST SP 800-53 Rev 5 and SOX ITGC controls, and writes a report signed
with Ed25519 that an auditor can verify independently.

Architecture and contribution rules are in [CLAUDE.md](CLAUDE.md).

## Install

```sh
uv sync                 # or: python -m venv .venv && .venv/Scripts/pip install -e . pytest responses ruff
```

## GitHub branch protection

Create a fine-grained token with read-only **Administration** access to the repo, and set it in
your shell (never commit it; `.env` is gitignored):

```powershell
$env:GITHUB_TOKEN = "github_pat_..."          # PowerShell
```
```sh
export GITHUB_TOKEN=github_pat_...            # bash
```

```sh
auditforge check github-branch-protection --repo myorg/payments-api --branch main
```

Each run writes `evidence/<run_id>/` containing `raw/` (unmodified API responses), `report.json`
and `report.md`, and records the run in `auditforge.db`.

| Check | Tests | Result if it can't see enough |
|---|---|---|
| GH-BP-01 | PR required before merge | MANUAL_REVIEW |
| GH-BP-02 | Minimum approvals (`--min-approvals`, default 1) | MANUAL_REVIEW |
| GH-BP-03 | Stale approvals dismissed on push | MANUAL_REVIEW |
| GH-BP-04 | Signed commits required | MANUAL_REVIEW |
| GH-BP-05 | Admins can't bypass protection | MANUAL_REVIEW |

Exit codes: `0` no FAIL findings, `1` at least one FAIL (use it to gate CI), `2` could not run.

## Verifying a report

The first run creates a signing key in `~/.auditforge/keys/` (override with `AUDITFORGE_HOME`).
Give `signing_key.pub.pem` to your auditor through a separate channel. They verify with:

```sh
auditforge verify evidence/<run_id>/report.json --pubkey signing_key.pub.pem
```

This checks the signature against that trusted key and re-hashes every evidence file. Without
`--pubkey`, your own public key is used.

**Windows:** file permissions on the private key are not restricted automatically. Keep
`AUDITFORGE_HOME` in a folder only your account can read.

## Mappings

`mappings/checks.yaml` maps checks to internal control objectives; `mappings/crosswalk.yaml` maps
objectives to framework control IDs. Each report records the SHA-256 of both files.

## Development

```sh
pytest          # all GitHub calls are mocked; tests never touch the network
ruff check . && ruff format --check .
```
