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

## GitHub change management (full population)

Branch protection shows how the branch is *configured*. This command tests what actually
*happened*: every PR merged into the branch during the audit period, with no sampling.

The token needs read-only **Pull requests**, **Contents**, **Checks** and **Commit statuses**.

```sh
auditforge check github-change-management --repo myorg/payments-api --branch main \
    --period-start 2026-01-01 --period-end 2026-06-30      # inclusive dates, UTC
```

| Check | Tests, for every change in the period | Result if it can't see enough |
|---|---|---|
| GH-CM-01 | Approved by someone other than the author (not a bot), on the commit that merged | MANUAL_REVIEW |
| GH-CM-02 | CI (check runs and commit statuses) passed on the merged commit | MANUAL_REVIEW |
| GH-CM-03 | Every commit that landed on the branch (first-parent history) came through a merged PR | MANUAL_REVIEW |

Each finding is population-level: its detail names the exceptions, and `observed.items` in
`report.json` lists every PR or commit with its outcome, for the auditor's population listing.
The population is rebuilt from the saved PR list pages, so it can be re-derived from the evidence.

Known limits, which are reported as MANUAL_REVIEW or explained in the finding detail:
- The PR API does not record whether a merge bypassed protection. A bypassed merge appears as a
  GH-CM-01 or GH-CM-02 exception, and a bypassed push appears as a GH-CM-03 exception.
- Commit dates are set by the client, so a backdated direct push can fall outside the window.
  The org audit log (GitHub Enterprise) is the authoritative record of pushes.
- An approval on an earlier commit (often just "Update branch") is MANUAL_REVIEW, not PASS.
- CI results are read as they are now, not as they were at merge time.

## Local only: change management from a git clone

No token and no network access. AuditForge runs read-only git commands against a clone on
disk. It does not fetch, so run `git fetch` yourself first; the report records the exact commit
it analysed and the clone's remote URL.

```sh
auditforge check git-change-management --path ../payments-api --ref origin/main \
    --period-start 2026-01-01 --period-end 2026-06-30
```

| Check | What git can show | Result |
|---|---|---|
| GIT-CM-01 | Approvals are not stored in git | Always MANUAL_REVIEW, listing every change to confirm in GitHub |
| GIT-CM-02 | CI results are not stored in git | Always MANUAL_REVIEW, listing every change to confirm |
| GIT-CM-03 | Each commit that landed on the branch (`git log --first-parent`) was created by GitHub's merge | PASS / FAIL; MANUAL_REVIEW if signatures can't be checked |

When GitHub merges a PR (merge, squash or rebase), the landing commit's committer is
`GitHub <noreply@github.com>` and it is signed with GitHub's **web-flow** key. Anyone can type
that committer name, so only a good signature from that key counts. Import the key into gpg
once, on any machine that has internet access, and confirm its fingerprint:

```sh
curl -s https://github.com/web-flow.gpg | gpg --import
```

Without the key, GitHub merges show as MANUAL_REVIEW ("signature could not be checked");
direct pushes are still FAIL.

The clone is treated as untrusted input: settings in its `.git/config` that would make git run
a program (e.g. `gpg.program`) are overridden, and replace refs are ignored. A shallow clone is
MANUAL_REVIEW (run `git fetch --unshallow`).

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
