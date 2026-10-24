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

**GitHub Enterprise Server** signs merges with the instance's own key and committer address.
Get both from your GitHub administrator (not from the repo being audited) and pass them;
the report records exactly which keys were trusted:

```sh
auditforge check git-change-management --path ../payments-api \
    --period-start 2026-01-01 --period-end 2026-03-31 \
    --merge-key <instance key fingerprint> --merge-committer-email noreply@git.example.internal
```

The clone is treated as untrusted input: settings in its `.git/config` that would make git run
a program (e.g. `gpg.program`) are overridden, and replace refs are ignored. A shallow clone is
MANUAL_REVIEW (run `git fetch --unshallow`).

## Infrastructure as code (Terraform, CloudFormation, Kubernetes)

AuditForge does not run scanners; it imports what they report, unmodified and hashed. Run any
scanner that emits Checkov JSON or SARIF 2.1.0 (Checkov, tfsec, KICS, kube-linter, Trivy, ...):

```sh
checkov -d infra/ -o json > checkov.json
kube-linter lint k8s/ --format sarif > kube.sarif
auditforge check iac --results checkov.json --results kube.sarif --target payments-infra
```

Each result lands in a control family (IAC-ENC encryption, IAC-NET exposure, IAC-LOG logging,
IAC-BAK recovery, IAC-PRIV least privilege, IAC-CFG baseline) by `mappings/iac_rules.yaml`:
an explicit rule ID first, then keywords, then the baseline fallback. Each item in the report says
which rule placed it there. Suppressed or skipped rules are MANUAL_REVIEW items with their reason.

## Gap assessment

```sh
auditforge scope init --framework SOC2 --framework ISO27001:2022   # writes scope.yaml
# edit scope.yaml: exclusions (with justification) and owners
auditforge attest add --control ISO27001:A.6.3 --result pass \
    --procedure "Reconciled LMS completions to HR roster" --evidence training.csv
auditforge gap --scope scope.yaml
```

The catalog covers SOC 2 Common Criteria (33), all 93 ISO 27001:2022 Annex A controls, the NIST
800-53 controls AuditForge maps, and the four SOX ITGC domains. For every in-scope control the
gap report combines the latest automated findings, manual attestations and finding exceptions:

| Status | Meaning |
|---|---|
| Failing | an automated FAIL, or a FAIL attestation (a manual PASS cannot override an automated FAIL) |
| Needs review | automation reached MANUAL_REVIEW and no later attestation resolves it |
| No evidence | nothing automated, no valid attestation (expired ones are noted) |
| Accepted | the only problems are covered by an active, approved exception |
| Covered | all automated results PASS, or a valid PASS attestation |

Gaps are ranked P1-P4 by gap type plus the highest linked risk score, sized S/M/L/XL, and grouped
with other gaps that share a control objective ("close together with"). Weights, tiers and sizes are
in `mappings/gap_method.yaml`. The report (`gap/<run_id>/gap-report.json` + `.md`) is signed and
carries the scope file and every attestation evidence file, so `auditforge verify` re-checks them.
Attestations are append-only and expire (default one year).

## Exceptions and sign-off

```sh
auditforge exception add --check GIT-CM-03 --resource payments-api@origin/main \
    --reason "Emergency hotfix process with post-review (SEC-12)" --approved-by "Dana (CISO)" \
    --expires 2027-01-31 --risk R-002
auditforge signoff add evidence/<run_id>/report.json --role preparer --note "Tested full population"
auditforge signoff add evidence/<run_id>/report.json --role reviewer      # a different person
```

An exception accepts a failing check on one resource until it expires (at most a year), carries over
to later runs, cannot be approved by the person recording it, and can be revoked. Sign-offs bind to
the exact signed report content, require a verified report, and a reviewer must differ from the
preparer. Both are append-only and appear in `auditforge view`.

## Remediation drafts

```sh
auditforge remediate evidence/<run_id>/report.json
```

Writes drafts for every FAIL or MANUAL_REVIEW finding to `remediation/<run_id>/`: Terraform
(GitHub branch protection, S3 encryption/logging/versioning), policy as code for conftest/OPA
(branch protection, encryption, network exposure, Kubernetes privilege) and a Python evidence script
for PR approvals and CI. Each file names the run and check that produced it. **AuditForge never
applies a change**: review, test and merge drafts through your change process, then re-run the check.

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

## Risk register

An Eramba-style register stored in `auditforge.db`, linked to the same controls the checks
test. Design: [docs/risk-register.md](docs/risk-register.md).

```sh
auditforge asset add --id AST-001 --name "Customer payments database" --type data \
    --owner "Priya Shah" --classification restricted
auditforge risk add --title "Customer data leaked from production database" \
    --category "Information security" --owner "Priya Shah" \
    --likelihood 4 --impact 5 --residual-likelihood 2 --residual-impact 5 \
    --asset AST-001:C --control SOC2:CC6.1 --control ISO27001:A.8.24
auditforge risk update R-001 --residual-likelihood 1      # scores recalculate
auditforge risk mitigate R-001 --description "Encrypt backups" --owner "Tom Okafor" --due 2026-11-30
auditforge risk list                                      # register + 5x5 heat map
auditforge risk export --out risk-register.csv            # spreadsheet, one row per risk
```

`risk export` writes a CSV that opens in Excel: scores and bands, appetite, assets with C/I/A,
linked controls with their latest automated result, mitigations and warnings. It is a snapshot;
`auditforge.db` with its history stays the record. Cells that would run as a spreadsheet formula
are prefixed with `'`.

Scores are likelihood x impact on a 5x5 matrix (Low 1-4, Medium 5-9, High 10-16,
Critical 20-25); level wording, bands, appetite and categories are in
`mappings/risk_matrix.yaml`. `risk show` lists the latest automated evidence for each linked
control and warns when a residual score relies on a control that is failing.

## Dashboard (`auditforge view`)

```sh
auditforge view --out auditforge-view.html                 # open the file in any browser
auditforge view --pubkey acme-operator.pub.pem             # verify runs against someone else's key
```

Writes one self-contained HTML file from `auditforge.db`: a dashboard, the risk register (5x5
heat map, inherent-to-residual sliders, per-risk detail with controls, mitigations and history)
and every evidence run with its tested population. The page loads nothing from the network.
While building it, AuditForge re-verifies each run's signature and evidence hashes against the
trusted key, and exits with code 1 if any run fails verification.
