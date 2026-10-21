#!/usr/bin/env python3
"""
AuditForge - GitHub branch protection check (change management evidence).

Verifies that a branch requires:
  1. Pull requests before merging
  2. A minimum number of approving reviews
  3. Stale approvals dismissed on new pushes
  4. Signed commits
  5. Rules enforced for administrators (no silent bypass)

Reads both classic branch protection AND repository rulesets, captures the raw
API responses as evidence (SHA-256 hashed), maps each result to SOC 2 / ISO 27001
/ NIST 800-53 control IDs, and writes a JSON + Markdown report signed with Ed25519.

Usage:
    export GITHUB_TOKEN=ghp_...            # fine-grained: "Administration: read" on the repo
    python branch_protection_check.py --repo myorg/payments-api --branch main
    python branch_protection_check.py --verify reports/<run>/report.json

Requirements:  pip install requests cryptography
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import sys
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

import requests
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

TOOL_VERSION = "0.1.0"
API = "https://api.github.com"
KEY_DIR = Path(os.environ.get("AUDITFORGE_HOME", Path.home() / ".auditforge")) / "keys"

# ---------------------------------------------------------------------------
# Control mapping. In the full tool this lives in mappings/*.yaml; it is inline
# here so the snippet runs on its own.
# ---------------------------------------------------------------------------
CONTROL_MAP: dict[str, dict[str, list[str]]] = {
    "GH-BP-01": {"SOC2": ["CC8.1"], "ISO27001:2022": ["A.8.32"], "NIST-800-53r5": ["CM-3"]},
    "GH-BP-02": {"SOC2": ["CC8.1"], "ISO27001:2022": ["A.8.32", "A.8.4"], "NIST-800-53r5": ["CM-3", "AC-5"]},
    "GH-BP-03": {"SOC2": ["CC8.1"], "ISO27001:2022": ["A.8.32"], "NIST-800-53r5": ["CM-3"]},
    "GH-BP-04": {"SOC2": ["CC8.1"], "ISO27001:2022": ["A.8.4", "A.8.28"], "NIST-800-53r5": ["SI-7"]},
    "GH-BP-05": {"SOC2": ["CC6.1", "CC8.1"], "ISO27001:2022": ["A.8.2", "A.8.32"], "NIST-800-53r5": ["AC-5", "CM-5"]},
}


class Status(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    MANUAL_REVIEW = "MANUAL_REVIEW"  # automation can't decide; a human must


@dataclass
class Evidence:
    source: str          # API endpoint the data came from
    http_status: int
    collected_at: str
    sha256: str          # hash of the raw response body, for integrity
    file: str            # where the raw response is saved


@dataclass
class Finding:
    check_id: str
    title: str
    status: Status
    detail: str
    observed: dict[str, Any]
    controls: dict[str, list[str]] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Evidence collection
# ---------------------------------------------------------------------------
class GitHubCollector:
    def __init__(self, token: str, evidence_dir: Path) -> None:
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": f"AuditForge/{TOOL_VERSION}",
        })
        self.evidence_dir = evidence_dir
        self.evidence: list[Evidence] = []

    def get(self, path: str, label: str) -> tuple[int, Any]:
        url = f"{API}{path}"
        resp = self.session.get(url, timeout=20)
        body = resp.content
        raw_file = self.evidence_dir / f"{label}.json"
        raw_file.write_bytes(body)
        self.evidence.append(Evidence(
            source=f"GET {url}",
            http_status=resp.status_code,
            collected_at=_now(),
            sha256=hashlib.sha256(body).hexdigest(),
            file=raw_file.name,
        ))
        if resp.status_code == 401:
            raise SystemExit("GitHub rejected the token (401). Check GITHUB_TOKEN.")
        try:
            return resp.status_code, resp.json()
        except ValueError:
            return resp.status_code, None


# ---------------------------------------------------------------------------
# Evaluation: merge classic protection + rulesets into one effective view
# ---------------------------------------------------------------------------
def effective_settings(classic_status: int, classic: Any, rules_status: int, rules: Any) -> dict[str, Any]:
    eff: dict[str, Any] = {
        "pr_required": False,
        "approvals": 0,
        "dismiss_stale": False,
        "signed_commits": False,
        "enforce_admins": None,  # None = unknown (rulesets hide bypass actors from this endpoint)
        "sources": [],
        "classic_readable": classic_status in (200, 404),
    }

    if classic_status == 200 and isinstance(classic, dict):
        eff["sources"].append("classic_branch_protection")
        pr = classic.get("required_pull_request_reviews")
        if pr:
            eff["pr_required"] = True
            eff["approvals"] = pr.get("required_approving_review_count", 0)
            eff["dismiss_stale"] = bool(pr.get("dismiss_stale_reviews"))
        eff["signed_commits"] = bool((classic.get("required_signatures") or {}).get("enabled"))
        eff["enforce_admins"] = bool((classic.get("enforce_admins") or {}).get("enabled"))

    if rules_status == 200 and isinstance(rules, list) and rules:
        eff["sources"].append("repository_rulesets")
        for rule in rules:
            rtype = rule.get("type")
            params = rule.get("parameters") or {}
            if rtype == "pull_request":
                eff["pr_required"] = True
                eff["approvals"] = max(eff["approvals"], params.get("required_approving_review_count", 0))
                eff["dismiss_stale"] = eff["dismiss_stale"] or bool(params.get("dismiss_stale_reviews_on_push"))
            elif rtype == "required_signatures":
                eff["signed_commits"] = True
    return eff


def evaluate(eff: dict[str, Any], min_approvals: int) -> list[Finding]:
    obs = {k: eff[k] for k in ("pr_required", "approvals", "dismiss_stale", "signed_commits", "enforce_admins", "sources")}
    findings = [
        Finding("GH-BP-01", "Changes require a pull request",
                Status.PASS if eff["pr_required"] else Status.FAIL,
                "Direct pushes are blocked; changes go through a PR." if eff["pr_required"]
                else "No PR requirement found; code can be pushed straight to the branch.", obs),
        Finding("GH-BP-02", f"At least {min_approvals} approving review(s) before merge",
                Status.PASS if eff["approvals"] >= min_approvals else Status.FAIL,
                f"Required approvals configured: {eff['approvals']} (threshold {min_approvals}).", obs),
        Finding("GH-BP-03", "Stale approvals dismissed on new commits",
                Status.PASS if eff["dismiss_stale"] else Status.FAIL,
                "An approval stays valid after new code is pushed, so unreviewed code can merge."
                if not eff["dismiss_stale"] else "New pushes invalidate earlier approvals.", obs),
        Finding("GH-BP-04", "Signed commits required",
                Status.PASS if eff["signed_commits"] else Status.FAIL,
                "Commit signature verification is enforced." if eff["signed_commits"]
                else "Unsigned commits are accepted; author identity is not cryptographically verified.", obs),
    ]
    if eff["enforce_admins"] is None:
        admin = (Status.MANUAL_REVIEW,
                 "Classic protection is absent or unreadable. Review the ruleset bypass list in "
                 "Settings > Rules and record who may bypass, with business justification.")
    elif eff["enforce_admins"]:
        admin = (Status.PASS, "Administrators are subject to the same rules.")
    else:
        admin = (Status.FAIL, "Administrators can bypass protection, which defeats segregation of duties.")
    findings.append(Finding("GH-BP-05", "Protection enforced for administrators", admin[0], admin[1], obs))

    for f in findings:
        f.controls = CONTROL_MAP[f.check_id]
    return findings


# ---------------------------------------------------------------------------
# Signing
# ---------------------------------------------------------------------------
def load_or_create_key() -> Ed25519PrivateKey:
    KEY_DIR.mkdir(parents=True, exist_ok=True)
    priv_path, pub_path = KEY_DIR / "signing_key.pem", KEY_DIR / "signing_key.pub.pem"
    if priv_path.exists():
        key = serialization.load_pem_private_key(priv_path.read_bytes(), password=None)
        assert isinstance(key, Ed25519PrivateKey)
        return key
    key = Ed25519PrivateKey.generate()
    priv_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                            serialization.NoEncryption()))
    priv_path.chmod(0o600)
    pub_path.write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM,
                                                       serialization.PublicFormat.SubjectPublicKeyInfo))
    print(f"Created signing key in {KEY_DIR} (share the .pub.pem with your auditor)", file=sys.stderr)
    return key


def canonical(obj: dict[str, Any]) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sign_report(report: dict[str, Any], key: Ed25519PrivateKey) -> dict[str, Any]:
    payload = canonical(report)
    pub = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return {
        "algorithm": "Ed25519",
        "payload_sha256": hashlib.sha256(payload).hexdigest(),
        "public_key": base64.b64encode(pub).decode(),
        "public_key_fingerprint": hashlib.sha256(pub).hexdigest()[:16],
        "signature": base64.b64encode(key.sign(payload)).decode(),
    }


def verify(report_path: Path) -> int:
    doc = json.loads(report_path.read_text())
    sig = doc.pop("signature")
    pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(sig["public_key"]))
    try:
        pub.verify(base64.b64decode(sig["signature"]), canonical(doc))
    except InvalidSignature:
        print("INVALID: report was modified after signing.")
        return 1
    # Re-hash the raw evidence files the report points to.
    bad = [e["file"] for e in doc["evidence"]
           if hashlib.sha256((report_path.parent / "evidence" / e["file"]).read_bytes()).hexdigest() != e["sha256"]]
    if bad:
        print(f"INVALID: evidence files changed: {', '.join(bad)}")
        return 1
    print(f"VALID: signature and {len(doc['evidence'])} evidence hashes check out "
          f"(key fingerprint {sig['public_key_fingerprint']}).")
    return 0


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------
def to_markdown(report: dict[str, Any]) -> str:
    icon = {"PASS": "✅", "FAIL": "❌", "MANUAL_REVIEW": "⚠️"}
    s = report["summary"]
    lines = [
        f"# Branch Protection Compliance Report — `{report['target']['repo']}@{report['target']['branch']}`",
        "",
        f"- **Run ID:** `{report['run_id']}`",
        f"- **Collected:** {report['collected_at']}",
        f"- **Tool:** AuditForge {report['tool_version']}",
        f"- **Result:** {s['pass']} pass · {s['fail']} fail · {s['manual_review']} manual review",
        "",
        "| Check | Result | SOC 2 | ISO 27001:2022 | NIST 800-53 r5 | Detail |",
        "|---|---|---|---|---|---|",
    ]
    for f in report["findings"]:
        c = f["controls"]
        lines.append(
            f"| {f['check_id']} {f['title']} | {icon[f['status']]} {f['status']} | "
            f"{', '.join(c['SOC2'])} | {', '.join(c['ISO27001:2022'])} | "
            f"{', '.join(c['NIST-800-53r5'])} | {f['detail']} |")
    lines += ["", "## Evidence", "", "| File | Source | HTTP | SHA-256 |", "|---|---|---|---|"]
    for e in report["evidence"]:
        lines.append(f"| `{e['file']}` | {e['source']} | {e['http_status']} | `{e['sha256'][:16]}…` |")
    sig = report["signature"]
    lines += ["", "## Integrity", "",
              f"Signed with {sig['algorithm']} (key fingerprint `{sig['public_key_fingerprint']}`). "
              "Verify with `python branch_protection_check.py --verify report.json`.", ""]
    return "\n".join(lines)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def run(repo: str, branch: str, min_approvals: int, out_root: Path) -> int:
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        raise SystemExit("Set GITHUB_TOKEN first.")
    run_id = f"{datetime.now(timezone.utc):%Y%m%dT%H%M%SZ}-{uuid.uuid4().hex[:6]}"
    run_dir = out_root / run_id
    (run_dir / "evidence").mkdir(parents=True)

    gh = GitHubCollector(token, run_dir / "evidence")
    c_status, classic = gh.get(f"/repos/{repo}/branches/{branch}/protection", "classic_protection")
    r_status, rules = gh.get(f"/repos/{repo}/rules/branches/{branch}", "rulesets")
    if r_status == 404 and c_status in (403, 404):
        raise SystemExit(f"Repo or branch not found, or token lacks access: {repo}@{branch}")

    eff = effective_settings(c_status, classic, r_status, rules)
    findings = evaluate(eff, min_approvals)

    report: dict[str, Any] = {
        "schema": "auditforge.report/v1",
        "tool_version": TOOL_VERSION,
        "run_id": run_id,
        "collected_at": _now(),
        "target": {"platform": "github", "repo": repo, "branch": branch},
        "parameters": {"min_approvals": min_approvals},
        "summary": {
            "pass": sum(f.status is Status.PASS for f in findings),
            "fail": sum(f.status is Status.FAIL for f in findings),
            "manual_review": sum(f.status is Status.MANUAL_REVIEW for f in findings),
        },
        "findings": [{**asdict(f), "status": f.status.value} for f in findings],
        "evidence": [asdict(e) for e in gh.evidence],
    }
    report["signature"] = sign_report(report, load_or_create_key())

    (run_dir / "report.json").write_text(json.dumps(report, indent=2, ensure_ascii=False))
    (run_dir / "report.md").write_text(to_markdown(report), encoding="utf-8")
    print(f"Report written to {run_dir}  ({report['summary']})")
    return 1 if report["summary"]["fail"] else 0  # non-zero exit lets CI gate on failures


def main() -> int:
    p = argparse.ArgumentParser(description="AuditForge: GitHub branch protection check")
    p.add_argument("--repo", help="owner/repo")
    p.add_argument("--branch", default="main")
    p.add_argument("--min-approvals", type=int, default=1)
    p.add_argument("--out", type=Path, default=Path("reports"))
    p.add_argument("--verify", type=Path, help="verify a signed report.json and its evidence")
    a = p.parse_args()
    if a.verify:
        return verify(a.verify)
    if not a.repo or "/" not in a.repo:
        p.error("--repo owner/repo is required")
    return run(a.repo, a.branch, a.min_approvals, a.out)


if __name__ == "__main__":
    sys.exit(main())
