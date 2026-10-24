"""Remediation drafts: Terraform, policy-as-code (Rego) and evidence scripts for failing checks.

AuditForge never applies a change (it is read-only by design). This module only writes draft
files into remediation/<run_id>/ for a person to review, test and merge through their normal
change process. Each draft says which run and check produced it.

Values taken from a report (repo names, Terraform resource names, PR numbers) end up inside
code, and reports describe systems the operator does not fully control, so every value is
checked against a strict pattern first; anything that does not match is left as a TODO.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from importlib.resources import files
from pathlib import Path
from string import Template
from typing import Any

import yaml

from auditforge import __version__

TEMPLATE_PACKAGE = "auditforge.remediation.templates"
INDEX = "drafts.yaml"
ACTIONABLE = ("FAIL", "MANUAL_REVIEW")

REPO = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
BRANCH = re.compile(r"^[A-Za-z0-9._/-]+$")
TF_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]*$")
GITHUB_REMOTE = re.compile(r"github\.com[:/]([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+?)(?:\.git)?/?$")


class DraftTemplate(Template):
    """@{name} placeholders, so Terraform's ${...} and Python's f-strings pass through untouched."""

    delimiter = "@"


@dataclass
class Draft:
    draft_id: str
    kind: str
    output: str
    triggers: list[str] = field(default_factory=list)  # "GIT-CM-03 FAIL"
    content: str = ""
    skipped: list[str] = field(default_factory=list)  # items that could not be templated safely


def _read(name: str) -> str:
    return files(TEMPLATE_PACKAGE).joinpath(name).read_text(encoding="utf-8")


def load_index() -> dict[str, Any]:
    return (yaml.safe_load(_read(INDEX)) or {}).get("drafts") or {}


def target_repo_and_branch(report: dict[str, Any]) -> tuple[str, str]:
    """owner/repo and branch for the report's target, or TODO placeholders if unknown or unsafe."""
    t = report.get("target") or {}
    repo = t.get("repo") or ""
    if not repo and t.get("remote"):
        m = GITHUB_REMOTE.search(t["remote"])
        repo = m.group(1) if m else ""
    branch = t.get("branch") or str(t.get("ref") or "").removeprefix("origin/")
    return (repo if REPO.match(repo) else "OWNER/REPO"), (branch if BRANCH.match(branch) else "main")


def _pull_requests(findings: list[dict[str, Any]]) -> tuple[list[int], list[str]]:
    numbers, unnumbered = set(), set()
    for f in findings:
        for item in (f.get("observed") or {}).get("items") or []:
            pr = item.get("pull_request") or item.get("number")
            if isinstance(pr, int):
                numbers.add(pr)
            elif re.fullmatch(r"[0-9a-f]{40}", str(item.get("sha", ""))):
                unnumbered.add(item["sha"][:12])
    return sorted(numbers), sorted(unnumbered)


def build(report: dict[str, Any]) -> list[Draft]:
    """Drafts for every FAIL / MANUAL_REVIEW finding in a signed check report."""
    index = load_index()
    actionable = [f for f in report.get("findings") or [] if f.get("status") in ACTIONABLE]
    repo, branch = target_repo_and_branch(report)
    drafts: list[Draft] = []
    for draft_id, spec in index.items():
        hits = [f for f in actionable if f["check_id"] in spec["checks"]]
        if not hits:
            continue
        draft = Draft(
            draft_id, spec["kind"], spec["output"], [f"{f['check_id']} {f['status']}" for f in hits]
        )
        prs, unnumbered = _pull_requests(hits)
        values = {
            "tool_version": __version__,
            "run_id": report["run_id"],
            "triggers": ", ".join(draft.triggers),
            "repo": repo,
            "branch": branch,
            "tf_branch": re.sub(r"[^A-Za-z0-9_]", "_", branch) or "main",
            "pull_requests": repr(prs),
            "unnumbered": ", ".join(unnumbered) or "none",
        }
        content = DraftTemplate(_read(spec["template"])).substitute(values)
        if spec.get("per_item"):
            items = 0
            for f in hits:
                for item in (f.get("observed") or {}).get("items") or []:
                    if item.get("outcome") != "exception":
                        continue
                    rtype, _, name = str(item.get("resource", "")).partition(".")
                    if rtype != spec["per_item"]:
                        continue
                    if not TF_NAME.match(name):
                        draft.skipped.append(f"{item.get('resource')!r} (name not safe to template)")
                        continue
                    rule = f"{item.get('rule_id', '')} {item.get('rule_name', '')}".strip()
                    content += DraftTemplate(_read(spec["item_template"])).substitute(
                        values, name=name, address=f"{rtype}.{name}", rule=re.sub(r"[\r\n]", " ", rule)
                    )
                    items += 1
            if items == 0:
                continue  # nothing of this resource type failed; a header alone is not a draft
        draft.content = content
        drafts.append(draft)
    return drafts


def readme(report: dict[str, Any], drafts: list[Draft]) -> str:
    lines = [
        f"# Remediation drafts for run `{report['run_id']}`",
        "",
        f"Source report: {report.get('title', report['run_id'])}",
        "",
        "**These are drafts. AuditForge never applies changes.** Review each file, adjust the TODOs, test it",
        "(`terraform plan`, `conftest test`, or a dry run of the script) and merge it through your normal,",
        "reviewed change process. After the change is in place, re-run the check to produce new evidence.",
        "",
        "| File | Kind | Triggered by |",
        "|---|---|---|",
    ]
    lines += [f"| `{d.output}` | {d.kind} | {', '.join(d.triggers)} |" for d in drafts]
    skipped = [(d.output, s) for d in drafts for s in d.skipped]
    if skipped:
        lines += ["", "## Not templated", ""]
        lines += [f"- `{out}`: {s}" for out, s in skipped]
    return "\n".join(lines) + "\n"


def write(report: dict[str, Any], drafts: list[Draft], out_dir: Path) -> list[Path]:
    written = []
    for d in drafts:
        path = out_dir / d.output
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(d.content, encoding="utf-8")
        written.append(path)
    (out_dir / "README.md").write_text(readme(report, drafts), encoding="utf-8")
    return written
