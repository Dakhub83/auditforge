"""Scope for a gap assessment: which frameworks apply, which controls are excluded and why.

Kept as a YAML file the organisation versions alongside its policies, because it is a
management decision (ISO 27001's Statement of Applicability), not something the tool infers.

    frameworks: [SOC2, ISO27001:2022]
    exclude:
      "ISO27001:2022 A.7.12": Fully remote; no premises cabling (hosting provider's SOC 2 covers it)
    owners:
      "SOC2 CC6.1": Priya Shah
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from auditforge.mappings import Mappings


class ScopeError(ValueError):
    pass


def control_key(framework: str, control_id: str) -> str:
    return f"{framework} {control_id}"


def split_key(key: str) -> tuple[str, str]:
    framework, _, control_id = key.rpartition(" ")
    return framework, control_id


@dataclass(frozen=True)
class Scope:
    frameworks: tuple[str, ...]
    exclusions: dict[str, str]  # control key -> justification
    owners: dict[str, str]  # control key -> owner
    raw: bytes
    path: Path

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.raw).hexdigest()

    @classmethod
    def load(cls, path: Path, mappings: Mappings) -> Scope:
        if not path.is_file():
            raise ScopeError(
                f"No scope file at {path}. Create one with: auditforge scope init --framework SOC2"
            )
        raw = path.read_bytes()
        doc: dict[str, Any] = yaml.safe_load(raw) or {}
        scope = cls(
            frameworks=tuple(doc.get("frameworks") or []),
            exclusions={str(k): str(v or "").strip() for k, v in (doc.get("exclude") or {}).items()},
            owners={str(k): str(v).strip() for k, v in (doc.get("owners") or {}).items()},
            raw=raw,
            path=path,
        )
        scope.validate(mappings)
        return scope

    def validate(self, mappings: Mappings) -> None:
        if not self.frameworks:
            raise ScopeError(f"{self.path}: list at least one framework under 'frameworks'")
        for fw in self.frameworks:
            if fw not in mappings.frameworks:
                raise ScopeError(
                    f"{self.path}: unknown framework {fw!r}; known: {', '.join(mappings.frameworks)}"
                )
        for section, entries in (("exclude", self.exclusions), ("owners", self.owners)):
            for key in entries:
                fw, cid = split_key(key)
                if fw not in self.frameworks or cid not in mappings.frameworks.get(fw, {}):
                    raise ScopeError(
                        f"{self.path}: {section} entry {key!r} is not an in-scope catalog control "
                        "(write it as '<framework> <control id>', e.g. 'SOC2 CC6.1')"
                    )
        for key, why in self.exclusions.items():
            if not why:
                raise ScopeError(f"{self.path}: exclusion of {key} needs a justification")

    def in_scope(self, mappings: Mappings) -> list[tuple[str, str, str]]:
        """(framework, control_id, title) for every applicable control, in catalog order."""
        return [
            (fw, cid, title)
            for fw in self.frameworks
            for cid, title in mappings.frameworks[fw].items()
            if control_key(fw, cid) not in self.exclusions
        ]


def starter_scope(frameworks: list[str], mappings: Mappings) -> str:
    """A scope.yaml to start from: frameworks set, every control listed as a comment."""
    for fw in frameworks:
        if fw not in mappings.frameworks:
            raise ScopeError(f"Unknown framework {fw!r}; known: {', '.join(mappings.frameworks)}")
    lines = [
        "# Gap assessment scope (statement of applicability). Review it with the control owners.",
        f"frameworks: [{', '.join(frameworks)}]",
        "",
        "# Exclude a control with a justification; ISO 27001 requires one for every exclusion.",
        "exclude: {}",
        '#  "ISO27001:2022 A.7.12": Fully remote; no premises cabling',
        "",
        "# Accountable owner per control, shown in the gap report.",
        "owners: {}",
        '#  "SOC2 CC6.1": Priya Shah',
        "",
    ]
    for fw in frameworks:
        lines.append(f"# {fw}: {len(mappings.frameworks[fw])} controls")
        lines += [f"#   {control_key(fw, cid):<26} {title}" for cid, title in mappings.frameworks[fw].items()]
    return "\n".join(lines) + "\n"
