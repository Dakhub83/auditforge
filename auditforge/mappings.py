"""Load check -> objective -> framework control mappings from YAML.

Checks never know framework IDs; reports ask this module which controls a
check's result is evidence for.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

CHECKS_FILE = "checks.yaml"
CROSSWALK_FILE = "crosswalk.yaml"


class MappingError(ValueError):
    pass


@dataclass(frozen=True)
class Mappings:
    checks: dict[str, Any]
    objectives: dict[str, Any]
    frameworks: dict[str, dict[str, str]]
    file_hashes: dict[str, str]  # sha256 of each YAML file, recorded in reports

    @classmethod
    def load(cls, directory: Path) -> Mappings:
        hashes: dict[str, str] = {}
        docs: dict[str, Any] = {}
        for name in (CHECKS_FILE, CROSSWALK_FILE):
            raw = (directory / name).read_bytes()
            hashes[name] = hashlib.sha256(raw).hexdigest()
            docs[name] = yaml.safe_load(raw) or {}
        crosswalk = docs[CROSSWALK_FILE]
        mappings = cls(
            checks=docs[CHECKS_FILE].get("checks") or {},
            objectives=crosswalk.get("objectives") or {},
            frameworks=crosswalk.get("frameworks") or {},
            file_hashes=hashes,
        )
        mappings.validate()
        return mappings

    def validate(self) -> None:
        for check_id, check in self.checks.items():
            objectives = check.get("objectives") or []
            if not objectives:
                raise MappingError(f"{check_id} has no objectives")
            for objective in objectives:
                if objective not in self.objectives:
                    raise MappingError(f"{check_id} references unknown objective {objective}")
        for objective_id, objective in self.objectives.items():
            for framework, ids in (objective.get("controls") or {}).items():
                catalog = self.frameworks.get(framework)
                if catalog is None:
                    raise MappingError(f"{objective_id} references unknown framework {framework}")
                for control_id in ids:
                    if control_id not in catalog:
                        raise MappingError(
                            f"{objective_id} references {framework} {control_id}, "
                            "which has no entry in the frameworks catalog"
                        )

    def controls_for(self, check_id: str) -> dict[str, list[str]]:
        """Union of framework control IDs across the check's objectives, in file order."""
        if check_id not in self.checks:
            raise MappingError(f"No mapping for check {check_id}")
        result: dict[str, list[str]] = {framework: [] for framework in self.frameworks}
        for objective in self.checks[check_id]["objectives"]:
            for framework, ids in (self.objectives[objective].get("controls") or {}).items():
                result[framework].extend(i for i in ids if i not in result[framework])
        return result

    def objectives_for(self, check_id: str) -> list[str]:
        return list(self.checks[check_id]["objectives"])

    def control_catalog(self) -> list[tuple[str, str, str]]:
        """(framework, control_id, title) for every control in the catalog."""
        return [
            (framework, control_id, title)
            for framework, controls in self.frameworks.items()
            for control_id, title in controls.items()
        ]
