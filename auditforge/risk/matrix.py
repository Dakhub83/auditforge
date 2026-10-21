"""5x5 risk matrix: score = likelihood x impact, rated by the bands in mappings/risk_matrix.yaml.

The formula lives here and in the database (generated columns), so a stored score can never
drift from its likelihood and impact. Everything a risk committee might tune (level wording,
band thresholds, appetite, categories) is data in the YAML file, whose hash is recorded.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

MATRIX_FILE = "risk_matrix.yaml"
LEVELS = (1, 2, 3, 4, 5)


class MatrixError(ValueError):
    pass


@dataclass(frozen=True)
class Band:
    name: str
    min: int


@dataclass(frozen=True)
class RiskMatrix:
    likelihood: dict[int, dict[str, str]]  # level -> {label, description}
    impact: dict[int, dict[str, str]]
    bands: tuple[Band, ...]
    appetite: int
    categories: tuple[str, ...]
    file_hash: str

    @classmethod
    def load(cls, mappings_dir: Path) -> RiskMatrix:
        raw = (mappings_dir / MATRIX_FILE).read_bytes()
        doc: dict[str, Any] = yaml.safe_load(raw) or {}
        matrix = cls(
            likelihood={int(k): v for k, v in (doc.get("likelihood") or {}).items()},
            impact={int(k): v for k, v in (doc.get("impact") or {}).items()},
            bands=tuple(Band(b["name"], int(b["min"])) for b in doc.get("bands") or []),
            appetite=int(doc.get("appetite", 0)),
            categories=tuple(doc.get("categories") or []),
            file_hash=hashlib.sha256(raw).hexdigest(),
        )
        matrix.validate()
        return matrix

    def validate(self) -> None:
        for axis, scale in (("likelihood", self.likelihood), ("impact", self.impact)):
            if tuple(sorted(scale)) != LEVELS:
                raise MatrixError(f"{MATRIX_FILE}: {axis} must define exactly levels 1-5")
        mins = [b.min for b in self.bands]
        if not mins or mins[0] != 1 or mins != sorted(set(mins)) or mins[-1] > 25:
            raise MatrixError(f"{MATRIX_FILE}: bands must ascend from min 1 with distinct mins up to 25")
        if not 1 <= self.appetite <= 25:
            raise MatrixError(f"{MATRIX_FILE}: appetite must be between 1 and 25")
        if not self.categories:
            raise MatrixError(f"{MATRIX_FILE}: at least one category is required")

    @staticmethod
    def score(likelihood: int, impact: int) -> int:
        for name, value in (("likelihood", likelihood), ("impact", impact)):
            if value not in LEVELS:
                raise MatrixError(f"{name} must be 1-5, got {value!r}")
        return likelihood * impact

    def band(self, score: int) -> str:
        if not 1 <= score <= 25:
            raise MatrixError(f"score must be 1-25, got {score!r}")
        return [b.name for b in self.bands if score >= b.min][-1]

    def above_appetite(self, score: int) -> bool:
        return score > self.appetite

    def describe(self, likelihood: int, impact: int) -> str:
        """e.g. '4 Likely x 5 Severe = 20 Critical'."""
        s = self.score(likelihood, impact)
        return (
            f"{likelihood} {self.likelihood[likelihood]['label']} x "
            f"{impact} {self.impact[impact]['label']} = {s} {self.band(s)}"
        )
