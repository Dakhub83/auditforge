from __future__ import annotations

from pathlib import Path

import pytest

from auditforge.mappings import MappingError, Mappings
from auditforge.paths import default_mappings_dir

# The prototype's inline CONTROL_MAP. Moving to YAML must not change any of it.
PROTOTYPE_MAP = {
    "GH-BP-01": {"SOC2": ["CC8.1"], "ISO27001:2022": ["A.8.32"], "NIST-800-53r5": ["CM-3"]},
    "GH-BP-02": {"SOC2": ["CC8.1"], "ISO27001:2022": ["A.8.32", "A.8.4"], "NIST-800-53r5": ["CM-3", "AC-5"]},
    "GH-BP-03": {"SOC2": ["CC8.1"], "ISO27001:2022": ["A.8.32"], "NIST-800-53r5": ["CM-3"]},
    "GH-BP-04": {"SOC2": ["CC8.1"], "ISO27001:2022": ["A.8.4", "A.8.28"], "NIST-800-53r5": ["SI-7"]},
    "GH-BP-05": {
        "SOC2": ["CC6.1", "CC8.1"],
        "ISO27001:2022": ["A.8.2", "A.8.32"],
        "NIST-800-53r5": ["AC-5", "CM-5"],
    },
}


@pytest.fixture
def mappings() -> Mappings:
    return Mappings.load(default_mappings_dir())


@pytest.mark.parametrize("check_id", sorted(PROTOTYPE_MAP))
def test_yaml_preserves_prototype_mapping(mappings: Mappings, check_id: str) -> None:
    controls = mappings.controls_for(check_id)
    for framework, expected in PROTOTYPE_MAP[check_id].items():
        assert sorted(controls[framework]) == sorted(expected)


def test_every_check_maps_to_sox_program_change(mappings: Mappings) -> None:
    for check_id in PROTOTYPE_MAP:
        assert "ITGC-PC" in mappings.controls_for(check_id)["SOX-ITGC"]


def test_file_hashes_recorded(mappings: Mappings) -> None:
    assert set(mappings.file_hashes) == {"checks.yaml", "crosswalk.yaml"}
    assert all(len(h) == 64 for h in mappings.file_hashes.values())


def test_unknown_check_raises(mappings: Mappings) -> None:
    with pytest.raises(MappingError):
        mappings.controls_for("NOPE-01")


def _write(directory: Path, checks: str, crosswalk: str) -> Path:
    (directory / "checks.yaml").write_text(checks, encoding="utf-8")
    (directory / "crosswalk.yaml").write_text(crosswalk, encoding="utf-8")
    return directory


def test_unknown_objective_rejected(tmp_path: Path) -> None:
    _write(tmp_path, "checks:\n  X-01:\n    objectives: [MISSING]\n", "objectives: {}\nframeworks: {}\n")
    with pytest.raises(MappingError, match="unknown objective MISSING"):
        Mappings.load(tmp_path)


def test_control_missing_from_catalog_rejected(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "checks:\n  X-01:\n    objectives: [OBJ]\n",
        "objectives:\n  OBJ:\n    controls:\n      SOC2: [CC9.9]\nframeworks:\n  SOC2: {}\n",
    )
    with pytest.raises(MappingError, match="CC9.9"):
        Mappings.load(tmp_path)
