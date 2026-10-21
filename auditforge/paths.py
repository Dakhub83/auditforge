"""Filesystem locations. AUDITFORGE_HOME overrides the default ~/.auditforge."""

from __future__ import annotations

import os
from pathlib import Path

RAW_DIRNAME = "raw"


def auditforge_home() -> Path:
    return Path(os.environ.get("AUDITFORGE_HOME", Path.home() / ".auditforge"))


def key_dir() -> Path:
    return auditforge_home() / "keys"


def default_mappings_dir() -> Path:
    # mappings/ sits at the repository root, next to the package.
    return Path(__file__).resolve().parent.parent / "mappings"
