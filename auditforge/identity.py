"""Who is running AuditForge, recorded on runs and on every risk register change."""

from __future__ import annotations

import getpass


def operator() -> str:
    try:
        return getpass.getuser()
    except Exception:  # no login name available (some CI containers)
        return "unknown"
