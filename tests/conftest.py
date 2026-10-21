from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
import responses

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture(autouse=True)
def _isolate(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Keys and other state go to a temp dir, never the real ~/.auditforge.
    monkeypatch.setenv("AUDITFORGE_HOME", str(tmp_path / "home"))
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)


@pytest.fixture(autouse=True)
def mock_http():
    # Every test runs inside a RequestsMock, so any unmocked HTTP call fails
    # instead of reaching the real network.
    with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        yield rsps


def load_fixture(name: str) -> Any:
    return json.loads((FIXTURES / "github" / name).read_text(encoding="utf-8"))
