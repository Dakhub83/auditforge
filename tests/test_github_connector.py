from __future__ import annotations

import hashlib
from pathlib import Path

import pytest
import responses

from auditforge.connectors.github import API, GitHubAuthError, GitHubConnector, GitHubResponseError
from tests import change_mgmt_scenario as sc
from tests.conftest import FIXTURES

TOKEN = "github_pat_TESTTOKEN_do_not_leak"
CLASSIC_URL = f"{API}/repos/acme/payments-api/branches/main/protection"
RULES_URL = f"{API}/repos/acme/payments-api/rules/branches/main"


def fixture_bytes(name: str) -> bytes:
    return (FIXTURES / "github" / name).read_bytes()


def test_saves_raw_bytes_unmodified_with_hash(tmp_path: Path, mock_http: responses.RequestsMock) -> None:
    body = fixture_bytes("classic_strong.json")
    mock_http.get(CLASSIC_URL, body=body, status=200)
    mock_http.get(RULES_URL, body=fixture_bytes("rulesets_strong.json"), status=200)

    gh = GitHubConnector(TOKEN, tmp_path)
    classic, rules = gh.branch_protection("acme/payments-api", "main")

    saved = tmp_path / classic.evidence.file_path
    assert saved.read_bytes() == body
    assert classic.evidence.sha256 == hashlib.sha256(body).hexdigest()
    assert classic.evidence.file_path == "raw/classic_protection.json"
    assert classic.evidence.source_uri == f"GET {CLASSIC_URL}"
    assert classic.status == 200
    assert classic.body["enforce_admins"]["enabled"] is True
    assert isinstance(rules.body, list)
    assert [e.evidence_id for e in gh.evidence] == [classic.evidence.evidence_id, rules.evidence.evidence_id]


def test_sends_token_and_api_headers_and_only_gets(tmp_path: Path, mock_http: responses.RequestsMock) -> None:
    mock_http.get(CLASSIC_URL, json={}, status=200)
    mock_http.get(RULES_URL, json=[], status=200)
    GitHubConnector(TOKEN, tmp_path).branch_protection("acme/payments-api", "main")

    assert {c.request.method for c in mock_http.calls} == {"GET"}
    headers = mock_http.calls[0].request.headers
    assert headers["Authorization"] == f"Bearer {TOKEN}"
    assert headers["X-GitHub-Api-Version"] == "2022-11-28"


def test_branch_with_slash_is_encoded(tmp_path: Path, mock_http: responses.RequestsMock) -> None:
    mock_http.get(f"{API}/repos/acme/payments-api/branches/release%2F1.0/protection", json={}, status=200)
    mock_http.get(f"{API}/repos/acme/payments-api/rules/branches/release%2F1.0", json=[], status=200)
    classic, rules = GitHubConnector(TOKEN, tmp_path).branch_protection("acme/payments-api", "release/1.0")
    assert classic.status == 200 and rules.status == 200


def test_401_saves_evidence_then_raises(tmp_path: Path, mock_http: responses.RequestsMock) -> None:
    mock_http.get(CLASSIC_URL, body=fixture_bytes("bad_credentials_401.json"), status=401)
    gh = GitHubConnector(TOKEN, tmp_path)
    with pytest.raises(GitHubAuthError) as exc:
        gh.branch_protection("acme/payments-api", "main")
    assert TOKEN not in str(exc.value)
    assert gh.evidence[0].http_status == 401
    assert (tmp_path / "raw" / "classic_protection.json").exists()


def test_403_is_returned_not_raised(tmp_path: Path, mock_http: responses.RequestsMock) -> None:
    mock_http.get(CLASSIC_URL, body=fixture_bytes("forbidden_403.json"), status=403)
    mock_http.get(RULES_URL, json=[], status=200)
    classic, _ = GitHubConnector(TOKEN, tmp_path).branch_protection("acme/payments-api", "main")
    assert classic.status == 403


def test_non_json_body_parses_to_none(tmp_path: Path, mock_http: responses.RequestsMock) -> None:
    mock_http.get(CLASSIC_URL, body=b"<html>bad gateway</html>", status=502)
    mock_http.get(RULES_URL, json=[], status=200)
    classic, _ = GitHubConnector(TOKEN, tmp_path).branch_protection("acme/payments-api", "main")
    assert classic.body is None
    assert (tmp_path / "raw" / "classic_protection.json").read_bytes() == b"<html>bad gateway</html>"


def test_token_never_written_to_evidence(tmp_path: Path, mock_http: responses.RequestsMock) -> None:
    mock_http.get(CLASSIC_URL, json={}, status=200)
    mock_http.get(RULES_URL, json=[], status=200)
    gh = GitHubConnector(TOKEN, tmp_path)
    gh.branch_protection("acme/payments-api", "main")
    for f in tmp_path.rglob("*"):
        if f.is_file():
            assert TOKEN.encode() not in f.read_bytes()
    assert TOKEN not in repr(gh.evidence)


@pytest.mark.parametrize("repo", ["acme", "acme/x/y", "../etc", "acme/..", "acme/repo?x=1"])
def test_rejects_malformed_repo(tmp_path: Path, repo: str) -> None:
    with pytest.raises(ValueError):
        GitHubConnector(TOKEN, tmp_path).branch_protection(repo, "main")


# --- Pagination and change-management collection ------------------------------------

PULLS_URL = f"{API}/repos/acme/payments-api/pulls"


def test_get_pages_follows_next_links_and_saves_each_page(
    tmp_path: Path, mock_http: responses.RequestsMock
) -> None:
    page2 = f"{API}/repositories/1/commits?page=2"
    mock_http.get(
        f"{API}/repos/acme/payments-api/commits",
        json=[{"sha": "a"}],
        status=200,
        headers={"Link": f'<{page2}>; rel="next"'},
    )
    mock_http.get(page2, json=[{"sha": "b"}], status=200)
    gh = GitHubConnector(TOKEN, tmp_path)
    pages = gh.get_pages("/repos/acme/payments-api/commits", "commits")
    assert [p.body for p in pages] == [[{"sha": "a"}], [{"sha": "b"}]]
    assert [e.file_path for e in gh.evidence] == ["raw/commits_p1.json", "raw/commits_p2.json"]
    assert gh.evidence[1].source_uri == f"GET {page2}"


def test_get_pages_refuses_links_off_github(tmp_path: Path, mock_http: responses.RequestsMock) -> None:
    mock_http.get(
        f"{API}/repos/acme/payments-api/commits",
        json=[],
        status=200,
        headers={"Link": '<https://evil.example/steal?page=2>; rel="next"'},
    )
    with pytest.raises(GitHubResponseError):
        GitHubConnector(TOKEN, tmp_path).get_pages("/repos/acme/payments-api/commits", "commits")
    assert len(mock_http.calls) == 1


def test_closed_pulls_stops_once_past_the_period_start(
    tmp_path: Path, mock_http: responses.RequestsMock
) -> None:
    # Page 1 ends with a PR last updated before the period, so page 2 is never requested.
    mock_http.get(
        PULLS_URL,
        json=sc.PULLS_PAGE,
        status=200,
        headers={"Link": f'<{API}/repositories/1/pulls?page=2>; rel="next"'},
    )
    pages = GitHubConnector(TOKEN, tmp_path).closed_pulls("acme/payments-api", "main", "2026-01-01T00:00:00Z")
    assert len(pages) == 1
    query = mock_http.calls[0].request.url.split("?", 1)[1]
    assert "state=closed" in query and "base=main" in query and "sort=updated" in query


def test_closed_pulls_keeps_paging_while_prs_are_in_the_period(
    tmp_path: Path, mock_http: responses.RequestsMock
) -> None:
    page2 = f"{API}/repositories/1/pulls?page=2"
    mock_http.get(PULLS_URL, json=sc.PULLS_PAGE[:3], status=200, headers={"Link": f'<{page2}>; rel="next"'})
    mock_http.get(page2, json=sc.PULLS_PAGE[3:], status=200)
    pages = GitHubConnector(TOKEN, tmp_path).closed_pulls("acme/payments-api", "main", "2026-01-01T00:00:00Z")
    assert len(pages) == 2


def test_sha_from_a_response_is_validated_before_use(tmp_path: Path) -> None:
    with pytest.raises(GitHubResponseError):
        GitHubConnector(TOKEN, tmp_path).check_runs("acme/payments-api", "../../orgs/acme", "pr_1")
