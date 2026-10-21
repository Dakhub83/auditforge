"""A small repo history for change-management tests, shaped like real GitHub API responses.

Audit period 2026-01-01 .. 2026-03-31 on acme/payments-api@main.

PRs (newest update first, as GET /pulls?sort=updated&direction=desc returns them):
  #104 closed unmerged                         -> not in population
  #103 carol, no reviews, no CI                -> GH-CM-01 exception, GH-CM-02 review
  #102 alice, approved on an earlier commit,   -> GH-CM-01 review,    GH-CM-02 exception
       one failing check
  #101 alice, approved by bob on head, CI ok   -> ok, ok
  #99  merged 2025-12-20 (updated in Jan)      -> before the period
  #98  last updated 2025-12-01                 -> ends paging

First-parent history of main (newest first):
  M103 (merge of #103) -> D1 (direct push) -> M102 -> R1 (rebased commit of #100) -> M101 -> BASE
  M101's second parent F1 is a feature-branch commit and is not on the first-parent chain.
"""

from __future__ import annotations

import zlib
from typing import Any

REPO = "acme/payments-api"


def sha(tag: str) -> str:
    """A stable 40-hex SHA per tag, like GitHub's."""
    return tag.encode().hex().ljust(40, "0")[:40]


H101, H102, H102_OLD, H103 = sha("h101"), sha("h102"), sha("h102old"), sha("h103")
M101, M102, M103, D1, R1, F1, BASE = (sha(t) for t in ("m101", "m102", "m103", "d1", "r1", "f1", "base"))


def user(login: str, kind: str = "User") -> dict[str, Any]:
    return {"login": login, "id": zlib.crc32(login.encode()), "type": kind}


def pull(
    number: int, author: str, merged_at: str | None, updated_at: str, head: str, merge: str | None
) -> dict:
    return {
        "number": number,
        "state": "closed",
        "title": f"Change {number}",
        "user": user(author),
        "created_at": "2025-11-01T09:00:00Z",
        "updated_at": updated_at,
        "closed_at": merged_at or updated_at,
        "merged_at": merged_at,
        "merge_commit_sha": merge,
        "head": {"ref": f"feature-{number}", "sha": head},
        "base": {"ref": "main", "sha": BASE},
    }


PULLS_PAGE = [
    pull(104, "dave", None, "2026-03-20T10:00:00Z", sha("h104"), sha("m104")),
    pull(103, "carol", "2026-03-01T12:00:00Z", "2026-03-01T12:00:00Z", H103, M103),
    pull(102, "alice", "2026-02-10T12:00:00Z", "2026-02-11T08:00:00Z", H102, M102),
    pull(101, "alice", "2026-02-01T12:00:00Z", "2026-02-01T12:00:00Z", H101, M101),
    pull(99, "bob", "2025-12-20T12:00:00Z", "2026-01-02T09:00:00Z", sha("h99"), sha("m99")),
    pull(98, "bob", "2025-11-30T12:00:00Z", "2025-12-01T09:00:00Z", sha("h98"), sha("m98")),
]


def review(login: str, state: str, commit: str, at: str, kind: str = "User") -> dict[str, Any]:
    return {
        "id": zlib.crc32(f"{login}{at}".encode()),
        "user": user(login, kind),
        "state": state,
        "commit_id": commit,
        "submitted_at": at,
    }


REVIEWS = {
    101: [review("bob", "APPROVED", H101, "2026-02-01T11:00:00Z")],
    102: [review("bob", "APPROVED", H102_OLD, "2026-02-09T11:00:00Z")],
    103: [],
}


def check_run(name: str, conclusion: str | None, status: str = "completed") -> dict[str, Any]:
    return {"id": zlib.crc32(name.encode()), "name": name, "status": status, "conclusion": conclusion}


CHECK_RUNS = {
    101: {"total_count": 2, "check_runs": [check_run("test", "success"), check_run("lint", "skipped")]},
    102: {"total_count": 2, "check_runs": [check_run("test", "failure"), check_run("lint", "success")]},
    103: {"total_count": 0, "check_runs": []},
}


def combined_status(state: str, statuses: list[dict[str, Any]]) -> dict[str, Any]:
    return {"state": state, "statuses": statuses, "total_count": len(statuses)}


STATUSES = {n: combined_status("pending", []) for n in (101, 102, 103)}  # no legacy statuses


def commit(sha_: str, date: str, parents: list[str], message: str, login: str = "web-flow") -> dict[str, Any]:
    return {
        "sha": sha_,
        "commit": {
            "author": {"name": "Someone", "date": date},
            "committer": {"name": "GitHub", "date": date},
            "message": message,
        },
        "author": user("alice"),
        "committer": user(login),
        "parents": [{"sha": p} for p in parents],
    }


COMMITS_PAGE = [
    commit(M103, "2026-03-01T12:00:00Z", [D1, H103], "Merge pull request #103"),
    commit(D1, "2026-02-20T18:00:00Z", [M102], "hotfix straight to main", login="alice"),
    commit(M102, "2026-02-10T12:00:00Z", [R1, H102], "Merge pull request #102"),
    commit(R1, "2026-02-05T12:00:00Z", [M101], "Rebased change from #100"),
    commit(M101, "2026-02-01T12:00:00Z", [BASE, F1], "Merge pull request #101"),
    commit(F1, "2026-01-30T12:00:00Z", [BASE], "feature work for #101", login="alice"),
]

BRANCH = {"name": "main", "commit": {"sha": M103}, "protected": True}

COMMIT_PULLS = {
    R1: [{"number": 100, "merged_at": "2026-02-05T12:00:00Z", "base": {"ref": "main"}}],
    D1: [],
}
