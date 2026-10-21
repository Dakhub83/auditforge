"""Local git connector: collects from a clone on disk. No network access.

Every command's stdout is saved byte-for-byte to <run_dir>/raw/ before anything
parses it, with the exact command, timestamp, exit code and SHA-256. Only
read-only commands are run (rev-parse, remote, log), and nothing is fetched:
the clone is analysed as it is, so fetch it yourself before a run.

The clone is the thing under audit, so its own configuration is untrusted. A
repo's .git/config can name programs git will execute (e.g. gpg.program, which
`log --format=%G?` runs to check signatures), so those settings are pinned on
the command line, and replace refs, which can make history display differently
from what is stored, are ignored.
"""

from __future__ import annotations

import hashlib
import os
import re
import shlex
import subprocess
import uuid
from pathlib import Path

from auditforge.connectors.github import utc_now
from auditforge.models import CommandOutput, Evidence
from auditforge.paths import RAW_DIRNAME

SHA_PATTERN = re.compile(r"^[0-9a-f]{40}$")
# A ref name as typed by the operator: no leading '-', no whitespace or shell/rev syntax beyond
# what branch names use. Checked before it reaches git (which also gets --end-of-options).
REF_PATTERN = re.compile(r"^(?!-)[A-Za-z0-9._/-]+$")

SAFE_CONFIG = (
    "-c", "core.fsmonitor=false",
    "-c", "core.pager=cat",
    "-c", "gpg.program=gpg",
    "-c", "gpg.openpgp.program=gpg",
    "-c", "gpg.x509.program=gpgsm",
    "-c", "gpg.ssh.program=ssh-keygen",
    "-c", "log.showSignature=false",
)  # fmt: skip

# One record per commit, fields separated by US (0x1f), records by RS (0x1e), so
# commit subjects and names can't break parsing.
LOG_FIELDS = (
    ("sha", "%H"),
    ("parents", "%P"),
    ("committed_at", "%cI"),
    ("author_name", "%an"),
    ("author_email", "%ae"),
    ("committer_name", "%cn"),
    ("committer_email", "%ce"),
    ("signature", "%G?"),  # G/U/X/Y good, B bad, N none, E can't check (e.g. key not in keyring), R revoked
    ("signing_key", "%GK"),
    ("signing_fingerprint", "%GF"),
    ("subject", "%s"),
)
LOG_FORMAT = "%x1f".join(code for _, code in LOG_FIELDS) + "%x1e"


class GitError(RuntimeError):
    """git could not be run, or the path is not a git repository."""


class GitConnector:
    def __init__(self, repo_path: Path, run_dir: Path, git: str = "git") -> None:
        self.repo_path = repo_path.resolve()
        self.git = git
        self.run_dir = run_dir
        self.raw_dir = run_dir / RAW_DIRNAME
        self.raw_dir.mkdir(parents=True, exist_ok=True)
        self.evidence: list[Evidence] = []

    def run(self, args: list[str], label: str) -> CommandOutput:
        cmd = [self.git, "--no-pager", "--no-replace-objects", *SAFE_CONFIG, "-C", str(self.repo_path), *args]
        env = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_OPTIONAL_LOCKS": "0"}
        try:
            proc = subprocess.run(cmd, capture_output=True, timeout=300, env=env, check=False)
        except FileNotFoundError:
            raise GitError(f"git was not found ({self.git!r}). Install git or put it on PATH.") from None
        raw_file = self.raw_dir / f"{label}.txt"
        raw_file.write_bytes(proc.stdout)
        evidence = Evidence(
            evidence_id=uuid.uuid4().hex,
            source_uri=f"git -C {self.repo_path} {shlex.join(args)}",
            http_status=None,
            collected_at=utc_now(),
            sha256=hashlib.sha256(proc.stdout).hexdigest(),
            file_path=raw_file.relative_to(self.run_dir).as_posix(),
            exit_code=proc.returncode,
        )
        self.evidence.append(evidence)
        error = proc.stderr.decode("utf-8", errors="replace").strip().splitlines()
        return CommandOutput(
            evidence, proc.stdout.decode("utf-8", errors="replace"), error[0] if error else ""
        )

    def is_shallow(self) -> CommandOutput:
        """'true' if history is truncated, in which case commits in the period may be missing."""
        return self.run(["rev-parse", "--is-shallow-repository"], "shallow")

    def resolve(self, ref: str) -> CommandOutput:
        """The commit a ref points to, e.g. origin/main as of the clone's last fetch."""
        if not REF_PATTERN.match(ref):
            raise ValueError(f"Not a valid ref name: {ref!r}")
        return self.run(["rev-parse", "--verify", "--end-of-options", f"{ref}^{{commit}}"], "ref")

    def remote_url(self) -> CommandOutput:
        """Where the clone came from, so the report ties the evidence to a repository."""
        return self.run(["remote", "get-url", "origin"], "remote")

    def first_parent_log(self, sha: str, since: str) -> CommandOutput:
        """Commits that landed on the branch itself (git log --first-parent) since `since`."""
        if not SHA_PATTERN.match(sha):
            raise GitError(f"Unexpected commit SHA from git: {sha!r}")
        args = [
            "log",
            "--first-parent",
            f"--since={since}",
            f"--format={LOG_FORMAT}",
            "--end-of-options",
            sha,
            "--",
        ]
        return self.run(args, "first_parent_log")
