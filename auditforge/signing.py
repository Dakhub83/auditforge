"""Ed25519 signing and verification of reports.

A report is signed over its canonical JSON (sorted keys, no whitespace) with
the "signature" block removed. Verification needs a *trusted* public key
supplied out of band: the key embedded in a report only says who claims to
have signed it, so anyone could edit a report and re-sign it with their own.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

PRIVATE_KEY_FILE = "signing_key.pem"
PUBLIC_KEY_FILE = "signing_key.pub.pem"


def load_or_create_key(key_dir: Path) -> tuple[Ed25519PrivateKey, bool]:
    """Return the signing key and whether it was just created."""
    key_dir.mkdir(parents=True, exist_ok=True)
    priv_path = key_dir / PRIVATE_KEY_FILE
    if priv_path.exists():
        key = serialization.load_pem_private_key(priv_path.read_bytes(), password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise ValueError(f"{priv_path} is not an Ed25519 private key")
        return key, False

    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    # 0o600 on POSIX. On Windows the mode is ignored and the file inherits the
    # folder's ACL, so keep AUDITFORGE_HOME in a folder only you can read.
    fd = os.open(priv_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(pem)
    (key_dir / PUBLIC_KEY_FILE).write_bytes(
        key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )
    return key, True


def load_public_key(path: Path) -> Ed25519PublicKey:
    key = serialization.load_pem_public_key(path.read_bytes())
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError(f"{path} is not an Ed25519 public key")
    return key


def _raw(pub: Ed25519PublicKey) -> bytes:
    return pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def fingerprint(pub: Ed25519PublicKey) -> str:
    return hashlib.sha256(_raw(pub)).hexdigest()[:16]


def canonical(obj: dict[str, Any]) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sign_report(report: dict[str, Any], key: Ed25519PrivateKey) -> dict[str, Any]:
    payload = canonical(report)
    pub = key.public_key()
    return {
        "algorithm": "Ed25519",
        "payload_sha256": hashlib.sha256(payload).hexdigest(),
        "public_key": base64.b64encode(_raw(pub)).decode(),
        "public_key_fingerprint": fingerprint(pub),
        "signature": base64.b64encode(key.sign(payload)).decode(),
    }


@dataclass(frozen=True)
class VerifyResult:
    ok: bool
    message: str


def verify_report(report_path: Path, trusted_key: Ed25519PublicKey) -> VerifyResult:
    """Check the signature against the trusted key, then re-hash every evidence file."""
    try:
        doc = json.loads(report_path.read_text(encoding="utf-8"))
        sig = doc.pop("signature")
        claimed = base64.b64decode(sig["public_key"])
        signature = base64.b64decode(sig["signature"])
    except (ValueError, KeyError, TypeError) as exc:
        return VerifyResult(False, f"INVALID: report is malformed ({exc}).")

    if claimed != _raw(trusted_key):
        claimed_fp = hashlib.sha256(claimed).hexdigest()[:16]
        trusted_fp = fingerprint(trusted_key)
        return VerifyResult(
            False, f"INVALID: report was signed by key {claimed_fp}, not the trusted key {trusted_fp}."
        )
    payload = canonical(doc)
    try:
        trusted_key.verify(signature, payload)
    except InvalidSignature:
        return VerifyResult(False, "INVALID: report was modified after signing.")

    run_dir = report_path.parent.resolve()
    bad: list[str] = []
    for e in doc.get("evidence", []):
        path = (run_dir / e["file_path"]).resolve()
        if not path.is_relative_to(run_dir) or not path.is_file():
            bad.append(f"{e['file_path']} (missing)")
        elif hashlib.sha256(path.read_bytes()).hexdigest() != e["sha256"]:
            bad.append(e["file_path"])
    if bad:
        return VerifyResult(False, f"INVALID: evidence files changed: {', '.join(bad)}")
    return VerifyResult(
        True,
        f"VALID: signature and {len(doc.get('evidence', []))} evidence hashes check out "
        f"(key fingerprint {fingerprint(trusted_key)}).",
    )
