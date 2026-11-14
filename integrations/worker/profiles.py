"""Immutable execution-profile identity; no network or activation side effects."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat


PROFILE_ID = "external-web-v1"
PROFILE_SHA256 = "1f2a19c959570157ee9df788141ae1e21b8f67aba8c6ce99b768efbd42eb7a37"
MANIFEST_PATH = Path(__file__).resolve().parents[1] / "profiles" / (PROFILE_ID + ".json")
MAX_MANIFEST_BYTES = 32 * 1024
_SERVICE_ORDER = {("http", 80): 0, ("https", 443): 1}


class ProfileError(ValueError):
    """A fixed, log-safe refusal category, never untrusted profile contents."""


def canonical_json(value) -> bytes:
    return (json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode("ascii")


def _pairs(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ProfileError("profile_duplicate_key")
        value[key] = item
    return value


def _read_manifest(path: Path) -> bytes:
    descriptor = -1
    try:
        if path.is_symlink():
            raise ProfileError("profile_file_invalid")
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or not 0 < before.st_size <= MAX_MANIFEST_BYTES:
            raise ProfileError("profile_file_invalid")
        raw = os.read(descriptor, MAX_MANIFEST_BYTES + 1)
        after = os.fstat(descriptor)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
            after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns
        ) or len(raw) != before.st_size:
            raise ProfileError("profile_file_changed")
        return raw
    except OSError as exc:
        raise ProfileError("profile_unavailable") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def profile_manifest(profile_id: str = PROFILE_ID, *, path: Path | None = None) -> dict:
    """Return a fresh copy of the one pinned manifest, never mutable configuration.

    The optional path supports installation layouts and offline tests. It does not
    permit another manifest: exact bytes must match this release's pinned digest.
    A changed behavior requires a new profile version and renewed acceptance.
    """
    if type(profile_id) is not str or profile_id != PROFILE_ID:
        raise ProfileError("profile_unknown")
    raw = _read_manifest(MANIFEST_PATH if path is None else Path(path))
    if hashlib.sha256(raw).hexdigest() != PROFILE_SHA256:
        raise ProfileError("profile_digest_mismatch")
    try:
        value = json.loads(raw.decode("ascii"), object_pairs_hook=_pairs,
                           parse_constant=lambda _value: (_ for _ in ()).throw(ProfileError("profile_nonfinite")))
        if canonical_json(value) != raw or type(value) is not dict or value.get("schema_version") != 1 or value.get("profile_id") != PROFILE_ID:
            raise ProfileError("profile_schema_invalid")
    except (UnicodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
        if isinstance(exc, ProfileError):
            raise
        raise ProfileError("profile_schema_invalid") from exc
    return value


def profile_digest(profile_id: str = PROFILE_ID) -> str:
    profile_manifest(profile_id)
    return PROFILE_SHA256


def validate_services(value) -> tuple[tuple[str, int], ...]:
    """Require the exact selected service list, without adding HTTPS or HTTP."""
    if type(value) is not list or not 1 <= len(value) <= 2:
        raise ProfileError("profile_services_invalid")
    result = []
    for service in value:
        if type(service) is not dict or set(service) != {"scheme", "port"}:
            raise ProfileError("profile_services_invalid")
        scheme, port = service["scheme"], service["port"]
        if type(scheme) is not str or type(port) is not int or (scheme, port) not in _SERVICE_ORDER:
            raise ProfileError("profile_services_invalid")
        result.append((scheme, port))
    if len(set(result)) != len(result) or result != sorted(result, key=_SERVICE_ORDER.__getitem__):
        raise ProfileError("profile_services_invalid")
    return tuple(result)


def validate_binding(profile_id, digest, services) -> tuple[tuple[str, int], ...]:
    """Validate a frozen claim/acceptance binding before any target connection."""
    if type(digest) is not str or digest != profile_digest(profile_id):
        raise ProfileError("profile_binding_mismatch")
    return validate_services(services)
