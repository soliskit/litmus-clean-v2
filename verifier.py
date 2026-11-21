#!/usr/bin/env python3
"""Evidence bundle verifier (owner-side qualification tooling).

The verifier is the only component that emits a verdict. A verdict exists
only after complete validation of the exact bundle it names. It binds the
manifest-DECLARED bundle name, the bundle's absolute path and the
bundle's manifest sha256, so a verdict for an absent, moved, renamed or
changed bundle is invalid on its face (source binding, stale-verdict
avoidance). The name binding is to the name declared inside the manifest;
the path binding is to the directory the verdict was issued for.

--check-verdict re-validates an existing verdict file against the current
bytes of the bundle it claims to cover: the verdict is accepted only when
the bundle still validates AND every bound field matches. Anything else is
a stale or foreign verdict and is rejected. The path/name binding detects
a moved, renamed or swapped bundle against a stored verdict; it is not a
signature and proves nothing about who produced the verdict.

Only the exact published directory validates: a path that is a symlink,
or a directory whose name is not the valid bundle name its manifest
declares, is INVALID. So unpublished staging, a copy under another name
and a renamed bundle never validate.

Fail-closed: absent path, missing/incomplete manifest, a manifest that is
not a regular file, hash or size mismatch, unexpected extra files or
empty directories, symlinks, unreadable directories or files in the
bundle, and unknown or malformed manifest framing all produce INVALID.
Never emits VALID for a bundle it could not fully read.

Python 3 standard library only.
"""

import hashlib
import json
import os
import re
import stat
import sys
import uuid
from datetime import datetime, timezone
from typing import TypedDict

MANIFEST_VERSION = 1
MANIFEST_FIELDS = {"version", "bundle", "created", "files"}
FILE_FIELDS = {"sha256", "size"}
# The packager's bundle name rule. A leading letter or digit also keeps
# out ".", ".." and the ".staging-" prefix.
NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")
SHA256_RE = re.compile(r"[0-9a-f]{64}")
VERDICT_FIELDS = {
    "verdict",
    "bundle",
    "bundle_path",
    "manifest_sha256",
    "run_id",
    "checked_at",
    "reasons",
}


class Verdict(TypedDict):
    verdict: str
    bundle: str | None
    bundle_path: str
    manifest_sha256: str | None
    run_id: str
    checked_at: str
    reasons: list[str]


def verify(bundle_path: str) -> Verdict:
    reasons: list[str] = []
    manifest_sha256: str | None = None
    bundle_name: str | None = None
    # Check and read the same path the verdict names. The kernel resolves a
    # '..' after a symlink differently from abspath, so the raw path could
    # name another directory than the one bound and checked below.
    bundle_path = os.path.abspath(bundle_path)

    if not os.path.isdir(bundle_path):
        reasons.append("bundle path absent or not a directory")
        return _verdict("INVALID", bundle_name, bundle_path, manifest_sha256, reasons)

    if os.path.islink(os.path.abspath(bundle_path)):
        reasons.append("bundle path is a symlink, not the published directory")
        return _verdict("INVALID", bundle_name, bundle_path, manifest_sha256, reasons)

    manifest_path = os.path.join(bundle_path, "manifest.json")
    try:
        manifest_mode = os.lstat(manifest_path).st_mode
    except FileNotFoundError:
        reasons.append("manifest.json missing")
        return _verdict("INVALID", bundle_name, bundle_path, manifest_sha256, reasons)
    except OSError as e:
        reasons.append(f"manifest.json could not be inspected: {e.strerror}")
        return _verdict("INVALID", bundle_name, bundle_path, manifest_sha256, reasons)
    if not stat.S_ISREG(manifest_mode):
        reasons.append("manifest.json is not a regular file")
        return _verdict("INVALID", bundle_name, bundle_path, manifest_sha256, reasons)

    try:
        with open(manifest_path, "rb") as f:
            manifest_bytes = f.read()
        manifest = json.loads(manifest_bytes.decode("utf-8"))
    except Exception as e:
        reasons.append(f"manifest unreadable: {e}")
        return _verdict("INVALID", bundle_name, bundle_path, manifest_sha256, reasons)

    manifest_sha256 = hashlib.sha256(manifest_bytes).hexdigest()

    if not isinstance(manifest, dict):
        reasons.append("manifest is not an object")
        return _verdict("INVALID", bundle_name, bundle_path, manifest_sha256, reasons)
    unknown = set(manifest) - MANIFEST_FIELDS
    if unknown:
        reasons.append(f"unknown manifest framing fields: {sorted(unknown)}")
    missing = MANIFEST_FIELDS - set(manifest)
    if missing:
        reasons.append(f"manifest missing fields: {sorted(missing)}")
    version = manifest.get("version")
    if type(version) is not int or version != MANIFEST_VERSION:
        reasons.append(f"unsupported manifest version: {version!r}")
    declared = manifest.get("bundle")
    if isinstance(declared, str):
        bundle_name = declared
    directory_name = os.path.basename(os.path.abspath(bundle_path))
    if not isinstance(declared, str) or not NAME_RE.fullmatch(declared):
        reasons.append(f"manifest bundle is not a valid bundle name: {declared!r}")
    elif declared != directory_name:
        reasons.append(
            f"bundle directory {directory_name!r} is not the declared bundle "
            f"name {declared!r}; only the published path validates"
        )
    if not _is_timestamp(manifest.get("created")):
        reasons.append(
            "manifest created is not a timezone-aware ISO timestamp: {!r}".format(
                manifest.get("created")
            )
        )
    files = manifest.get("files")
    if not isinstance(files, dict) or not files:
        reasons.append("manifest files map missing or empty")
        return _verdict("INVALID", bundle_name, bundle_path, manifest_sha256, reasons)
    for rel in sorted(files):
        entry = files[rel]
        if (
            not isinstance(entry, dict)
            or set(entry) != FILE_FIELDS
            or not isinstance(entry["sha256"], str)
            or not SHA256_RE.fullmatch(entry["sha256"])
            or type(entry["size"]) is not int
            or entry["size"] < 0
        ):
            reasons.append(f"malformed manifest entry: {rel}")
    if reasons:
        return _verdict("INVALID", bundle_name, bundle_path, manifest_sha256, reasons)

    listed = set(files)
    on_disk = set()
    unreadable: list[OSError] = []
    for root, dirs, fns in os.walk(bundle_path, onerror=unreadable.append):
        dirs.sort()
        if root != bundle_path and not dirs and not fns:
            # A directory holding no listed file is unaccounted for.
            rel = os.path.relpath(root, bundle_path)
            reasons.append(f"unexpected empty directory in bundle: {rel}")
        for dn in dirs:
            if os.path.islink(os.path.join(root, dn)):
                rel = os.path.relpath(os.path.join(root, dn), bundle_path)
                reasons.append(f"unexpected symlink in bundle: {rel}")
        for fn in sorted(fns):
            rel = os.path.relpath(os.path.join(root, fn), bundle_path)
            if rel == "manifest.json":
                continue
            on_disk.add(rel)

    for error in unreadable:
        rel = os.path.relpath(str(error.filename), bundle_path)
        reasons.append(f"bundle directory unreadable: {rel}: {error.strerror}")
    if unreadable:
        return _verdict("INVALID", bundle_name, bundle_path, manifest_sha256, reasons)

    for rel in sorted(listed - on_disk):
        reasons.append(f"listed file absent: {rel}")
    for rel in sorted(on_disk - listed):
        reasons.append(f"unexpected file not in manifest: {rel}")

    for rel in sorted(listed & on_disk):
        ap = os.path.join(bundle_path, rel)
        entry = files[rel]
        if os.path.islink(ap) or not os.path.isfile(ap):
            reasons.append(f"listed file not regular: {rel}")
            continue
        h = hashlib.sha256()
        size = 0
        try:
            with open(ap, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    h.update(chunk)
                    size += len(chunk)
        except OSError as e:
            reasons.append(f"listed file unreadable: {rel}: {e.strerror}")
            continue
        if entry["sha256"] != h.hexdigest():
            reasons.append(f"hash mismatch: {rel}")
        elif entry["size"] != size:
            reasons.append(f"size mismatch: {rel}")

    return _verdict(
        "VALID" if not reasons else "INVALID",
        bundle_name,
        bundle_path,
        manifest_sha256,
        reasons,
    )


def _is_timestamp(value: object) -> bool:
    if not isinstance(value, str):
        return False
    try:
        return datetime.fromisoformat(value).tzinfo is not None
    except ValueError:
        return False


def _verdict(
    status: str,
    bundle_name: str | None,
    bundle_path: str,
    manifest_sha256: str | None,
    reasons: list[str],
) -> Verdict:
    return {
        "verdict": status,
        "bundle": bundle_name,
        "bundle_path": os.path.abspath(bundle_path),
        "manifest_sha256": manifest_sha256,
        "run_id": str(uuid.uuid4()),
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "reasons": reasons,
    }


def check_verdict(bundle_path: str, verdict_path: str) -> tuple[bool, list[str]]:
    """Re-validate an existing verdict file against the bundle's current
    bytes. Returns (accepted, reasons)."""
    reasons = []
    try:
        with open(verdict_path, "rb") as f:
            old = json.loads(f.read().decode("utf-8"))
    except Exception as e:
        return False, [f"verdict file unreadable: {e}"]
    if not isinstance(old, dict):
        return False, ["verdict file is not an object"]
    unknown = set(old) - VERDICT_FIELDS
    if unknown:
        reasons.append(f"unknown verdict fields: {sorted(unknown)}")
    if old.get("verdict") != "VALID":
        reasons.append("verdict is not VALID")
    current = verify(bundle_path)
    if current["verdict"] != "VALID":
        reasons.append(
            "bundle no longer validates: {}".format("; ".join(current["reasons"]))
        )
    for field in ("bundle", "bundle_path", "manifest_sha256"):
        if old.get(field) != current.get(field):
            reasons.append(
                f"{field} mismatch: verdict names {old.get(field)!r}, bundle has {current.get(field)!r}"
            )
    return (not reasons), reasons


def main(argv: list[str]) -> int:
    if len(argv) == 4 and argv[1] == "--check-verdict":
        accepted, reasons = check_verdict(argv[2], argv[3])
        print(
            json.dumps(
                {"verdict_accepted": accepted, "reasons": reasons},
                indent=2,
                sort_keys=True,
            )
        )
        return 0 if accepted else 1
    if len(argv) != 2:
        print(
            "usage: verifier.py BUNDLE_PATH\n"
            "       verifier.py --check-verdict BUNDLE_PATH VERDICT_PATH",
            file=sys.stderr,
        )
        return 2
    result = verify(argv[1])
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["verdict"] == "VALID" else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
