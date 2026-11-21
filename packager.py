#!/usr/bin/env python3
"""Evidence bundle packager (owner-side qualification tooling).

Produces an evidence bundle: a directory of evidence files plus
manifest.json. The producer emits evidence + a manifest only. It never
emits a verdict.

Interrupt honesty:
- Staging is never guaranteed removed on interruption (SIGKILL/power loss
  can strand it). The guarantee is inverted: the consumer only ever trusts
  the exact published path with a complete manifest, so unpublished staging
  can never masquerade as complete.
- Publish is a single atomic no-overwrite rename (renameat2
  RENAME_NOREPLACE on linux/x86_64; any other platform or kernel fails
  closed and refuses to publish). Before the rename there is no partial
  bundle at the published path. After it the bundle IS complete and
  valid; a kill after publish may leave a complete bundle. That is
  stated, not hidden.
- The contract is atomic VISIBILITY of a complete bundle. fsync is
  ATTEMPTED on every file, every staging directory and the output
  parent, and a pre-publish fsync error ABORTS the pack with nothing
  published. A post-publish parent-dir fsync error is reported as a
  warning only, because publication has already completed. Durability
  across power loss is UNTESTED and NOT claimed. Kill testing used real
  SIGKILLs at defined pause points between write steps; a kill mid-write
  of a single file and actual power loss are UNTESTED.
- Normal prepublication errors attempt to remove only this pack's own
  staging. Interruptions and failed cleanup can leave residue; explicit
  --recover-sweep remains best-effort recovery, not a correctness condition.

Qualification driver hook: if C1C2_PAUSE_AT is set, the packager pauses
INDEFINITELY at the named point until a resume file appears or the
process is killed. Never set it in normal use.

No root, no mounts, no environment mechanics. Python 3 standard library
only (ctypes is used solely to ask the kernel for no-overwrite rename).
"""

import ctypes
import fcntl
import hashlib
import json
import os
import platform
import re
import secrets
import stat
import sys
import time
from datetime import datetime, timezone

MANIFEST_VERSION = 1
MANIFEST_FIELDS = {"version", "bundle", "created", "files"}
# \Z, not $: $ also matches before a trailing newline.
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*\Z")
STAGING_PREFIX = ".staging-"
RESERVED_NAME = "manifest.json"

# Qualification-driver synchronization (never set in normal use): pause at
# a named point so the driver can inject a real SIGKILL or a real OS write
# error. Points: after_staging_created, mid_copy, after_manifest,
# after_publish.
PAUSE_AT = os.environ.get("C1C2_PAUSE_AT", "")

_SYS_RENAMEAT2 = 316  # x86_64 Linux
_AT_FDCWD = -100
_RENAME_NOREPLACE = 1


def _pause(point: str, out_parent: str, name: str) -> None:
    if PAUSE_AT != point:
        return
    ready = os.path.join(out_parent, f".sync-{name}-{point}.ready")
    resume = os.path.join(out_parent, f".sync-{name}.resume")
    with open(ready, "w") as f:
        f.write(point + "\n")
    while not os.path.exists(resume):
        time.sleep(0.05)


def _fsync_dir(path: str) -> None:
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _write_sync(path: str, data: bytes) -> None:
    with open(path, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())


def _rename_noreplace(src: str, dst: str) -> None:
    """Atomic rename that refuses to replace an existing dst.

    Fail-closed: implemented only for linux/x86_64 via renameat2
    RENAME_NOREPLACE. Any other platform, architecture, or a kernel
    without renameat2 raises instead of falling back to a check-then-
    rename that would silently break the no-overwrite contract."""
    if (
        sys.platform != "linux"
        or platform.machine() != "x86_64"
        or ctypes.sizeof(ctypes.c_void_p) != 8
    ):
        raise RuntimeError(
            "atomic no-overwrite publish requires linux/x86-64 with a "
            f"64-bit process; refusing to publish on {sys.platform}/"
            f"{platform.machine()} (pointer size "
            f"{ctypes.sizeof(ctypes.c_void_p) * 8})"
        )
    libc = ctypes.CDLL(None, use_errno=True)
    ret = libc.syscall(
        _SYS_RENAMEAT2,
        _AT_FDCWD,
        os.fsencode(src),
        _AT_FDCWD,
        os.fsencode(dst),
        _RENAME_NOREPLACE,
    )
    if ret == 0:
        return
    err = ctypes.get_errno()
    raise OSError(err, os.strerror(err), dst)


RESERVATION_PREFIX = ".reserve-"
_NAMESPACE_ATTEMPTS = 16


def _rename_noreplace_at(src_dirfd: int, src: str, dst_dirfd: int, dst: str) -> None:
    # Extend the current helper's exact platform guard/syscall semantics.
    if (
        sys.platform != "linux"
        or platform.machine() != "x86_64"
        or ctypes.sizeof(ctypes.c_void_p) != 8
    ):
        raise RuntimeError(
            "atomic no-overwrite rename requires linux/x86-64 with a 64-bit process"
        )
    libc = ctypes.CDLL(None, use_errno=True)
    ret = libc.syscall(
        _SYS_RENAMEAT2,
        src_dirfd,
        os.fsencode(src),
        dst_dirfd,
        os.fsencode(dst),
        _RENAME_NOREPLACE,
    )
    if ret != 0:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err), dst)


def _locked_staging(stage_root: str, bundle_name: str) -> tuple[str, int]:
    # Caller has validated bundle_name with the existing producer policy.
    # Return staging path and owned lock fd. Caller must close fd in finally.
    # No failure path deletes reservation or staging residue.
    parent_fd = os.open(stage_root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    parent: int | None = parent_fd
    child: int | None = None
    try:
        for _ in range(_NAMESPACE_ATTEMPTS):
            reservation = RESERVATION_PREFIX + bundle_name + "-" + secrets.token_hex(16)
            try:
                os.mkdir(reservation, 0o700, dir_fd=parent)
                break
            except FileExistsError:
                continue
        else:
            raise RuntimeError("reservation namespace collision limit")
        opened = os.open(
            reservation,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=parent,
        )
        child = opened
        fcntl.flock(opened, fcntl.LOCK_EX | fcntl.LOCK_NB)

        def same_identity(name: str) -> None:
            held = os.fstat(opened)
            named = os.stat(name, dir_fd=parent, follow_symlinks=False)
            if (
                not stat.S_ISDIR(held.st_mode)
                or not stat.S_ISDIR(named.st_mode)
                or (held.st_dev, held.st_ino) != (named.st_dev, named.st_ino)
            ):
                raise RuntimeError("reservation/staging identity mismatch")

        same_identity(reservation)
        for _ in range(_NAMESPACE_ATTEMPTS):
            staging_name = STAGING_PREFIX + bundle_name + "-" + secrets.token_hex(16)
            try:
                _rename_noreplace_at(parent_fd, reservation, parent_fd, staging_name)
                break
            except FileExistsError:
                continue
        else:
            raise RuntimeError("staging namespace collision limit")
        same_identity(staging_name)
        result = (os.path.join(stage_root, staging_name), opened)
        os.close(parent_fd)
        parent = None
        child = None  # Ownership transfers only after all checks and parent close.
        return result
    finally:
        try:
            if child is not None:
                os.close(child)
        finally:
            if parent is not None:
                os.close(parent)


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def valid_bundle_name(name: str) -> bool:
    if name in (".", "..", "") or not NAME_RE.match(name):
        return False
    if os.sep in name or (os.altsep and os.altsep in name):
        return False
    if name.startswith(STAGING_PREFIX):
        return False
    return True


def collect_evidence(evidence_dir: str) -> dict[str, tuple[str, int, int]]:
    """Return {relpath: (abspath, dev, ino)} for regular files only; refuse
    the rest, including any input named manifest.json (reserved for the
    bundle's own manifest). A symlinked directory, a directory that cannot
    be read and an empty directory, which the manifest cannot carry, are
    refused too, so nothing under evidence_dir is skipped silently. The
    device and inode are the entry's identity at collection: the copy
    rechecks them, because a path kept as a bare string can be made to
    name a different file after collection."""
    entries: dict[str, tuple[str, int, int]] = {}

    def refuse_unreadable(error: OSError) -> None:
        rel = os.path.relpath(str(error.filename), evidence_dir)
        raise ValueError(f"evidence directory unreadable: {rel}: {error.strerror}")

    for root, dirs, files in os.walk(evidence_dir, onerror=refuse_unreadable):
        dirs.sort()
        if root != evidence_dir and not dirs and not files:
            rel = os.path.relpath(root, evidence_dir)
            raise ValueError(f"empty evidence directory refused: {rel}")
        for dn in dirs:
            if os.path.islink(os.path.join(root, dn)):
                rel = os.path.relpath(os.path.join(root, dn), evidence_dir)
                raise ValueError(f"symlinked evidence directory refused: {rel}")
        for fn in sorted(files):
            ap = os.path.join(root, fn)
            rel = os.path.relpath(ap, evidence_dir)
            if os.path.islink(ap) or not os.path.isfile(ap):
                raise ValueError(f"non-regular evidence file refused: {rel}")
            if rel == RESERVED_NAME:
                raise ValueError(f"evidence file collides with reserved name: {rel}")
            st = os.stat(ap)
            entries[rel] = (ap, st.st_dev, st.st_ino)
    if not entries:
        raise ValueError("evidence directory is empty")
    return entries


def _cleanup_diagnostic(label: str, error: Exception) -> None:
    # A secondary reporting failure must not replace the pack's original error.
    try:
        print(
            f"warning: {label} ({error}); files may remain; use explicit recovery",
            file=sys.stderr,
        )
    except Exception:
        pass


def _remove_own_staging(staging: str, staging_lock: int) -> None:
    """Remove only the held, unpublished stage, under the cooperative protocol.

    The path check does not defend against hostile replacement after inspection.
    No permissions are changed and no other names are scanned.
    """
    import shutil

    held = os.fstat(staging_lock)
    named = os.stat(staging, follow_symlinks=False)
    if (
        not stat.S_ISDIR(held.st_mode)
        or not stat.S_ISDIR(named.st_mode)
        or (held.st_dev, held.st_ino) != (named.st_dev, named.st_ino)
    ):
        raise RuntimeError("own staging identity changed; cleanup refused")
    shutil.rmtree(staging)


def pack(
    evidence_dir: str,
    out_parent: str,
    bundle_name: str,
    staging_parent: str | None = None,
) -> dict[str, object]:
    """Stage, manifest, fsync, then publish by one atomic no-overwrite
    rename. Returns the evidence dict the producer may report (no verdict
    field). Raises on any failure before publish; nothing is published
    then."""
    # Publish into the same normalized path the result reports. The kernel
    # resolves a '..' after a symlink differently from abspath.
    out_parent = os.path.abspath(out_parent)
    if not os.path.isdir(evidence_dir):
        raise ValueError(f"evidence directory not found: {evidence_dir}")
    if not os.path.isdir(out_parent):
        raise ValueError(f"output parent not found: {out_parent}")
    if not valid_bundle_name(bundle_name):
        raise ValueError(f"invalid bundle name: {bundle_name!r}")
    published = os.path.join(out_parent, bundle_name)
    if os.path.exists(published):
        raise ValueError(f"published path already exists: {published}")

    entries = collect_evidence(evidence_dir)
    stage_root = staging_parent if staging_parent is not None else out_parent
    staging, staging_lock = _locked_staging(stage_root, bundle_name)
    # A staging name exists only after its lock is held. Reservations
    # are not swept. Earlier producers retain their creation-to-lock gap.
    published_ok = False
    try:
        _pause("after_staging_created", out_parent, bundle_name)
        # Same-filesystem guarantee, asserted with real device numbers before
        # any write and again before the rename.
        if os.stat(staging).st_dev != os.stat(out_parent).st_dev:
            raise ValueError("cross-filesystem staging rejected")

        manifest_files: dict[str, dict[str, object]] = {}
        copied = 0
        for rel, (src, dev, ino) in entries.items():
            dst = os.path.join(staging, rel)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            # Collection is not a snapshot: an entry edited in place is
            # still read as it is, but an entry replaced since collection
            # (swapped for a symlink, renamed into place) is a different
            # file, so refuse instead of packing content never collected.
            try:
                fd = os.open(src, os.O_RDONLY | os.O_NOFOLLOW)
            except OSError as e:
                raise ValueError(f"evidence changed after collection: {rel}") from e
            with os.fdopen(fd, "rb") as f:
                now = os.fstat(f.fileno())
                if (now.st_dev, now.st_ino) != (dev, ino):
                    raise ValueError(f"evidence changed after collection: {rel}")
                data = f.read()
            _write_sync(dst, data)
            copied += 1
            if copied == max(1, len(entries) // 2):
                _pause("mid_copy", out_parent, bundle_name)
            manifest_files[rel] = {
                "sha256": hashlib.sha256(data).hexdigest(),
                "size": len(data),
            }
        manifest = {
            "version": MANIFEST_VERSION,
            "bundle": bundle_name,
            "created": datetime.now(timezone.utc).isoformat(),
            "files": manifest_files,
        }
        manifest_bytes = json.dumps(manifest, indent=2, sort_keys=True).encode()
        manifest_bytes += b"\n"
        _write_sync(os.path.join(staging, RESERVED_NAME), manifest_bytes)
        for root, _dirs, _files in os.walk(staging):
            _fsync_dir(root)  # aborts the pack on error; nested dirs included
        _pause("after_manifest", out_parent, bundle_name)

        if os.stat(staging).st_dev != os.stat(out_parent).st_dev:
            raise ValueError("cross-filesystem staging rejected")
        _rename_noreplace(staging, published)
        published_ok = True
    except Exception:
        # Interrupts (BaseException) retain their existing exit behavior.
        if not published_ok:
            try:
                _remove_own_staging(staging, staging_lock)
            except Exception as cleanup_error:
                _cleanup_diagnostic("own staging cleanup failed", cleanup_error)
        raise
    finally:
        try:
            os.close(staging_lock)
        except Exception as close_error:
            if published_ok:
                raise
            _cleanup_diagnostic("staging lock close failed", close_error)
    # Publish point: after this rename the bundle is complete and valid.
    # The parent-dir fsync below is attempted for crash ordering only;
    # its failure is reported as a warning and does not change the exit
    # code, because publication has already completed.
    try:
        _fsync_dir(out_parent)
    except OSError as e:
        print(f"warning: post-publish fsync failed: {e}", file=sys.stderr)
    _pause("after_publish", out_parent, bundle_name)

    return {
        "bundle": bundle_name,
        "published": os.path.abspath(published),
        "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "file_count": len(manifest_files),
    }


def recover_sweep(
    out_parent: str, diagnostics: list[str] | None = None
) -> tuple[list[str], list[str]]:
    """Best-effort removal of leftover staging dirs. Never a correctness
    condition; the consumer already rejects anything not at the exact
    published path with a complete manifest. Skips and reports staging a
    live pack still holds locked, symlinked entries, and anything it
    cannot remove. Reports reservations as skipped without opening or
    deleting them. Returns (removed, skipped). When diagnostics is given,
    appends one escaped, single-line "name: reason" per skipped entry;
    the returned tuple is unchanged."""
    import shutil

    # Resolve the path exactly as pack does: the kernel resolves a '..'
    # after a symlink differently from abspath, and pack staged under the
    # abspath, so the sweep must look where pack actually wrote.
    out_parent = os.path.abspath(out_parent)

    def note(fn: str, reason: str) -> None:
        skipped.append(fn)
        if diagnostics is not None:
            diagnostics.append(f"skipped {json.dumps(fn)}: {reason}")

    if not os.path.isdir(out_parent):
        raise ValueError(f"output parent not found: {out_parent}")
    removed: list[str] = []
    skipped: list[str] = []
    for fn in sorted(os.listdir(out_parent)):
        if fn.startswith(RESERVATION_PREFIX):
            # Never open or delete reservations.
            note(fn, "protected reservation, never swept")
            continue
        if not fn.startswith(STAGING_PREFIX):
            continue
        p = os.path.join(out_parent, fn)
        if os.path.islink(p) or not os.path.isdir(p):
            note(fn, "symlink or not a directory; left in place")
            continue
        try:
            fd = os.open(p, os.O_RDONLY)
        except OSError:
            # Disappeared or could not be opened.
            note(fn, "could not be opened")
            continue
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                # A live pack holds the lock.
                note(fn, "locked by a live pack")
                continue
            try:
                st = os.stat(p)
                fst = os.fstat(fd)
            except OSError:
                # Disappeared or could not be inspected.
                note(fn, "could not be inspected")
                continue
            if (st.st_dev, st.st_ino) != (fst.st_dev, fst.st_ino):
                note(fn, "changed during inspection")
                continue
            try:
                shutil.rmtree(p)
                removed.append(fn)
            except OSError as exc:
                # strerror only: no path is added to the diagnostic.
                note(fn, f"removal failed ({exc.strerror}); files may remain")
        finally:
            os.close(fd)
    return removed, skipped


def main(argv: list[str]) -> int:
    if len(argv) >= 2 and argv[1] == "--recover-sweep":
        if len(argv) != 3:
            print("usage: packager.py --recover-sweep OUT_PARENT", file=sys.stderr)
            return 2
        try:
            diagnostics: list[str] = []
            removed, skipped = recover_sweep(argv[2], diagnostics)
            for line in diagnostics:
                print(line, file=sys.stderr)
        except Exception as e:
            print(json.dumps({"error": str(e)}), file=sys.stderr)
            return 1
        print(json.dumps({"recovered_staging": removed, "skipped_staging": skipped}))
        return 0
    if len(argv) != 4:
        print("usage: packager.py EVIDENCE_DIR OUT_PARENT BUNDLE_NAME", file=sys.stderr)
        return 2
    try:
        evidence = pack(argv[1], argv[2], argv[3])
    except Exception as e:
        # No verdict, no claim about staging removal.
        print(json.dumps({"error": str(e)}), file=sys.stderr)
        return 1
    print(json.dumps(evidence, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
