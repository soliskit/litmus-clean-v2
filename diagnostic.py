#!/usr/bin/env python3
"""Run an explicit diagnostic profile once, without replacing its test verdict.

Session v1 is private local evidence. It neither uploads nor publishes a bundle.
The existing recorder receipt and its schema are unchanged.
"""

import argparse
import hashlib
import json
import math
import os
import platform
import signal
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any

import recorder
from local_mirror import LocalMirror

PROFILE_FIELDS = {"version", "repo", "check", "scope", "argv", "artifacts"}
MAX_PROFILE_BYTES = 65536
# session.json and receipt.json are generated, not caller-sized: a profile can be
# 64 KiB and the receipt repeats its argv with indentation, so they need headroom.
MAX_RECORD_BYTES = 1024 * 1024
CLAIMS = "One selected check only. No whole-repo or root-cause verdict."
MAX_ARTIFACT_BYTES = 16 * 1024 * 1024
MAX_TOTAL_BYTES = 32 * 1024 * 1024
MAX_ARTIFACTS = 32


def read_profile(path: Path) -> dict[str, Any]:
    """A profile is executable input, selected by the caller, not autodiscovered."""
    data = regular_bytes(path, MAX_PROFILE_BYTES)
    if len(data) > MAX_PROFILE_BYTES:
        raise ValueError("profile too large")
    value = json.loads(data)
    if not isinstance(value, dict) or set(value) != PROFILE_FIELDS:
        raise ValueError("unsupported profile fields")
    if type(value["version"]) is not int or value["version"] != 1:
        raise ValueError("unsupported profile version")
    for key in ("repo", "check", "scope"):
        if not isinstance(value[key], str) or not value[key].strip():
            raise ValueError(f"profile requires {key}")
    argv = value["argv"]
    if (
        not isinstance(argv, list)
        or not argv
        or not all(isinstance(arg, str) and "\0" not in arg for arg in argv)
        or not argv[0]
    ):
        raise ValueError("profile requires an argv vector")
    artifacts = value["artifacts"]
    if not isinstance(artifacts, list) or len(artifacts) > MAX_ARTIFACTS:
        raise ValueError("too many artifact paths")
    for item in artifacts:
        if not isinstance(item, str) or not item or "\0" in item:
            raise ValueError("invalid artifact path")
        relative = Path(item)
        if (
            relative.is_absolute()
            or str(relative) != item
            or any(p in (".", "..") for p in item.split("/"))
        ):
            raise ValueError("artifact path must be a relative file without traversal")
    if len(set(artifacts)) != len(artifacts):
        raise ValueError("duplicate artifact path")
    return value


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def regular_bytes(path: Path, limit: int) -> bytes:
    """Read one stable regular file, refusing links and special files."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size > limit:
            raise ValueError("artifact is not a bounded regular file")
        data = stream.read(limit + 1)
        after = os.fstat(stream.fileno())

    def identity(s: os.stat_result) -> tuple[int, int, int, int, int]:
        return s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns

    if (
        len(data) > limit
        or len(data) != before.st_size
        or identity(before) != identity(after)
    ):
        raise ValueError("artifact changed while reading")
    return data


Stamp = tuple[int, int, int, int, int]


def _stamp(info: os.stat_result) -> Stamp:
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns


def _open_anchored(root: Path, relative: str) -> int:
    """Anchor every path component to an opened directory, never a link."""
    directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        parts = Path(relative).parts
        for part in parts[:-1]:
            child = os.open(
                part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory
            )
            os.close(directory)
            directory = child
        return os.open(
            parts[-1],
            os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
            dir_fd=directory,
        )
    finally:
        os.close(directory)


def artifact_stamp(root: Path, relative: str) -> Stamp | None:
    """Identity of an artifact before launch, or None when it does not exist."""
    try:
        descriptor = _open_anchored(root, relative)
    except OSError:
        return None
    try:
        return _stamp(os.fstat(descriptor))
    finally:
        os.close(descriptor)


def artifact_bytes(root: Path, relative: str) -> tuple[bytes, Stamp]:
    """Read one stable regular file; return its bytes and observed identity."""
    with os.fdopen(_open_anchored(root, relative), "rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_ARTIFACT_BYTES:
            raise ValueError("artifact is not a bounded regular file")
        data = stream.read(MAX_ARTIFACT_BYTES + 1)
        after = os.fstat(stream.fileno())
    if (
        len(data) != before.st_size
        or len(data) > MAX_ARTIFACT_BYTES
        or _stamp(before) != _stamp(after)
    ):
        raise ValueError("artifact changed while reading")
    return data, _stamp(after)


def write_new(path: Path, data: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def command_status(receipt: dict[str, Any]) -> int:
    """Validate outcome framing before interpreting it in either code path."""
    if type(receipt.get("timed_out")) is not bool:
        raise ValueError("invalid timeout status")
    code, signum = receipt.get("exit"), receipt.get("signal")
    valid_exit = type(code) is int and 0 <= code <= 255 and signum is None
    valid_signal = code is None and type(signum) is int and 1 <= signum <= 127
    if not (valid_exit or valid_signal):
        raise ValueError("invalid command outcome")
    if receipt["timed_out"]:
        return 124
    if type(code) is int:
        return code
    if type(signum) is int:
        return 128 + signum
    raise ValueError("invalid command outcome")


def observed_unchanged(before: Any, after: Any, receipt: dict[str, Any]) -> bool:
    """Derived clean-checkout flag, recomputed by the verifier, never trusted."""
    return bool(
        before == after
        and before["worktree_clean"] is True
        and receipt["commit"] == before["commit"]
        and receipt["worktree_clean"] is True
    )


def ci_context(environment: dict[str, str]) -> dict[str, str] | None:
    """Allowlisted caller environment claims, not authenticated provider state."""
    if environment.get("GITHUB_ACTIONS") != "true":
        return None
    fields = {
        "repository": "GITHUB_REPOSITORY",
        "run_id": "GITHUB_RUN_ID",
        "run_attempt": "GITHUB_RUN_ATTEMPT",
        "job": "GITHUB_JOB",
        "event": "GITHUB_EVENT_NAME",
        "event_sha": "GITHUB_SHA",
        "ref": "GITHUB_REF",
        "head_ref": "GITHUB_HEAD_REF",
        "base_ref": "GITHUB_BASE_REF",
    }
    result = {
        name: environment[key] for name, key in fields.items() if environment.get(key)
    }
    if any(
        len(value) > 512 or any(ord(c) < 32 for c in value) for value in result.values()
    ):
        raise ValueError("invalid CI context")
    for field in ("run_id", "run_attempt"):
        if field in result and (not result[field].isdigit() or int(result[field]) < 1):
            raise ValueError("invalid CI numeric identity")
    if "event_sha" in result and not recorder.COMMIT_RE.fullmatch(result["event_sha"]):
        raise ValueError("invalid CI event SHA")
    result["provenance"] = "caller environment, not independently authenticated"
    return result


def git_identity(cwd: Path) -> dict[str, Any]:
    commit, clean = recorder.resolve_commit(str(cwd), None)
    tree = recorder._git(str(cwd), "rev-parse", "HEAD^{tree}")
    if tree.returncode:
        raise ValueError("cannot read checkout tree")
    return {"commit": commit, "tree": tree.stdout.strip(), "worktree_clean": clean}


def run(
    profile_path: Path,
    cwd: Path,
    destination: Path,
    timeout: float | None = None,
    mirror_path: Path | None = None,
) -> tuple[dict[str, Any], int]:
    if timeout is not None and (not math.isfinite(timeout) or timeout <= 0):
        raise ValueError("timeout must be finite and positive")
    if mirror_path is not None and os.environ.get("GITHUB_ACTIONS") == "true":
        raise ValueError("raw live mirror is local-only, not GitHub Actions")
    profile = read_profile(profile_path)
    profile_data = regular_bytes(profile_path, MAX_PROFILE_BYTES)
    # Bind the parsed profile to its exact input bytes before launching anything.
    if json.loads(profile_data) != profile:
        raise ValueError("profile changed while reading")
    cwd = cwd.resolve(strict=True)
    if not cwd.is_dir():
        raise ValueError("cwd must be a directory")
    source_before = git_identity(cwd)
    # A declared artifact that already exists before launch and is byte-for-byte
    # the same file afterwards was not produced by this run: stale, not evidence.
    stamps_before = {a: artifact_stamp(cwd, a) for a in profile["artifacts"]}
    ci = ci_context(dict(os.environ))
    tool_root = Path(__file__).resolve().parent
    tool_top = recorder._git(str(tool_root), "rev-parse", "--show-toplevel")
    if tool_top.returncode or Path(tool_top.stdout.strip()).resolve() != tool_root:
        raise ValueError("diagnostic must run from the root of its own Git checkout")
    for required in ("recorder.py", "packager.py", "verifier.py", "local_mirror.py"):
        tracked = recorder._git(str(tool_root), "ls-files", "--error-unmatch", required)
        if tracked.returncode:
            raise ValueError("tool checkout lacks tracked core files")
    tool_source = git_identity(tool_root)
    tool_files = {
        name: sha((Path(__file__).resolve().parent / name).read_bytes())
        for name in ("diagnostic.py", "recorder.py", "local_mirror.py")
    }
    git_version = recorder._git(str(cwd), "--version")
    runtime_facts = {
        "python": platform.python_version(),
        "system": platform.system(),
        "machine": platform.machine(),
        "git": git_version.stdout.strip() if git_version.returncode == 0 else "unknown",
    }
    if Path(profile["argv"][0]).name in ("node", "npm"):
        try:
            version = subprocess.run(
                ["node", "--version"],
                cwd=cwd,
                capture_output=True,
                text=True,
                check=False,
                timeout=5,
            )
            runtime_facts["path_node_probe"] = (
                version.stdout.strip() if version.returncode == 0 else "unknown"
            )
        except (OSError, subprocess.SubprocessError):
            runtime_facts["path_node_probe"] = "unknown"

    # Refuse reuse before invoking the command. Nothing is overwritten or retried.
    destination.mkdir(mode=0o700)
    destination = destination.resolve(strict=True)
    write_new(destination / "profile.json", profile_data)
    mirror = LocalMirror(mirror_path) if mirror_path is not None else None
    try:
        receipt = recorder.record(
            str(destination / "receipt.json"),
            profile["argv"],
            str(cwd),
            timeout,
            None,
            live_output=mirror,
        )
    finally:
        if mirror is not None:
            mirror.close()
    command_code = command_status(dict(receipt))
    attachments = []
    total = 0
    for number, relative in enumerate(profile["artifacts"]):
        entry: dict[str, Any] = {"source": relative}
        try:
            data, stamp = artifact_bytes(cwd, relative)
            if stamps_before[relative] == stamp:
                entry["reason"] = "unchanged_since_launch"
                raise ValueError("artifact was not written by this run")
            if total + len(data) > MAX_TOTAL_BYTES:
                raise ValueError("session attachment budget exceeded")
            target = f"attachment-{number:02d}.bin"
            write_new(destination / target, data)
            total += len(data)
            entry.update(
                status="captured", path=target, sha256=sha(data), bytes=len(data)
            )
        except (OSError, ValueError):
            # Error text can contain private paths or payloads. Keep a typed fact.
            entry.update(status="unavailable")
        attachments.append(entry)
    complete = all(a["status"] == "captured" for a in attachments)
    receipt_data = (destination / "receipt.json").read_bytes()
    source_after = None
    try:
        source_after = git_identity(cwd)
    except (OSError, ValueError):
        complete = False
    session = {
        "version": 1,
        "ci": ci,
        "source_before": source_before,
        "source_after": source_after,
        "observed_clean_checkout_unchanged": observed_unchanged(
            source_before, source_after, dict(receipt)
        ),
        "tool_source": tool_source,
        "tool_files": tool_files,
        "mirror": None if mirror is None else mirror.report(receipt["output"]["bytes"]),
        "runtime": runtime_facts,
        "repo_label": profile["repo"],
        "check": profile["check"],
        "scope": profile["scope"],
        "profile": {"path": "profile.json", "sha256": sha(profile_data)},
        "receipt": {"path": "receipt.json", "sha256": sha(receipt_data)},
        "command_exit": command_code,
        "evidence_status": "complete" if complete else "incomplete",
        "attachments": attachments,
        "claims": CLAIMS,
    }
    try:
        write_new(
            destination / "session.json",
            (json.dumps(session, indent=2) + "\n").encode(),
        )
    except OSError:
        session["evidence_status"] = "incomplete"
        session["session_write_failed"] = True
        complete = False

    # Keep original failure. A successful check with incomplete evidence is not a
    # successful diagnostic session, and uses the separate evidence-error code.
    return session, command_code if command_code else (0 if complete else 125)


def verify(destination: Path) -> dict[str, Any]:
    """Re-read a local session. Integrity only, not test correctness or authorship."""
    raw = regular_bytes(destination / "session.json", MAX_RECORD_BYTES)
    session = json.loads(raw)
    if not isinstance(session, dict) or session.get("version") != 1:
        raise ValueError("unsupported session")
    if type(session.get("version")) is not int or session["version"] != 1:
        raise ValueError("unsupported session version")
    if session.get("evidence_status") not in ("complete", "incomplete"):
        raise ValueError("invalid evidence status")
    for field, fixed_name in (("profile", "profile.json"), ("receipt", "receipt.json")):
        binding = session[field]
        if binding["path"] != fixed_name:
            raise ValueError("unexpected binding path")
        if (
            sha(regular_bytes(destination / fixed_name, MAX_RECORD_BYTES))
            != binding["sha256"]
        ):
            raise ValueError("session binding mismatch")
    receipt = json.loads(regular_bytes(destination / "receipt.json", MAX_RECORD_BYTES))
    if set(receipt) != recorder.RECEIPT_FIELDS or receipt["version"] != 1:
        raise ValueError("unsupported receipt")
    profile = read_profile(destination / "profile.json")
    if (
        session["repo_label"] != profile["repo"]
        or session["check"] != profile["check"]
        or session["scope"] != profile["scope"]
        or receipt["argv"] != profile["argv"]
    ):
        raise ValueError("profile/receipt/session mismatch")
    expected_exit = command_status(receipt)
    if (
        type(session["command_exit"]) is not int
        or session["command_exit"] != expected_exit
    ):
        raise ValueError("session outcome differs from receipt")
    if session.get("claims") != CLAIMS or "session_write_failed" in session:
        raise ValueError("session claims are not the fixed statement")
    origin, final = session["source_before"], session["source_after"]
    for source in (origin, final):
        if source is not None and (
            not isinstance(source, dict)
            or set(source) != {"commit", "tree", "worktree_clean"}
        ):
            raise ValueError("invalid source observation")
    if not isinstance(origin, dict):
        raise ValueError("invalid source observation")
    if session["observed_clean_checkout_unchanged"] is not observed_unchanged(
        origin, final, receipt
    ):
        raise ValueError("observed checkout flag is not derivable")
    output = receipt["output"]
    if output["path"] != "receipt.json.log":
        raise ValueError("unexpected log path")
    log_path = destination / "receipt.json.log"
    # The existing recorder does not cap logs. Hash in chunks without loading
    # an unbounded log into memory, refusing a link or changing file.
    fd = os.open(log_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size != output["bytes"]:
            raise ValueError("log framing mismatch")
        digest = hashlib.sha256()
        remaining = before.st_size
        while remaining:
            chunk = stream.read(min(65536, remaining))
            if not chunk:
                raise ValueError("short log")
            digest.update(chunk)
            remaining -= len(chunk)
        after = os.fstat(stream.fileno())
    if digest.hexdigest() != output["sha256"] or (
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    ) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
        raise ValueError("log changed")
    attachments = session["attachments"]
    if not isinstance(attachments, list) or len(attachments) > MAX_ARTIFACTS:
        raise ValueError("invalid attachments")
    if len(attachments) != len(profile["artifacts"]):
        raise ValueError("attachment census mismatch")
    total_bytes = 0
    for number, item in enumerate(attachments):
        if item["source"] != profile["artifacts"][number]:
            raise ValueError("attachment source mismatch")
        if item["status"] == "unavailable":
            if session["evidence_status"] != "incomplete":
                raise ValueError("unavailable evidence labeled complete")
            continue
        expected = f"attachment-{number:02d}.bin"
        if item["status"] != "captured" or item["path"] != expected:
            raise ValueError("invalid attachment binding")
        data = regular_bytes(destination / expected, MAX_ARTIFACT_BYTES)
        total_bytes += len(data)
        if total_bytes > MAX_TOTAL_BYTES:
            raise ValueError("attachment budget exceeded")
        if (
            sha(data) != item["sha256"]
            or type(item["bytes"]) is not int
            or len(data) != item["bytes"]
        ):
            raise ValueError("attachment mismatch")
    if session["evidence_status"] == "complete" and final is None:
        raise ValueError("complete evidence without a final source observation")
    return session


def main() -> int:
    if len(sys.argv) == 3 and sys.argv[1] == "--verify":
        try:
            result = verify(Path(sys.argv[2]))
        except (OSError, ValueError, KeyError, TypeError, RecursionError):
            print("Diagnostic integrity check failed.", file=sys.stderr)
            return 125
        print(json.dumps(result, indent=2))
        return 0
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("profile", type=Path)
    parser.add_argument("destination", type=Path)
    parser.add_argument("--cwd", type=Path, required=True)
    parser.add_argument("--timeout", type=float, default=None)
    parser.add_argument("--mirror-fifo", type=Path, default=None)
    args = parser.parse_args()
    for signum in recorder.INTERRUPT_SIGNALS:
        signal.signal(signum, recorder._raise_interrupted)
    try:
        session, code = run(
            args.profile, args.cwd, args.destination, args.timeout, args.mirror_fifo
        )
    except recorder.Interrupted as error:
        print("Diagnostic interrupted; no completed session claimed.", file=sys.stderr)
        return 128 + error.signum
    except (OSError, ValueError, json.JSONDecodeError, RecursionError):
        print("Diagnostic unavailable; no completed session claimed.", file=sys.stderr)
        return 125
    print(json.dumps(session, indent=2))
    return code


if __name__ == "__main__":
    sys.exit(main())
