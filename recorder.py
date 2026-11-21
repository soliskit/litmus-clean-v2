#!/usr/bin/env python3
"""Run receipt recorder (owner-side qualification tooling).

Records one observed local or manual run as a receipt: the commit the
run started from, the exact argv, start and end times, the measured
runtime, the exit outcome, an optional timeout, and the sha256 of the
captured output. One receipt schema for every suite, so a result quoted
later carries the same fields no matter which project produced it.

Honesty boundaries:
- A receipt records ONE OBSERVED run. It is not a minimum-runtime proof,
  not a supported-environment claim, and not a CI result; CI records its
  own runs.
- runtime_seconds is measured on a monotonic clock, independent of wall
  clock changes. started/ended are wall-clock UTC and are NOT monotonic.
- commit is the worktree's HEAD at launch. A dirty worktree means the
  bytes that ran are not the commit's bytes; worktree_clean records that
  state honestly instead of hiding it. Both come from the working
  directory's own repository: GIT_* environment variables and git config
  that hide files from git status do not change them.
- cwd and argv are recorded raw, including local absolute paths.
  Normalizing machine-specific paths is a separate publication step,
  never the recorder's edit.
- The receipt path is never overwritten: publication is two atomic
  no-overwrite hard links, the output log first and then the receipt,
  and an existing receipt or output log, including a symlink whose
  target is missing, refuses the run before the command starts. A log
  without its receipt can exist after an interruption; such a log is
  not a receipt and carries no meaning.
- A firing timeout sends a real SIGKILL to the run's whole process
  group. The receipt records timed_out, meaning the deadline fired;
  exit and signal record how the run actually ended, because a natural
  exit can race the kill. It does not record where the run was when
  the deadline fired.
- SIGINT, SIGTERM or SIGHUP to the recorder while the run is live sends
  the same real SIGKILL to the run's whole process group; no receipt is
  published and the recorder exits 128 plus the signal number. A missing
  receipt never hides a live run. An interrupt after the receipt link
  also exits 128 plus the signal number and says the receipt was
  published.

No root, no mounts, no environment mechanics. Python 3 standard library
only. git is used only to read HEAD and worktree state.
"""

import hashlib
import json
import math
import os
import re
import signal
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from typing import TypedDict

RECEIPT_VERSION = 1
RECEIPT_FIELDS = {
    "version",
    "commit",
    "worktree_clean",
    "argv",
    "cwd",
    "started",
    "ended",
    "runtime_seconds",
    "timeout_seconds",
    "timed_out",
    "exit",
    "signal",
    "output",
}
OUTPUT_FIELDS = {"path", "sha256", "bytes"}
# \Z, not $: $ also matches before a trailing newline.
COMMIT_RE = re.compile(r"^[0-9a-f]{40}\Z")
LOG_SUFFIX = ".log"
INTERRUPT_SIGNALS = (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)


class Interrupted(Exception):
    """SIGINT, SIGTERM or SIGHUP reached the recorder."""

    def __init__(self, signum: int) -> None:
        super().__init__(f"interrupted by signal {signum}")
        self.signum = signum


# The live run's process group, set only while the run is live. The handler
# kills it before raising: a further interrupt can cut short any Python code
# that runs after this exception is raised, but never a kill already done.
_live_group: int | None = None
# The receipt path this process has published. It is set with interrupts
# held, so an interrupt is reported against the exact publication state.
_published: str | None = None


def _raise_interrupted(signum: int, _frame: object) -> None:
    if _live_group is not None:
        _kill_group(_live_group)
    raise Interrupted(signum)


def _kill_group(pid: int) -> None:
    try:
        os.killpg(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


class ReceiptOutput(TypedDict):
    path: str
    sha256: str
    bytes: int


class Receipt(TypedDict):
    version: int
    commit: str
    worktree_clean: bool | None
    argv: list[str]
    cwd: str
    started: str
    ended: str
    runtime_seconds: float
    timeout_seconds: float | None
    timed_out: bool
    exit: int | None
    signal: int | None
    output: ReceiptOutput


USAGE = (
    "usage: recorder.py RECEIPT_PATH [--timeout SECONDS] [--cwd DIR] "
    "[--commit COMMIT] -- COMMAND [ARG...]"
)


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def _git(cwd: str, *args: str) -> "subprocess.CompletedProcess[str]":
    """Run git on cwd's own repository and work tree. GIT_* variables such
    as GIT_DIR or GIT_WORK_TREE would point git at other state, so none
    reaches it, and the fsmonitor that could vouch for files is off. No
    core.excludesFile, nor the user-level ignore file git reads when that is
    unset, can hide untracked files; the repository's own ignore rules
    still apply. core.ignoreCase is pinned false so a user-level setting
    cannot fold an untracked file into a tracked one that differs only by
    case; on a case-insensitive filesystem this can only mark more trees
    dirty, never fewer."""
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    return subprocess.run(
        [
            "git",
            "-c",
            "core.fsmonitor=false",
            "-c",
            f"core.excludesFile={os.devnull}",
            "-c",
            "core.ignoreCase=false",
            "-C",
            cwd,
            *args,
        ],
        capture_output=True,
        text=True,
        timeout=30,
        env=env,
    )


def resolve_commit(cwd: str, commit_override: str | None) -> tuple[str, bool | None]:
    """Return (commit, worktree_clean). Fail closed: without a resolvable
    HEAD and no override there is no receipt, because the commit field is
    load-bearing for everything the receipt says about what ran.
    worktree_clean is true only when git status, with untracked files and
    submodules always included, reports nothing and no index entry is
    marked assume-unchanged or skip-worktree: git status does not look at
    those files, so nothing vouches for them."""
    if commit_override is not None:
        if not COMMIT_RE.match(commit_override):
            raise ValueError("--commit must be 40 lowercase hex characters")
        return commit_override, None
    try:
        head = _git(cwd, "rev-parse", "HEAD")
    except FileNotFoundError:
        raise ValueError("git not found; pass --commit") from None
    if head.returncode != 0:
        raise ValueError(f"no git HEAD in {cwd}; pass --commit")
    commit = head.stdout.strip()
    if not COMMIT_RE.match(commit):
        raise ValueError(f"unexpected git HEAD output: {commit!r}")
    top = _git(cwd, "rev-parse", "--show-toplevel")
    toplevel = os.path.realpath(top.stdout.rstrip("\n"))
    if (
        top.returncode != 0
        or os.path.commonpath([toplevel, os.path.realpath(cwd)]) != toplevel
    ):
        raise ValueError(f"git work tree does not contain {cwd}; pass --commit")
    status = _git(
        cwd,
        "status",
        "--porcelain",
        "--untracked-files=all",
        "--ignore-submodules=none",
    )
    if status.returncode != 0:
        raise ValueError(f"git status failed in {cwd}")
    entries = _git(cwd, "ls-files", "-v", "-z")
    if entries.returncode != 0:
        raise ValueError(f"git ls-files failed in {cwd}")
    # ls-files -v tags assume-unchanged entries in lower case, skip-worktree S.
    hidden = any(e[0].islower() or e[0] == "S" for e in entries.stdout.split("\0") if e)
    return commit, status.stdout == "" and not hidden


def record(
    receipt_path: str,
    argv: list[str],
    cwd: str,
    timeout_seconds: float | None,
    commit_override: str | None,
) -> Receipt:
    """Run argv once and publish the pair by two atomic no-overwrite
    hard links, log first then receipt. Returns the receipt dict.
    Raises on any recorder-level failure; no receipt is published then."""
    global _live_group, _published
    receipt_path = os.path.abspath(receipt_path)
    parent = os.path.dirname(receipt_path)
    receipt_name = os.path.basename(receipt_path)
    log_name = receipt_name + LOG_SUFFIX
    if not os.path.isdir(parent):
        raise ValueError(f"receipt parent directory not found: {parent}")
    if not receipt_name:
        raise ValueError("receipt path names no file")
    # lexists: a symlink whose target is missing also takes the name, and
    # the no-overwrite link would refuse it only after the command ran.
    if os.path.lexists(receipt_path):
        raise ValueError(f"receipt path already exists: {receipt_path}")
    if os.path.lexists(os.path.join(parent, log_name)):
        raise ValueError(f"output log path already exists: {log_name}")
    if not os.path.isdir(cwd):
        raise ValueError(f"working directory not found: {cwd}")
    commit, worktree_clean = resolve_commit(cwd, commit_override)

    staging = tempfile.mkdtemp(prefix=".receipt-", dir=parent)
    staged_log = os.path.join(staging, log_name)
    staged_receipt = os.path.join(staging, receipt_name)

    started = _utcnow()
    t0 = time.monotonic()
    timed_out = False
    with open(staged_log, "xb") as logf:
        # Interrupts stay pending while the run starts, so none can land
        # between its start and the handling below. The command itself
        # starts with the recorder's original signal mask.
        mask = signal.pthread_sigmask(signal.SIG_BLOCK, INTERRUPT_SIGNALS)
        try:
            proc = subprocess.Popen(
                argv,
                cwd=cwd,
                stdout=logf,
                stderr=subprocess.STDOUT,
                start_new_session=True,
                preexec_fn=lambda: signal.pthread_sigmask(signal.SIG_SETMASK, mask),
            )
        except BaseException:
            signal.pthread_sigmask(signal.SIG_SETMASK, mask)
            raise
        _live_group = proc.pid  # still masked: no handler runs before this
        try:
            signal.pthread_sigmask(signal.SIG_SETMASK, mask)
            try:
                rc = proc.wait(timeout=timeout_seconds)
            except subprocess.TimeoutExpired:
                timed_out = True
                _kill_group(proc.pid)
                rc = proc.wait()
        except BaseException:
            # Interrupted while the run is live: kill its whole group, so
            # no run outlives the recorder without its deadline.
            _kill_group(proc.pid)
            proc.wait()
            raise
        finally:
            _live_group = None
    ended = _utcnow()
    runtime = time.monotonic() - t0

    if rc >= 0:
        exit_code, sig = rc, None
    else:
        exit_code, sig = None, -rc

    # Freeze the log before publishing: rename the staged log aside,
    # copy it into a fresh inode while hashing, and publish the copy.
    # No run process ever holds a descriptor on the fresh inode, so the
    # published log cannot change after the receipt. The copy is bounded
    # by the aside's size at freeze time, so a still-writing descendant
    # cannot keep the recorder copying forever.
    aside = staged_log + ".aside"
    os.rename(staged_log, aside)
    h = hashlib.sha256()
    nbytes = 0
    with open(aside, "rb") as src_f:
        cutoff = os.fstat(src_f.fileno()).st_size
        with open(staged_log, "xb") as dst_f:
            while nbytes < cutoff:
                chunk = src_f.read(min(65536, cutoff - nbytes))
                if not chunk:
                    break
                dst_f.write(chunk)
                h.update(chunk)
                nbytes += len(chunk)
    os.unlink(aside)
    output: ReceiptOutput = {"path": log_name, "sha256": h.hexdigest(), "bytes": nbytes}
    receipt: Receipt = {
        "version": RECEIPT_VERSION,
        "commit": commit,
        "worktree_clean": worktree_clean,
        "argv": list(argv),
        "cwd": cwd,
        "started": started,
        "ended": ended,
        "runtime_seconds": round(runtime, 3),
        "timeout_seconds": timeout_seconds,
        "timed_out": timed_out,
        "exit": exit_code,
        "signal": sig,
        "output": output,
    }
    data = json.dumps(receipt, indent=2, sort_keys=True, allow_nan=False).encode()
    data += b"\n"
    with open(staged_receipt, "xb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    log_fd = os.open(staged_log, os.O_RDONLY)
    try:
        os.fsync(log_fd)
    finally:
        os.close(log_fd)

    # Publish: log first, then the receipt, each one atomic no-overwrite
    # hard link. After the receipt link the pair is complete; before it,
    # an orphaned log carries no meaning.
    published_log = os.path.join(parent, log_name)
    os.link(staged_log, published_log)
    held = signal.pthread_sigmask(signal.SIG_BLOCK, [])
    try:
        signal.pthread_sigmask(signal.SIG_BLOCK, INTERRUPT_SIGNALS)
        try:
            os.link(staged_receipt, receipt_path)
        except OSError:
            try:
                os.unlink(published_log)
            except OSError as cleanup_error:
                # Keep the link error: it is why there is no receipt.
                print(
                    f"warning: published log not removed ({cleanup_error}); "
                    "it carries no meaning without its receipt",
                    file=sys.stderr,
                )
            raise
        _published = receipt_path
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, held)
    # The pair is published. A staging cleanup failure is a warning only.
    try:
        os.unlink(staged_log)
        os.unlink(staged_receipt)
        os.rmdir(staging)
    except OSError as e:
        print(f"warning: staging cleanup failed after publish: {e}", file=sys.stderr)
    return receipt


def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def main(argv: list[str]) -> int:
    args = argv[1:]
    if "--" not in args:
        print(USAGE, file=sys.stderr)
        return 2
    sep = args.index("--")
    opts, command = args[:sep], args[sep + 1 :]
    if not command:
        print(USAGE, file=sys.stderr)
        return 2
    receipt_path = None
    timeout_seconds = None
    cwd = os.getcwd()
    commit_override = None
    i = 0
    while i < len(opts):
        o = opts[i]
        if o == "--timeout" and i + 1 < len(opts):
            try:
                timeout_seconds = float(opts[i + 1])
            except ValueError:
                print("--timeout must be a number of seconds", file=sys.stderr)
                return 2
            if not math.isfinite(timeout_seconds) or timeout_seconds <= 0:
                print("--timeout must be a finite positive number", file=sys.stderr)
                return 2
            i += 2
        elif o == "--cwd" and i + 1 < len(opts):
            cwd = os.path.abspath(opts[i + 1])
            i += 2
        elif o == "--commit" and i + 1 < len(opts):
            commit_override = opts[i + 1]
            i += 2
        elif receipt_path is None and not o.startswith("--"):
            receipt_path = o
            i += 1
        else:
            print(USAGE, file=sys.stderr)
            return 2
    if receipt_path is None:
        print(USAGE, file=sys.stderr)
        return 2
    for signum in INTERRUPT_SIGNALS:
        signal.signal(signum, _raise_interrupted)
    try:
        receipt = record(receipt_path, command, cwd, timeout_seconds, commit_override)
        print(json.dumps(receipt, indent=2, sort_keys=True))
    except Interrupted as e:
        if _published == os.path.abspath(receipt_path):
            error = f"{e} after the run ended and its receipt was published"
        else:
            error = f"{e}; any live run's process group was killed; no receipt"
        print(json.dumps({"error": error}), file=sys.stderr)
        return 128 + e.signum
    except Exception as e:
        print(json.dumps({"error": str(e)}), file=sys.stderr)
        return 1
    if receipt["timed_out"]:
        return 124
    if receipt["exit"] is not None:
        return receipt["exit"]
    sig = receipt["signal"]
    assert sig is not None
    return 128 + sig


if __name__ == "__main__":
    sys.exit(main(sys.argv))
