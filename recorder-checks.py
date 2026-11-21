#!/usr/bin/env python3
"""Qualification checks for the run receipt recorder.

Real mechanisms only: a real git work tree, real subprocesses, a real
timeout with a real SIGKILL of the run's process group, and real existing
files for the no-overwrite refusals. Each check returns a detail string;
the driver prints one line per check and exits nonzero if any fail. This
gate qualifies the recorder's own behavior ONLY; it certifies nothing
about any run the recorder records.
"""

import array
import json
import os
import select
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import recorder

HERE = os.path.dirname(os.path.abspath(__file__))
RECORDER = os.path.join(HERE, "recorder.py")
sys.path.insert(0, HERE)


def run(cmd: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run([sys.executable, *cmd], capture_output=True, text=True)


def git(cwd: str, *args: str) -> str:
    r = subprocess.run(["git", "-C", cwd, *list(args)], capture_output=True, text=True)
    assert r.returncode == 0, f"git {args} failed: {r.stderr}"
    return r.stdout.strip()


def make_repo(root: str) -> str:
    repo = os.path.join(root, "repo")
    os.makedirs(repo)
    git(repo, "init", "-q")
    git(repo, "config", "user.email", "gate@example.invalid")
    git(repo, "config", "user.name", "Gate")
    with open(os.path.join(repo, "tracked.txt"), "w") as f:
        f.write("tracked\n")
    git(repo, "add", "tracked.txt")
    git(repo, "commit", "-q", "-m", "init")
    return repo


def read_receipt(path: str) -> "tuple[recorder.Receipt, bytes]":
    with open(path, "rb") as f:
        raw = f.read()
    receipt: recorder.Receipt = json.loads(
        raw.decode("utf-8"), parse_constant=reject_constant
    )
    return receipt, raw


def reject_constant(token: str) -> None:
    """Receipts are strict JSON: NaN and Infinity are refused."""
    raise ValueError(f"receipt is not strict JSON: {token}")


def check(name: str) -> Callable[[Callable[[str], str]], Callable[[str], str]]:
    def deco(fn: Callable[[str], str]) -> Callable[[str], str]:
        CHECKS.append((name, fn))
        return fn

    return deco


CHECKS: list[tuple[str, Callable[[str], str]]] = []


@check("R1 passing run recorded exactly")
def r1(t: str) -> str:
    import recorder

    repo = make_repo(t)
    rp = os.path.join(t, "pass.json")
    r = run(
        [
            RECORDER,
            rp,
            "--cwd",
            repo,
            "--",
            sys.executable,
            "-c",
            "import sys; sys.stdout.write('hello-run\\n')",
        ]
    )
    assert r.returncode == 0, r.stderr
    receipt, _ = read_receipt(rp)
    assert set(receipt) == recorder.RECEIPT_FIELDS, sorted(receipt)
    assert receipt["version"] == 1
    assert receipt["commit"] == git(repo, "rev-parse", "HEAD")
    assert receipt["worktree_clean"] is True
    assert receipt["argv"] == [
        sys.executable,
        "-c",
        "import sys; sys.stdout.write('hello-run\\n')",
    ]
    assert receipt["cwd"] == repo
    assert receipt["exit"] == 0
    assert receipt["timed_out"] is False
    assert receipt["signal"] is None
    assert receipt["timeout_seconds"] is None
    assert receipt["runtime_seconds"] > 0
    out = receipt["output"]
    assert set(out) == recorder.OUTPUT_FIELDS
    log = os.path.join(t, "pass.json.log")
    with open(log, "rb") as f:
        log_bytes = f.read()
    assert b"hello-run" in log_bytes
    assert out["bytes"] == len(log_bytes)
    import hashlib

    assert out["sha256"] == hashlib.sha256(log_bytes).hexdigest()
    return "commit, argv, exit 0 and output hash recorded exactly"


@check("R2 failing exit code recorded and propagated")
def r2(t: str) -> str:
    repo = make_repo(t)
    rp = os.path.join(t, "fail.json")
    r = run(
        [
            RECORDER,
            rp,
            "--cwd",
            repo,
            "--",
            sys.executable,
            "-c",
            "import sys; sys.exit(3)",
        ]
    )
    assert r.returncode == 3, (r.returncode, r.stderr)
    receipt, _ = read_receipt(rp)
    assert receipt["exit"] == 3
    assert receipt["timed_out"] is False
    assert receipt["signal"] is None
    return "exit 3 recorded; recorder exits 3"


def reap(survivors: list[tuple[int, int]]) -> None:
    """SIGKILL only the exact processes that anchored themselves, each
    named by a pidfd the process opened on itself and passed here. A
    member already dead is skipped with no signal: its descriptor polls
    as exited, and even a signal attempted against a dead member fails
    ProcessLookupError, because the descriptor still names the original
    process and can never reach a reuser of its pid. Descriptors are
    closed either way."""
    for _pid, fd in survivors:
        try:
            if not exited(fd, wait=0):
                signal.pidfd_send_signal(fd, signal.SIGKILL)
        except ProcessLookupError:
            pass
        finally:
            os.close(fd)


def exited(fd: int, wait: float = 5.0) -> bool:
    """True once the process a pidfd names has exited. The descriptor
    becomes readable at exit, zombie or reaped alike, and never goes
    readable for an unrelated process that later reuses the pid."""
    deadline = time.monotonic() + wait
    poller = select.poll()
    poller.register(fd, select.POLLIN)
    while True:
        if poller.poll(0):
            return True
        if time.monotonic() > deadline:
            return False
        time.sleep(0.05)


def anchor_payload(sock_path: str) -> str:
    """Fixture prefix: open a pidfd on this very process and pass it to
    the gate over the run's unix socket, with the pid as a label. The
    process anchors itself from inside, so the descriptor provably names
    the sender: there is no pidfile and no window in which the pid could
    die and be reused before the gate anchors it."""
    return (
        "import array, os, socket; "
        "_fd = os.pidfd_open(os.getpid()); "
        "_s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM); "
        f"_s.connect({sock_path!r}); "
        "_s.sendmsg([str(os.getpid()).encode()], "
        "[(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', [_fd]))])"
    )


def group_child(sock_path: str) -> str:
    """A run whose child starts a background descendant in its own process
    group; each member anchors itself with the gate, then sleeps."""
    descendant = anchor_payload(sock_path) + "; import time; time.sleep(60)"
    return (
        "import subprocess, sys; "
        f"subprocess.Popen([sys.executable, '-c', {descendant!r}]); "
        + anchor_payload(sock_path)
        + "; print('before-sleep', flush=True); import time; time.sleep(60)"
    )


@check(
    "R3 timeout or interrupt kills the run's process group with a real SIGKILL;"
    " only a finite positive timeout is accepted"
)
def r3(t: str) -> str:
    repo = make_repo(t)
    marker = os.path.join(t, "should-not-exist")
    for bad in ("nan", "inf", "-inf", "0", "-1"):
        rp = os.path.join(t, f"bad-timeout-{bad}.json")
        r = run(
            [
                RECORDER,
                rp,
                "--cwd",
                repo,
                "--timeout",
                bad,
                "--",
                sys.executable,
                "-c",
                f"open({marker!r},'w').write('x')",
            ]
        )
        assert r.returncode == 2, (bad, r.returncode, r.stderr)
        assert not os.path.exists(marker), f"command ran with --timeout {bad}"
        assert not os.path.exists(rp), f"receipt written with --timeout {bad}"
    rp = os.path.join(t, "slow.json")
    sock_path = os.path.join(t, "anchors.sock")
    anchors = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    anchors.bind(sock_path)
    # Each survivor is (pid, pidfd) the process passed about itself over
    # the run's socket: self-anchored, so the descriptor provably names
    # that exact process, and a pidfd never names a reused pid. Cleanup
    # can only ever signal the processes this run anchored.
    survivors: list[tuple[int, int]] = []

    def collect(expected: int) -> None:
        """Receive self-anchored pidfds until expected members have checked
        in. The pid label is cross-checked against the descriptor's own
        fdinfo, so a mismatched anchor fails here rather than at kill."""
        deadline = time.monotonic() + 20
        for _ in range(expected):
            assert proc.poll() is None, proc.communicate()
            remaining = deadline - time.monotonic()
            assert remaining > 0, "run members never anchored"
            anchors.settimeout(remaining)
            try:
                msg, ancdata, _flags, _addr = anchors.recvmsg(
                    64, socket.CMSG_LEN(array.array("i").itemsize)
                )
            except TimeoutError:
                raise AssertionError("run members never anchored") from None
            pid = int(msg.decode())
            fds = array.array("i")
            for level, ctype, cdata in ancdata:
                if level == socket.SOL_SOCKET and ctype == socket.SCM_RIGHTS:
                    fds.frombytes(cdata[: fds.itemsize])
            assert len(fds) == 1, "anchor carried no pidfd"
            fd = int(fds[0])
            with open(f"/proc/self/fdinfo/{fd}") as f:
                labelled = next(
                    int(line.split()[1]) for line in f if line.startswith("Pid:")
                )
            assert labelled == pid, (labelled, pid)
            survivors.append((pid, fd))

    try:
        t0 = time.monotonic()
        proc = subprocess.Popen(
            [
                sys.executable,
                RECORDER,
                rp,
                "--cwd",
                repo,
                "--timeout",
                "1",
                "--",
                sys.executable,
                "-c",
                group_child(sock_path),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        # Both members anchor themselves at startup, well before the 1s
        # timeout kills the group.
        collect(2)
        _out, err = proc.communicate(timeout=30)
        wall = time.monotonic() - t0
        assert proc.returncode == 124, (proc.returncode, err)
        assert wall < 20, f"kill did not return promptly: {wall:.1f}s"
        receipt, _ = read_receipt(rp)
        assert receipt["timed_out"] is True
        assert receipt["exit"] is None
        assert receipt["signal"] == 9
        assert receipt["timeout_seconds"] == 1.0
        alive = [pid for pid, fd in survivors if not exited(fd)]
        assert not alive, f"process group members {alive} survived the timeout"
        log = os.path.join(t, "slow.json.log")
        with open(log, "rb") as f:
            assert b"before-sleep" in f.read()

        # An interrupt to the recorder during the run kills the same group,
        # long before the run's own deadline.
        for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            rp = os.path.join(t, f"interrupted-{sig.name}.json")
            proc = subprocess.Popen(
                [
                    sys.executable,
                    RECORDER,
                    rp,
                    "--cwd",
                    repo,
                    "--timeout",
                    "60",
                    "--",
                    sys.executable,
                    "-c",
                    group_child(sock_path),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            collect(2)
            proc.send_signal(sig)
            _out, err = proc.communicate(timeout=20)
            assert proc.returncode == 128 + sig, (sig.name, proc.returncode, err)
            assert "Traceback" not in err, err
            assert "interrupted" in json.loads(err)["error"], err
            assert not os.path.exists(rp), f"receipt published after {sig.name}"
            alive = [pid for pid, fd in survivors[-2:] if not exited(fd)]
            assert not alive, f"run's group members {alive} survived {sig.name}"
    finally:
        reap(survivors)
        anchors.close()
    return (
        "nan, inf, -inf, 0 and -1 timeouts refused before launch; timeout: "
        "timed_out, null exit, signal 9, child and background descendant "
        "really dead; SIGINT, SIGTERM and SIGHUP: group killed, no receipt, "
        "exit 128 plus the signal"
    )


@check("R4 existing receipt or log refuses before the command starts")
def r4(t: str) -> str:
    repo = make_repo(t)
    rp = os.path.join(t, "taken.json")
    r = run([RECORDER, rp, "--cwd", repo, "--", sys.executable, "-c", "pass"])
    assert r.returncode == 0, r.stderr
    _, original = read_receipt(rp)
    marker = os.path.join(t, "should-not-exist")
    r = run(
        [
            RECORDER,
            rp,
            "--cwd",
            repo,
            "--",
            sys.executable,
            "-c",
            f"open({marker!r},'w').write('x')",
        ]
    )
    assert r.returncode == 1
    assert not os.path.exists(marker), "command ran despite refusal"
    _, after = read_receipt(rp)
    assert original == after, "existing receipt changed"
    orphan = os.path.join(t, "orphan.json")
    with open(orphan + ".log", "w") as f:
        f.write("orphan log\n")
    r = run(
        [
            RECORDER,
            orphan,
            "--cwd",
            repo,
            "--",
            sys.executable,
            "-c",
            f"open({marker!r},'w').write('x')",
        ]
    )
    assert r.returncode == 1
    assert not os.path.exists(marker)
    assert not os.path.exists(orphan), "receipt written over orphan log"
    # A symlink whose target is missing still takes the name.
    for label, receipt_path, link in (
        ("receipt", os.path.join(t, "dangling.json"), "dangling.json"),
        ("log", os.path.join(t, "dangling-log.json"), "dangling-log.json.log"),
    ):
        link_path = os.path.join(t, link)
        os.symlink(os.path.join(t, "missing-target"), link_path)
        r = run(
            [
                RECORDER,
                receipt_path,
                "--cwd",
                repo,
                "--",
                sys.executable,
                "-c",
                f"open({marker!r},'w').write('x')",
            ]
        )
        assert r.returncode == 1, (label, r.returncode, r.stderr)
        assert not os.path.exists(marker), f"command ran despite a dangling {label}"
        assert os.readlink(link_path) == os.path.join(t, "missing-target"), label
        assert not os.path.lexists(os.path.join(t, "missing-target")), label
    return (
        "receipt and log collisions, including dangling symlinks at either "
        "path, refuse before launch"
    )


@check("R5 commit resolution fails closed outside a work tree")
def r5(t: str) -> str:
    rp = os.path.join(t, "nogit.json")
    r = run([RECORDER, rp, "--cwd", t, "--", sys.executable, "-c", "pass"])
    assert r.returncode == 1
    assert not os.path.exists(rp), "receipt written without a commit"
    commit = "d" * 40
    r = run(
        [
            RECORDER,
            rp,
            "--cwd",
            t,
            "--commit",
            commit,
            "--",
            sys.executable,
            "-c",
            "pass",
        ]
    )
    assert r.returncode == 0, r.stderr
    receipt, _ = read_receipt(rp)
    assert receipt["commit"] == commit
    assert receipt["worktree_clean"] is None
    marker = os.path.join(t, "should-not-exist")
    for bad in ("nothex", commit + "\n"):
        rp_bad = os.path.join(t, "bad.json")
        r = run(
            [
                RECORDER,
                rp_bad,
                "--cwd",
                t,
                "--commit",
                bad,
                "--",
                sys.executable,
                "-c",
                f"open({marker!r},'w').write('x')",
            ]
        )
        assert r.returncode == 1, (bad, r.returncode)
        assert not os.path.exists(rp_bad), f"receipt written for commit {bad!r}"
        assert not os.path.exists(marker), f"command ran with commit {bad!r}"
    return (
        "no HEAD and no --commit: no receipt; override recorded; malformed "
        "commits, including 40 hex plus a newline, refused before launch"
    )


@check("R6 dirty worktree is recorded, not hidden")
def r6(t: str) -> str:
    repo = make_repo(t)
    with open(os.path.join(repo, "tracked.txt"), "a") as f:
        f.write("dirty\n")
    rp = os.path.join(t, "dirty.json")
    r = run([RECORDER, rp, "--cwd", repo, "--", sys.executable, "-c", "pass"])
    assert r.returncode == 0, r.stderr
    receipt, _ = read_receipt(rp)
    assert receipt["worktree_clean"] is False
    assert receipt["commit"] == git(repo, "rev-parse", "HEAD")

    def recorded(name: str, cwd: str, **env: str) -> "recorder.Receipt":
        path = os.path.join(t, name)
        r = subprocess.run(
            [sys.executable, RECORDER, path, "--cwd", cwd, "--", "true"],
            capture_output=True,
            text=True,
            env=dict(os.environ, **env),
        )
        assert r.returncode == 0, (name, r.stderr)
        receipt, _ = read_receipt(path)
        return receipt

    # git config and index flags that hide changes from git status
    hidden: list[tuple[str, Callable[[str], object]]] = [
        (
            "assume-unchanged",
            lambda d: git(d, "update-index", "--assume-unchanged", "tracked.txt"),
        ),
        (
            "skip-worktree",
            lambda d: git(d, "update-index", "--skip-worktree", "tracked.txt"),
        ),
    ]
    for label, flag in hidden:
        d = make_repo(os.path.join(t, label))
        with open(os.path.join(d, "tracked.txt"), "a") as f:
            f.write("dirty\n")
        flag(d)
        assert git(d, "status", "--porcelain") == "", f"{label} did not hide the edit"
        assert recorded(f"{label}.json", d)["worktree_clean"] is False, label
    d = make_repo(os.path.join(t, "untracked"))
    git(d, "config", "status.showUntrackedFiles", "no")
    with open(os.path.join(d, "untracked.txt"), "w") as f:
        f.write("untracked\n")
    assert git(d, "status", "--porcelain") == "", "config did not hide the file"
    assert recorded("untracked.json", d)["worktree_clean"] is False

    # GIT_DIR naming another repository changes neither field
    clean = make_repo(os.path.join(t, "clean"))
    other = make_repo(os.path.join(t, "other"))
    git(other, "commit", "-q", "--allow-empty", "-m", "other")
    receipt = recorded("git-dir.json", clean, GIT_DIR=os.path.join(other, ".git"))
    assert receipt["commit"] == git(clean, "rev-parse", "HEAD"), "GIT_DIR followed"
    assert receipt["commit"] != git(other, "rev-parse", "HEAD")
    assert receipt["worktree_clean"] is True, "GIT_DIR changed worktree_clean"

    # A repository whose config moves its work tree elsewhere is refused
    moved = make_repo(os.path.join(t, "moved"))
    git(moved, "config", "core.worktree", other)
    path = os.path.join(t, "moved.json")
    r = run([RECORDER, path, "--cwd", moved, "--", sys.executable, "-c", "pass"])
    assert r.returncode == 1, (r.returncode, r.stderr)
    assert not os.path.exists(path), "receipt written for a moved work tree"
    return (
        "worktree_clean false for a plain edit, an edit behind assume-unchanged "
        "or skip-worktree, and an untracked file behind "
        "status.showUntrackedFiles=no; GIT_DIR changed neither field; a "
        "work tree moved by core.worktree refused"
    )


@check("R7 receipt framing is exact and timestamps parse")
def r7(t: str) -> str:
    import recorder

    repo = make_repo(t)
    rp = os.path.join(t, "framing.json")
    r = run([RECORDER, rp, "--cwd", repo, "--", sys.executable, "-c", "pass"])
    assert r.returncode == 0, r.stderr
    receipt, _raw = read_receipt(rp)
    assert set(receipt) == recorder.RECEIPT_FIELDS
    assert set(receipt["output"]) == recorder.OUTPUT_FIELDS
    from datetime import datetime, timedelta

    started = datetime.fromisoformat(receipt["started"])
    ended = datetime.fromisoformat(receipt["ended"])
    # UTC, not merely timezone-aware: any other offset breaks the receipt.
    assert started.utcoffset() == timedelta(0), receipt["started"]
    assert ended.utcoffset() == timedelta(0), receipt["ended"]
    # No ordering check: started and ended are wall clock, which can step
    # backward during a run. Only runtime_seconds is monotonic.
    assert receipt["runtime_seconds"] >= 0
    assert receipt["output"]["path"] == "framing.json.log"
    stdout_receipt = json.loads(r.stdout)
    assert stdout_receipt == receipt, "stdout differs from published file"
    return "exact field set, UTC timestamps, stdout equals file"


@check(
    "R8 published log frozen: a background descendant's later write never changes it"
)
def r8(t: str) -> str:
    import recorder

    repo = make_repo(t)
    rp = os.path.join(t, "freeze.json")
    r = run(
        [
            RECORDER,
            rp,
            "--cwd",
            repo,
            "--",
            "sh",
            "-c",
            "printf hello; (sleep 2; printf LATE-OUTPUT) &",
        ]
    )
    assert r.returncode == 0, r.stderr
    receipt, _ = read_receipt(rp)
    time.sleep(3)  # let the descendant's late write land (or be lost)
    with open(rp + ".log", "rb") as f:
        log = f.read()
    assert log == b"hello", f"published log changed after publish: {log!r}"
    assert receipt["output"]["sha256"] == recorder._sha256_file(rp + ".log")
    assert receipt["output"]["bytes"] == len(log)
    return "late background output absent from the published log; hash still matches"


@check("R9 timeout with a setsid-escaped writer: log frozen, exit 124")
def r9(t: str) -> str:
    import recorder

    repo = make_repo(t)
    rp = os.path.join(t, "freeze-timeout.json")
    r = run(
        [
            RECORDER,
            rp,
            "--cwd",
            repo,
            "--timeout",
            "1",
            "--",
            "sh",
            "-c",
            "setsid " + sys.executable + ' -c "import time; time.sleep(2); print(42)"'
            " & sleep 30",
        ]
    )
    assert r.returncode == 124, r.stderr
    receipt, _ = read_receipt(rp)
    assert receipt["timed_out"] is True
    time.sleep(3)  # past the escaped writer's 2s write
    with open(rp + ".log", "rb") as f:
        log = f.read()
    assert b"42" not in log, "escaped writer's output reached the published log"
    assert receipt["output"]["sha256"] == recorder._sha256_file(rp + ".log")
    return "escaped writer's post-kill output not captured; hash still matches"


@check("R10 runaway writer after child exit: bounded snapshot, recorder terminates")
def r10(t: str) -> str:
    import recorder

    repo = make_repo(t)
    writer = os.path.join(t, "flood-writer.py")
    with open(writer, "w") as f:
        f.write(
            "import os, time\n"
            "t0 = time.monotonic()\n"
            "while time.monotonic() - t0 < 10:\n"
            "    os.write(1, b'x' * 1048576)\n"
        )
    launcher = os.path.join(t, "flood-launcher.py")
    with open(launcher, "w") as f:
        f.write(
            "import subprocess, sys, time\n"
            f"subprocess.Popen([sys.executable, {writer!r}], stdout=1)\n"
            "time.sleep(0.5)  # let the flood get underway before exiting\n"
        )
    rp = os.path.join(t, "runaway.json")
    proc = subprocess.Popen(
        [sys.executable, RECORDER, rp, "--cwd", repo, "--", sys.executable, launcher],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    t0 = time.monotonic()
    try:
        proc.communicate(timeout=8)
    except subprocess.TimeoutExpired as e:
        proc.kill()
        proc.communicate()
        raise AssertionError(
            "recorder did not terminate within 8s (unbounded read of a growing log)"
        ) from e
    dt = time.monotonic() - t0
    assert proc.returncode == 0, proc.stderr
    receipt, _ = read_receipt(rp)
    size = os.path.getsize(rp + ".log")
    assert receipt["output"]["sha256"] == recorder._sha256_file(rp + ".log")
    assert receipt["output"]["bytes"] == size
    os.unlink(rp)
    os.unlink(rp + ".log")  # large snapshot; do not litter it
    return f"terminated in {dt:.1f}s with a bounded {size}-byte snapshot; hash matches"


SKIP_ENV = "RECORDER_CHECKS_SKIP"
SKIPPABLE = "R10"  # the one check CI excludes; every other check must run


def main() -> int:
    if not __debug__:
        print(
            "REFUSED: assertions are disabled (python -O or PYTHONOPTIMIZE); "
            "every check is an assert, so no PASS line would mean anything.",
            file=sys.stderr,
        )
        return 2
    raw = os.environ.get(SKIP_ENV)
    if raw is not None and raw.strip() != SKIPPABLE:
        print(
            f"REFUSED: {SKIP_ENV} accepts only {SKIPPABLE!r}; got {raw!r}. "
            "Every other check must run.",
            file=sys.stderr,
        )
        return 2
    skip = raw is not None
    failures = 0
    skipped = 0
    for name, fn in CHECKS:
        if skip and name.startswith(SKIPPABLE + " "):
            skipped += 1
            print(f"SKIP {name}: skipped by {SKIP_ENV}; no qualification claimed")
            continue
        t = tempfile.mkdtemp(prefix="recorder-check-")
        try:
            detail = fn(t)
            print(f"PASS {name}: {detail}")
        except Exception as e:
            failures += 1
            print(f"FAIL {name}: {e}")
        finally:
            shutil.rmtree(t, ignore_errors=True)
    print(f"{len(CHECKS)} checks, {failures} failures, {skipped} skipped")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
