"""Focused regressions: sweep inspection, the staging-name lock window,
gate startup refusals (RECORDER_CHECKS_SKIP and assertions-disabled),
evidence identity after collection, sweep path resolution, worktree
cleanliness against user-level git config, gate cleanup kills, and
per-attempt staging ownership.

Run from the repository root:
    python3 -m unittest discover -s tests -p test_staging_regressions.py

Linux directory flock and an unprivileged account are required. These are
controlled scheduling tests, not a measurement of ordinary race frequency.
"""

import array
import ast
import contextlib
import errno
import fcntl
import hashlib
import importlib.util
import io
import json
import os
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any
from unittest.mock import patch

import packager


class StagingRegressions(unittest.TestCase):
    def setUp(self) -> None:
        if os.geteuid() == 0:
            self.skipTest("unprivileged account required")
        self.temp = tempfile.TemporaryDirectory(prefix="litmus-regression-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_unreadable_entry_does_not_erase_earlier_or_later_results(self) -> None:
        for name in (".staging-a", ".staging-b", ".staging-c"):
            path = self.root / name
            path.mkdir()
            (path / "payload").write_bytes(name.encode())
        blocked = self.root / ".staging-b"
        before = blocked.stat()
        blocked.chmod(0)
        try:
            try:
                fd = os.open(blocked, os.O_RDONLY)
            except PermissionError as error:
                self.assertEqual(error.errno, errno.EACCES)
            else:
                os.close(fd)
                self.skipTest("account can bypass mode000 permissions")
            self.assertEqual(
                packager.recover_sweep(str(self.root)),
                ([".staging-a", ".staging-c"], [".staging-b"]),
            )
            after = blocked.stat()
            self.assertEqual(
                (before.st_dev, before.st_ino), (after.st_dev, after.st_ino)
            )
            self.assertEqual(stat.S_IMODE(after.st_mode), 0)
        finally:
            blocked.chmod(0o700)
        self.assertEqual((blocked / "payload").read_bytes(), b".staging-b")

    def test_staging_name_already_holds_lock_at_creation_hook(self) -> None:
        evidence, output = self.root / "evidence", self.root / "output"
        evidence.mkdir()
        output.mkdir()
        (evidence / "payload").write_bytes(b"evidence")
        witnesses: list[str] = []

        def pause(point: str, parent: str, name: str) -> None:
            if point != "after_staging_created":
                return
            staging = [p for p in output.iterdir() if p.name.startswith(".staging-")]
            self.assertEqual(len(staging), 1)
            target = staging[0]
            before = target.stat()
            fd = os.open(target, os.O_RDONLY | os.O_DIRECTORY)
            try:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError as error:
                    self.assertIn(error.errno, (errno.EAGAIN, errno.EACCES))
                else:
                    self.fail("staging name was visible before its producer lock")
            finally:
                os.close(fd)
            self.assertEqual(packager.recover_sweep(str(output)), ([], [target.name]))
            after = target.stat()
            self.assertEqual(
                (before.st_dev, before.st_ino), (after.st_dev, after.st_ino)
            )
            witnesses.append(target.name)

        with patch.object(packager, "_pause", pause):
            result = packager.pack(str(evidence), str(output), "bundle")
        self.assertEqual(len(witnesses), 1)
        self.assertEqual((output / "bundle" / "payload").read_bytes(), b"evidence")
        self.assertEqual(result["file_count"], 1)

    def test_reservations_are_reported_without_being_opened(self) -> None:
        reservation = self.root / ".reserve-protected"
        reservation.mkdir()
        (reservation / "payload").write_bytes(b"reservation")
        before = reservation.stat()
        original = os.open
        attempts: list[str] = []

        def observed(
            path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
            flags: int,
            mode: int = 0o777,
            *,
            dir_fd: int | None = None,
        ) -> int:
            if os.fspath(path) == str(reservation):
                attempts.append(os.fsdecode(path))
            return original(path, flags, mode, dir_fd=dir_fd)

        with patch.object(os, "open", observed):
            self.assertEqual(
                packager.recover_sweep(str(self.root)), ([], [reservation.name])
            )
        self.assertEqual(attempts, [])
        after = reservation.stat()
        self.assertEqual((before.st_dev, before.st_ino), (after.st_dev, after.st_ino))
        self.assertEqual((reservation / "payload").read_bytes(), b"reservation")


def _load_recorder_checks() -> Any:
    spec = importlib.util.spec_from_file_location(
        "recorder_checks",
        Path(__file__).resolve().parent.parent / "recorder-checks.py",
    )
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def _stub_checks(rc: Any, ran: list[str], fail: set[str] | None = None) -> None:
    def make(label: str) -> Callable[[str], str]:
        def run(t: str) -> str:
            os.rmdir(t)
            ran.append(label)
            if fail and label in fail:
                raise RuntimeError(f"{label} stub failure")
            return "stub"

        return run

    rc.CHECKS[:] = [
        ("R1 stub one", make("R1")),
        ("R10 stub ten", make("R10")),
        ("R3 stub three", make("R3")),
    ]


class RecorderSkipRegressions(unittest.TestCase):
    """Pin RECORDER_CHECKS_SKIP, CI's R10-only exclusion mechanism."""

    def test_unknown_skip_name_refuses_the_run(self) -> None:
        rc = _load_recorder_checks()
        ran: list[str] = []
        _stub_checks(rc, ran)
        err = io.StringIO()
        with patch.dict(os.environ, {"RECORDER_CHECKS_SKIP": "R1O"}):
            with contextlib.redirect_stderr(err):
                result = rc.main()
        self.assertEqual(result, 2)
        self.assertIn("REFUSED", err.getvalue())
        self.assertIn("R1O", err.getvalue())
        self.assertEqual(ran, [])

    def test_known_non_r10_skip_name_refuses_the_run(self) -> None:
        rc = _load_recorder_checks()
        ran: list[str] = []
        _stub_checks(rc, ran)
        err = io.StringIO()
        with patch.dict(os.environ, {"RECORDER_CHECKS_SKIP": "R1"}):
            with contextlib.redirect_stderr(err):
                result = rc.main()
        self.assertEqual(result, 2)
        self.assertIn("REFUSED", err.getvalue())
        self.assertIn("R1", err.getvalue())
        self.assertEqual(ran, [])

    def test_r10_skip_excludes_only_r10_without_running_it(self) -> None:
        rc = _load_recorder_checks()
        ran: list[str] = []
        _stub_checks(rc, ran)
        out = io.StringIO()
        with patch.dict(os.environ, {"RECORDER_CHECKS_SKIP": "R10"}):
            with contextlib.redirect_stdout(out):
                result = rc.main()
        self.assertEqual(result, 0)
        self.assertEqual(ran, ["R1", "R3"])
        self.assertIn(
            "SKIP R10 stub ten: skipped by RECORDER_CHECKS_SKIP", out.getvalue()
        )
        self.assertIn("no qualification claimed", out.getvalue())
        self.assertIn("3 checks, 0 failures, 1 skipped", out.getvalue())

    def test_unset_variable_runs_every_check_full_default(self) -> None:
        rc = _load_recorder_checks()
        ran: list[str] = []
        _stub_checks(rc, ran)
        out = io.StringIO()
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("RECORDER_CHECKS_SKIP", None)
            with contextlib.redirect_stdout(out):
                result = rc.main()
        self.assertEqual(result, 0)
        self.assertEqual(ran, ["R1", "R10", "R3"])
        self.assertIn("3 checks, 0 failures, 0 skipped", out.getvalue())

    def test_real_failures_propagate_with_r10_skipped(self) -> None:
        rc = _load_recorder_checks()
        ran: list[str] = []
        _stub_checks(rc, ran, fail={"R3"})
        out = io.StringIO()
        with patch.dict(os.environ, {"RECORDER_CHECKS_SKIP": "R10"}):
            with contextlib.redirect_stdout(out):
                result = rc.main()
        self.assertEqual(result, 1)
        self.assertEqual(ran, ["R1", "R3"])
        self.assertIn("FAIL R3 stub three: R3 stub failure", out.getvalue())
        self.assertIn("3 checks, 1 failures, 1 skipped", out.getvalue())


class RecorderGateCleanupRegression(unittest.TestCase):
    def test_every_check_directory_is_removed_pass_or_fail(self) -> None:
        rc = _load_recorder_checks()
        made: list[str] = []

        def leave_files(t: str) -> str:
            made.append(t)
            Path(t, "left.txt").write_text("left by a check\n")
            return "stub"

        def fail(t: str) -> str:
            leave_files(t)
            raise RuntimeError("stub failure")

        rc.CHECKS[:] = [("R1 stub one", leave_files), ("R2 stub two", fail)]
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("RECORDER_CHECKS_SKIP", None)
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(rc.main(), 1)
        self.assertEqual([os.path.exists(t) for t in made], [False, False])


class PublishedPathRegressions(unittest.TestCase):
    """Only the exact published directory validates."""

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="litmus-regression-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.evidence = self.root / "evidence"
        self.evidence.mkdir()
        (self.evidence / "a.txt").write_bytes(b"alpha\n")

    def test_complete_staging_from_a_crash_and_its_verdict_are_refused(
        self,
    ) -> None:
        import verifier

        output = self.root / "output"
        output.mkdir()
        proc = subprocess.Popen(
            [
                sys.executable,
                packager.__file__,
                str(self.evidence),
                str(output),
                "bundle-x",
            ],
            env=dict(os.environ, C1C2_PAUSE_AT="after_manifest"),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            ready = output / ".sync-bundle-x-after_manifest.ready"
            deadline = time.monotonic() + 30
            while not ready.exists():
                self.assertIsNone(
                    proc.poll(), "producer exited before complete staging"
                )
                self.assertLess(time.monotonic(), deadline, "producer pause timed out")
                time.sleep(0.02)
            proc.kill()
            proc.communicate(timeout=30)
            self.assertEqual(proc.returncode, -signal.SIGKILL)
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.communicate(timeout=30)
        self.assertFalse((output / "bundle-x").exists())
        staging = [p for p in output.iterdir() if p.name.startswith(".staging-")]
        self.assertEqual(len(staging), 1)
        self.assertTrue((staging[0] / "manifest.json").is_file())
        result = verifier.verify(str(staging[0]))
        self.assertEqual(result["verdict"], "INVALID")
        self.assertIn("not the declared bundle name", "; ".join(result["reasons"]))
        # A verdict as the unfixed verifier issued it for this staging.
        manifest = (staging[0] / "manifest.json").read_bytes()
        stored = verifier._verdict(
            "VALID",
            "bundle-x",
            str(staging[0]),
            hashlib.sha256(manifest).hexdigest(),
            [],
        )
        verdict_path = self.root / "verdict.json"
        verdict_path.write_text(json.dumps(stored))
        accepted, reasons = verifier.check_verdict(str(staging[0]), str(verdict_path))
        self.assertFalse(accepted)
        self.assertIn("bundle no longer validates", "; ".join(reasons))

    def test_the_published_bundle_still_validates_and_its_verdict_is_accepted(
        self,
    ) -> None:
        import verifier

        output = self.root / "output"
        output.mkdir()
        packager.pack(str(self.evidence), str(output), "bundle-x")
        published = str(output / "bundle-x")
        result = verifier.verify(published)
        self.assertEqual(result["verdict"], "VALID", result["reasons"])
        verdict_path = self.root / "verdict.json"
        verdict_path.write_text(json.dumps(result))
        self.assertEqual(
            verifier.check_verdict(published, str(verdict_path)), (True, [])
        )


class OwnStagingRegressions(unittest.TestCase):
    """Synthetic per-attempt faults; real crash/write-error witnesses stay separate."""

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="litmus-own-stage-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.evidence = self.root / "evidence"
        self.output = self.root / "output"
        self.evidence.mkdir()
        self.output.mkdir()
        (self.evidence / "payload").write_bytes(b"source")
        self.original = OSError(errno.EIO, "original write failure")

    def pack(self) -> dict[str, object]:
        return packager.pack(str(self.evidence), str(self.output), "bundle")

    def stage(self) -> Path:
        paths = list(self.output.glob(".staging-*"))
        self.assertEqual(len(paths), 1)
        return paths[0]

    def test_invalid_input_allocates_nothing(self) -> None:
        (self.evidence / "manifest.json").write_text("reserved")
        with patch.object(
            packager, "_locked_staging", wraps=packager._locked_staging
        ) as allocation:
            with self.assertRaisesRegex(ValueError, "reserved name"):
                self.pack()
        allocation.assert_not_called()
        self.assertEqual(list(self.output.iterdir()), [])

    def test_normal_failure_removes_only_own_stage_under_lock(self) -> None:
        for name in (".staging-other", ".reserve-other", "unrelated"):
            directory = self.output / name
            directory.mkdir()
            (directory / "payload").write_bytes(b"keep")
        real_remove = __import__("shutil").rmtree
        other_fd = os.open(self.output / ".staging-other", os.O_RDONLY)
        self.addCleanup(os.close, other_fd)
        fcntl.flock(other_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        witnessed: list[str] = []

        def remove(path: str) -> None:
            fd = os.open(path, os.O_RDONLY)
            try:
                with self.assertRaises(BlockingIOError):
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            finally:
                os.close(fd)
            witnessed.append(path)
            real_remove(path)

        with (
            patch.object(packager, "_write_sync", side_effect=self.original),
            patch("shutil.rmtree", side_effect=remove),
        ):
            with self.assertRaises(OSError) as caught:
                self.pack()
        self.assertIs(caught.exception, self.original)
        self.assertEqual(len(witnessed), 1)
        for name in (".staging-other", ".reserve-other", "unrelated"):
            self.assertEqual((self.output / name / "payload").read_bytes(), b"keep")
        self.assertEqual((self.evidence / "payload").read_bytes(), b"source")
        self.assertEqual(len(list(self.output.iterdir())), 3)

    def test_partial_cleanup_failure_keeps_original_data_mode_and_reason(self) -> None:
        errors = io.StringIO()
        remaining: list[Path] = []

        def write(path: str, data: bytes) -> None:
            stage = Path(path).parent
            (stage / "removed").write_bytes(b"partial")
            (stage / "remaining").write_bytes(b"keep")
            stage.chmod(0o700)
            raise self.original

        def partial(path: str) -> None:
            stage = Path(path)
            (stage / "removed").unlink()
            remaining.append(stage)
            raise PermissionError(errno.EACCES, "controlled removal obstacle")

        with (
            patch.object(packager, "_write_sync", side_effect=write),
            patch("shutil.rmtree", side_effect=partial),
            contextlib.redirect_stderr(errors),
        ):
            with self.assertRaises(OSError) as caught:
                self.pack()
        self.assertIs(caught.exception, self.original)
        self.assertEqual((remaining[0] / "remaining").read_bytes(), b"keep")
        self.assertFalse((remaining[0] / "removed").exists())
        self.assertEqual(stat.S_IMODE(remaining[0].stat().st_mode), 0o700)
        self.assertIn("files may remain", errors.getvalue())
        self.assertIn("controlled removal obstacle", errors.getvalue())

    def test_cleanup_diagnostic_and_close_errors_do_not_replace_original(self) -> None:
        original_close = os.close

        def close(fd: int) -> None:
            original_close(fd)
            raise OSError("controlled close failure")

        def fail_write(path: str, data: bytes) -> None:
            # Allocation is complete, so this fault affects only final lock close.
            os.close = close
            raise self.original

        try:
            with (
                patch.object(packager, "_write_sync", side_effect=fail_write),
                patch("shutil.rmtree", side_effect=OSError("cleanup failure")),
                patch("builtins.print", side_effect=OSError("diagnostic failure")),
            ):
                with self.assertRaises(OSError) as caught:
                    self.pack()
            self.assertIs(caught.exception, self.original)
        finally:
            os.close = original_close

    def test_identity_change_or_symlink_refuses_cleanup(self) -> None:
        for symlink in (False, True):
            with self.subTest(symlink=symlink):
                moved: list[Path] = []

                def replace(
                    path: str,
                    data: bytes,
                    symlink: bool = symlink,
                    moved: list[Path] = moved,
                ) -> None:
                    stage = self.stage()
                    saved = self.root / ("held-link" if symlink else "held-dir")
                    stage.rename(saved)
                    moved.append(saved)
                    if symlink:
                        stage.symlink_to(saved, target_is_directory=True)
                    else:
                        stage.mkdir()
                        (stage / "replacement").write_bytes(b"keep")
                    raise self.original

                with (
                    patch.object(packager, "_write_sync", side_effect=replace),
                    patch("shutil.rmtree") as remove,
                    contextlib.redirect_stderr(io.StringIO()),
                ):
                    with self.assertRaises(OSError) as caught:
                        self.pack()
                self.assertIs(caught.exception, self.original)
                remove.assert_not_called()
                stage = self.stage()
                if symlink:
                    self.assertTrue(stage.is_symlink())
                    stage.unlink()
                else:
                    self.assertEqual((stage / "replacement").read_bytes(), b"keep")
                    (stage / "replacement").unlink()
                    stage.rmdir()
                moved[0].rmdir()

    def test_interrupt_and_system_exit_do_not_attempt_removal(self) -> None:
        for exception in (KeyboardInterrupt(), SystemExit(3)):
            with self.subTest(exception=type(exception).__name__):
                with (
                    patch.object(packager, "_write_sync", side_effect=exception),
                    patch("shutil.rmtree") as remove,
                ):
                    with self.assertRaises(type(exception)):
                        self.pack()
                remove.assert_not_called()
                self.stage().rmdir()

    def test_success_and_postpublish_close_error_never_remove_published(self) -> None:
        self.pack()
        self.assertEqual((self.output / "bundle" / "payload").read_bytes(), b"source")
        original_close = os.close
        original_rename = packager._rename_noreplace
        changed = False

        def close(fd: int) -> None:
            original_close(fd)
            raise OSError("postpublish close failure")

        def rename(src: str, dst: str) -> None:
            nonlocal changed
            original_rename(src, dst)
            os.close = close
            changed = True

        try:
            with (
                patch.object(packager, "_rename_noreplace", side_effect=rename),
                patch("shutil.rmtree") as remove,
            ):
                with self.assertRaisesRegex(OSError, "postpublish close failure"):
                    packager.pack(str(self.evidence), str(self.output), "bundle-two")
            self.assertTrue(changed)
            remove.assert_not_called()
            self.assertEqual(
                (self.output / "bundle-two" / "payload").read_bytes(), b"source"
            )
        finally:
            os.close = original_close

    def test_inspection_refusal_and_allocation_failure_do_not_remove(self) -> None:
        with (
            patch.object(
                packager, "_locked_staging", side_effect=OSError("allocation failure")
            ),
            patch("shutil.rmtree") as remove,
        ):
            with self.assertRaisesRegex(OSError, "allocation failure"):
                self.pack()
        remove.assert_not_called()
        original_fstat = os.fstat

        def write(path: str, data: bytes) -> None:
            os.fstat = lambda fd: (_ for _ in ()).throw(OSError("inspection failure"))
            raise self.original

        try:
            with (
                patch.object(packager, "_write_sync", side_effect=write),
                patch("shutil.rmtree") as remove,
                contextlib.redirect_stderr(io.StringIO()),
            ):
                with self.assertRaises(OSError) as caught:
                    self.pack()
            self.assertIs(caught.exception, self.original)
            remove.assert_not_called()
            self.assertTrue(self.stage().is_dir())
        finally:
            os.fstat = original_fstat

    def test_postpublish_fsync_warning_and_manual_result_unchanged(self) -> None:
        original = packager._fsync_dir

        def fsync(path: str) -> None:
            if path == str(self.output):
                raise OSError("postpublish fsync failure")
            original(path)

        with (
            patch.object(packager, "_fsync_dir", side_effect=fsync),
            patch("shutil.rmtree") as remove,
            contextlib.redirect_stderr(io.StringIO()) as errors,
        ):
            result = self.pack()
        remove.assert_not_called()
        self.assertEqual(result["bundle"], "bundle")
        self.assertEqual((self.output / "bundle" / "payload").read_bytes(), b"source")
        self.assertIn("post-publish fsync failed", errors.getvalue())
        (self.output / ".staging-residue").mkdir()
        (self.output / ".reserve-protected").mkdir()
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            status = packager.main(["packager.py", "--recover-sweep", str(self.output)])
        self.assertEqual(status, 0)
        self.assertEqual(
            json.loads(stdout.getvalue()),
            {
                "recovered_staging": [".staging-residue"],
                "skipped_staging": [".reserve-protected"],
            },
        )
        self.assertIn("protected reservation", stderr.getvalue())

    def test_unprintable_cleanup_and_close_errors_keep_original(self) -> None:
        class UnprintableError(Exception):
            def __str__(self) -> str:
                raise RuntimeError("controlled formatting failure")

        original_close = os.close

        def close(fd: int) -> None:
            original_close(fd)
            raise UnprintableError()

        def write(path: str, data: bytes) -> None:
            os.close = close
            raise self.original

        try:
            with (
                patch.object(packager, "_write_sync", side_effect=write),
                patch("shutil.rmtree", side_effect=UnprintableError()),
            ):
                with self.assertRaises(OSError) as caught:
                    self.pack()
            self.assertIs(caught.exception, self.original)
        finally:
            os.close = original_close

    def test_callers_active_exception_does_not_hide_postpublish_close_error(
        self,
    ) -> None:
        original_close = os.close
        original_rename = packager._rename_noreplace

        def close(fd: int) -> None:
            original_close(fd)
            raise OSError("postpublish close failure")

        def rename(src: str, dst: str) -> None:
            original_rename(src, dst)
            os.close = close

        try:
            try:
                raise ValueError("caller's handled exception")
            except ValueError:
                with (
                    patch.object(packager, "_rename_noreplace", side_effect=rename),
                    patch("shutil.rmtree") as remove,
                ):
                    with self.assertRaisesRegex(OSError, "postpublish close failure"):
                        self.pack()
                remove.assert_not_called()
                self.assertEqual(
                    (self.output / "bundle" / "payload").read_bytes(), b"source"
                )
        finally:
            os.close = original_close

    def test_interrupts_win_over_secondary_close_error_without_cleanup(self) -> None:
        original_close = os.close

        def close(fd: int) -> None:
            original_close(fd)
            raise OSError("secondary close failure")

        for exception in (KeyboardInterrupt(), SystemExit(3)):

            def write(
                path: str, data: bytes, exception: BaseException = exception
            ) -> None:
                os.close = close
                raise exception

            try:
                with (
                    patch.object(packager, "_write_sync", side_effect=write),
                    patch("shutil.rmtree") as remove,
                    contextlib.redirect_stderr(io.StringIO()),
                ):
                    with self.assertRaises(type(exception)) as caught:
                        self.pack()
                self.assertIs(caught.exception, exception)
                remove.assert_not_called()
                self.stage().rmdir()
            finally:
                os.close = original_close


REPO = Path(__file__).resolve().parent.parent


def _unprivileged(case: unittest.TestCase) -> None:
    if os.geteuid() == 0:
        case.skipTest("unprivileged account required")


def _gone(pid: int, wait: float = 5.0) -> bool:
    deadline = time.monotonic() + wait
    while True:
        try:
            with open(f"/proc/{pid}/stat") as f:
                state = f.read().rsplit(")", 1)[1].split()[0]
        except FileNotFoundError:
            return True
        if state == "Z" or time.monotonic() > deadline:
            return state == "Z"
        time.sleep(0.05)


def _crash_staging(evidence: Path, output: Path, name: str) -> Path:
    """Complete unpublished staging left by a real SIGKILL after the manifest."""
    proc = subprocess.Popen(
        [sys.executable, packager.__file__, str(evidence), str(output), name],
        env=dict(os.environ, C1C2_PAUSE_AT="after_manifest"),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        ready = output / f".sync-{name}-after_manifest.ready"
        deadline = time.monotonic() + 30
        while not ready.exists():
            assert proc.poll() is None, "producer exited before complete staging"
            assert time.monotonic() < deadline, "producer pause timed out"
            time.sleep(0.02)
    finally:
        proc.kill()
        proc.wait(timeout=30)
    (staging,) = output.glob(f".staging-{name}-*")
    return staging


class PathResolutionRegressions(unittest.TestCase):
    """A '..' after a symlink: the path checked, read and reported is one path."""

    def setUp(self) -> None:
        temp = tempfile.TemporaryDirectory(prefix="litmus-paths-")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.evidence = self.root / "evidence"
        self.evidence.mkdir()
        (self.evidence / "a.txt").write_bytes(b"alpha\n")

    def hop(self, target: Path) -> Path:
        """Raw path to target's parent through a symlink; abspath says elsewhere."""
        (self.root / "elsewhere").mkdir()
        (self.root / "elsewhere" / "hop").symlink_to(target)
        return self.root / "elsewhere" / "hop" / ".."

    def test_dotdot_after_a_symlink_cannot_validate_crash_staging(self) -> None:
        import verifier

        output = self.root / "output"
        output.mkdir()
        staging = _crash_staging(self.evidence, output, "bundle-x")
        alias = self.root / "alias"
        (alias / "any").mkdir(parents=True)
        (alias / "bundle-x").symlink_to(staging, target_is_directory=True)
        result = verifier.verify(str(self.hop(alias / "any") / "bundle-x"))
        self.assertEqual(result["verdict"], "INVALID", result)

    def test_verdict_names_the_directory_it_checked(self) -> None:
        import verifier

        output = self.root / "output"
        (output / "deep").mkdir(parents=True)
        packager.pack(str(self.evidence), str(output), "bundle-x")
        result = verifier.verify(str(self.hop(output / "deep") / "bundle-x"))
        self.assertEqual(result["bundle_path"], str(self.root / "elsewhere/bundle-x"))
        self.assertEqual(result["verdict"], "INVALID", result)
        self.assertIn("absent", "; ".join(result["reasons"]))

    def test_reported_published_path_holds_the_bundle(self) -> None:
        import verifier

        output = self.root / "output"
        (output / "deep").mkdir(parents=True)
        out_parent = str(self.hop(output / "deep"))
        published = str(packager.pack(str(self.evidence), out_parent, "z")["published"])
        self.assertTrue(os.path.isdir(published), published)
        self.assertEqual(verifier.verify(published)["verdict"], "VALID")


class BundleEntryRegressions(unittest.TestCase):
    """Every entry is read or refused by name: no crash, no silent skip."""

    def setUp(self) -> None:
        _unprivileged(self)
        temp = tempfile.TemporaryDirectory(prefix="litmus-entries-")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.evidence = self.root / "evidence"
        self.evidence.mkdir()
        (self.evidence / "a.txt").write_bytes(b"alpha\n")
        (self.evidence / "b.txt").write_bytes(b"beta\n")

    def test_unreadable_bundle_entries_are_invalid_not_a_crash(self) -> None:
        import verifier

        packager.pack(str(self.evidence), str(self.root), "bundle-u")
        bundle = self.root / "bundle-u"
        for target, restore, reason in (
            (bundle, 0o755, "manifest.json could not be inspected"),
            (bundle / "b.txt", 0o644, "listed file unreadable: b.txt"),
        ):
            with self.subTest(target=target.name):
                target.chmod(0)
                try:
                    if os.access(target, os.R_OK):
                        self.skipTest("account bypasses mode 000")
                    result = verifier.verify(str(bundle))
                finally:
                    target.chmod(restore)
                self.assertEqual(result["verdict"], "INVALID")
                self.assertIn(reason, "; ".join(result["reasons"]))

    def test_empty_evidence_directory_is_refused_before_staging(self) -> None:
        (self.evidence / "empty").mkdir()
        with self.assertRaisesRegex(ValueError, "empty evidence directory refused"):
            packager.pack(str(self.evidence), str(self.root), "bundle-e")
        self.assertEqual(sorted(p.name for p in self.root.iterdir()), ["evidence"])

    def test_unlisted_empty_directory_makes_a_bundle_invalid(self) -> None:
        import verifier

        packager.pack(str(self.evidence), str(self.root), "bundle-e")
        (self.root / "bundle-e" / "extra" / "empty").mkdir(parents=True)
        result = verifier.verify(str(self.root / "bundle-e"))
        self.assertEqual(result["verdict"], "INVALID")
        self.assertIn(
            "unexpected empty directory in bundle: extra/empty", result["reasons"]
        )


@contextlib.contextmanager
def _recorder_handlers(recorder: Any) -> Iterator[None]:
    previous: dict[signal.Signals, Any] = {
        s: signal.getsignal(s) for s in recorder.INTERRUPT_SIGNALS
    }
    for s in recorder.INTERRUPT_SIGNALS:
        signal.signal(s, recorder._raise_interrupted)
    try:
        yield
    finally:
        for s, handler in previous.items():
            signal.signal(s, signal.SIG_DFL if handler is None else handler)


class RecorderRegressions(unittest.TestCase):
    """Real signals and real OS errors at controlled points of a real run."""

    def setUp(self) -> None:
        _unprivileged(self)
        temp = tempfile.TemporaryDirectory(prefix="litmus-recorder-")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)

    def main(self, receipt: Path, *command: str) -> tuple[int, str]:
        import recorder

        err = io.StringIO()
        argv = ["recorder.py", str(receipt), "--cwd", str(self.root)]
        argv += ["--commit", "d" * 40, "--", *command]
        with (
            _recorder_handlers(recorder),
            contextlib.redirect_stdout(io.StringIO()),
            contextlib.redirect_stderr(err),
        ):
            status = recorder.main(argv)
        return status, err.getvalue()

    def test_second_interrupt_cannot_skip_the_group_kill(self) -> None:
        import recorder

        pidfile = self.root / "run.pid"
        real_kill = recorder._kill_group
        calls: list[int] = []

        def kill_group(pid: int) -> None:
            calls.append(pid)
            if len(calls) == 1:
                # A second real interrupt lands before the first kill runs.
                signal.raise_signal(signal.SIGTERM)
            real_kill(pid)

        command = f"echo $$ > '{pidfile}'; kill -INT $PPID; exec sleep 30"
        run = 0
        try:
            with (
                _recorder_handlers(recorder),
                patch.object(recorder, "_kill_group", kill_group),
                self.assertRaises(recorder.Interrupted),
            ):
                recorder.record(
                    str(self.root / "r.json"),
                    ["sh", "-c", command],
                    str(self.root),
                    30.0,
                    "d" * 40,
                )
            run = int(pidfile.read_text())
            self.assertTrue(_gone(run), "the run outlived the interrupted recorder")
            self.assertFalse((self.root / "r.json").exists())
        finally:
            if run and not _gone(run, 0):
                os.killpg(run, signal.SIGKILL)

    def test_ignore_files_outside_the_repository_hide_no_untracked_file(self) -> None:
        excludes = self.root / "excludes"
        excludes.write_text("*.py\n")
        home = self.root / "home"
        (home / ".config" / "git").mkdir(parents=True)
        (home / ".config" / "git" / "ignore").write_text("*.py\n")
        env = {k: v for k, v in os.environ.items() if k != "XDG_CONFIG_HOME"}
        for label, extra_env, config in (
            ("core.excludesFile", {}, ["core.excludesFile", str(excludes)]),
            ("user ignore file", {"HOME": str(home)}, []),
        ):
            with self.subTest(label):
                repo = self.root / label.replace(" ", "-")
                repo.mkdir()
                run_env = dict(env, **extra_env)

                def git(
                    *args: str, repo: Path = repo, run_env: dict[str, str] = run_env
                ) -> None:
                    subprocess.run(
                        ["git", "-C", str(repo), *args],
                        check=True,
                        capture_output=True,
                        env=run_env,
                    )

                git("init", "-q")
                git("config", "user.email", "gate@example.invalid")
                git("config", "user.name", "Gate")
                (repo / "tracked.txt").write_text("tracked\n")
                git("add", "tracked.txt")
                git("commit", "-q", "-m", "init")
                if config:
                    git("config", *config)
                (repo / "untracked.py").write_text("print('not committed')\n")
                receipt = self.root / f"{repo.name}.json"
                subprocess.run(
                    [
                        sys.executable,
                        str(REPO / "recorder.py"),
                        str(receipt),
                        "--cwd",
                        str(repo),
                        "--",
                        "true",
                    ],
                    check=True,
                    capture_output=True,
                    env=run_env,
                )
                self.assertIs(json.loads(receipt.read_text())["worktree_clean"], False)

    def test_interrupt_after_publication_reports_the_published_receipt(self) -> None:
        receipt = self.root / "r.json"
        real_link = os.link

        def link(src: str, dst: str) -> None:
            real_link(src, dst)
            if dst == str(receipt):
                signal.raise_signal(signal.SIGTERM)  # real, just after the link

        with patch.object(os, "link", link):
            status, err = self.main(receipt, "true")
        self.assertEqual(status, 128 + signal.SIGTERM)
        self.assertTrue(receipt.exists())
        self.assertNotIn("no receipt", err)
        self.assertIn("receipt was published", err)

    def test_cleanup_failure_after_publication_keeps_the_run_result(self) -> None:
        receipt = self.root / "r.json"
        real_link = os.link
        locked: list[Path] = []

        def link(src: str, dst: str) -> None:
            real_link(src, dst)
            if dst == str(receipt):
                locked.append(Path(src).parent)
                locked[0].chmod(0o500)  # real EACCES for the cleanup that follows

        try:
            with patch.object(os, "link", link):
                status, err = self.main(receipt, "sh", "-c", "exit 3")
        finally:
            for staging in locked:
                staging.chmod(0o700)
        self.assertEqual(status, 3, err)
        self.assertTrue(receipt.exists())
        self.assertIn("staging cleanup failed after publish", err)

    def test_record_leaves_no_descriptor_open(self) -> None:
        import recorder

        before = set(os.listdir("/proc/self/fd"))
        recorder.record(
            str(self.root / "r.json"), ["true"], str(self.root), None, "d" * 40
        )
        self.assertEqual(set(os.listdir("/proc/self/fd")), before)

    def test_receipt_link_failure_is_reported_not_its_cleanup_failure(self) -> None:
        import recorder

        parent = self.root / "receipts"
        parent.mkdir()
        receipt = parent / "r.json"
        real_link = os.link

        def link(src: str, dst: str) -> None:
            if dst == str(receipt):
                parent.chmod(0o555)  # real EACCES for this link and the log cleanup
            real_link(src, dst)

        try:
            with (
                patch.object(os, "link", link),
                contextlib.redirect_stderr(io.StringIO()),
                self.assertRaises(OSError) as caught,
            ):
                recorder.record(str(receipt), ["true"], str(self.root), None, "d" * 40)
        finally:
            parent.chmod(0o755)
        self.assertEqual(caught.exception.filename2, str(receipt))


def _load_checks() -> Any:
    spec = importlib.util.spec_from_file_location("litmus_checks", REPO / "checks.py")
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def _mutant(directory: Path, name: str, *edits: tuple[str, str]) -> Path:
    """A copy of a tool carrying one defect a gate check exists to catch."""
    text = (REPO / name).read_text()
    for old, new in edits:
        assert text.count(old) == 1, old
        text = text.replace(old, new)
    path = directory / name
    path.write_text(text)
    return path


class GateWitnessRegressions(unittest.TestCase):
    """Each check fails against a tool with the defect its PASS line rules out."""

    def setUp(self) -> None:
        _unprivileged(self)
        temp = tempfile.TemporaryDirectory(prefix="litmus-witness-")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)

    def workdir(self) -> str:
        return tempfile.mkdtemp(prefix="gate-", dir=self.root)

    def test_f3_fails_when_a_refused_republish_changes_the_bundle(self) -> None:
        checks = _load_checks()
        refusal = (
            '        raise ValueError(f"published path already exists: {published}")'
        )
        damage = (
            '        with open(os.path.join(published, "evidence-1.log"), "ab") as f:\n'
            '            f.write(b"changed by a refused republish\\n")\n'
        )
        mutant = _mutant(self.root, "packager.py", (refusal, damage + refusal))
        with patch.object(checks, "PACKAGER", str(mutant)):
            with self.assertRaises(AssertionError):
                checks.f3(self.workdir())

    def test_c1d_fails_when_staging_precedes_the_name_check(self) -> None:
        checks = _load_checks()
        name_check = (
            "    if not valid_bundle_name(bundle_name):\n"
            '        raise ValueError(f"invalid bundle name: {bundle_name!r}")\n'
        )
        start = "    published_ok = False\n    try:\n"
        late = (
            "        if not valid_bundle_name(bundle_name):\n"
            '            raise ValueError(f"invalid bundle name: {bundle_name!r}")\n'
        )
        mutant = _mutant(
            self.root, "packager.py", (name_check, ""), (start, start + late)
        )
        with patch.object(checks, "PACKAGER", str(mutant)):
            with self.assertRaises(AssertionError):
                checks.c1d(self.workdir())

    def test_c1e_fails_when_evidence_is_read_before_the_device_check(self) -> None:
        checks = _load_checks()
        if checks.SECOND_FS is None:
            self.skipTest("no second filesystem")
        first_check = (
            "        # Same-filesystem guarantee, asserted with real device numbers before\n"
            "        # any write and again before the rename.\n"
            "        if os.stat(staging).st_dev != os.stat(out_parent).st_dev:\n"
            '            raise ValueError("cross-filesystem staging rejected")\n'
        )
        mutant = _mutant(self.root, "packager.py", (first_check, ""))
        spec = importlib.util.spec_from_file_location("packager", mutant)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with patch.dict(sys.modules, {"packager": module}):
            with self.assertRaises(AssertionError):
                checks.c1e(self.workdir())

    def test_c1e_leaves_second_filesystem_entries_it_did_not_create(self) -> None:
        checks = _load_checks()
        if checks.SECOND_FS is None:
            self.skipTest("no second filesystem")
        foreign = Path(
            tempfile.mkdtemp(prefix=".staging-bundle-c1e-", dir=checks.SECOND_FS)
        )

        def remove_foreign() -> None:
            if foreign.is_dir():
                foreign.rmdir()

        self.addCleanup(remove_foreign)
        checks.c1e(self.workdir())
        self.assertTrue(foreign.is_dir(), "C1-e removed another run's directory")

    def test_r7_fails_on_timestamps_that_are_not_utc(self) -> None:
        rc = _load_recorder_checks()
        mutant = _mutant(
            self.root,
            "recorder.py",
            (
                "    return datetime.now(timezone.utc).isoformat()",
                "    return datetime.now(timezone(timedelta(hours=5))).isoformat()",
            ),
            (
                "from datetime import datetime, timezone",
                "from datetime import datetime, timedelta, timezone",
            ),
        )
        with patch.object(rc, "RECORDER", str(mutant)):
            with self.assertRaises(AssertionError):
                rc.r7(self.workdir())


class AssertionsDisabledRegressions(unittest.TestCase):
    """Both gates refuse to run under python -O / PYTHONOPTIMIZE: a PASS
    line printed with assertions stripped would certify nothing."""

    def test_gates_refuse_when_assertions_are_disabled(self) -> None:
        env = dict(os.environ, PYTHONOPTIMIZE="1")
        for gate in ("checks.py", "recorder-checks.py"):
            r = subprocess.run(
                [sys.executable, str(REPO / gate)],
                env=env,
                capture_output=True,
                text=True,
                timeout=600,
            )
            self.assertEqual(r.returncode, 2, f"{gate}: {r.stdout} {r.stderr}")
            self.assertIn("REFUSED", r.stderr, gate)


class EvidenceIdentityRegressions(unittest.TestCase):
    """An evidence entry replaced after collection is refused. Collection
    is not a snapshot: only an in-place edit may still be read as it is."""

    def setUp(self) -> None:
        _unprivileged(self)
        temp = tempfile.TemporaryDirectory(prefix="litmus-identity-")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.evidence = self.root / "evidence"
        self.output = self.root / "output"
        self.outside = self.root / "outside"
        for d in (self.evidence, self.output, self.outside):
            d.mkdir()
        (self.evidence / "f1.log").write_bytes(b"evidence-1")
        (self.evidence / "f2.log").write_bytes(b"evidence-2")
        (self.outside / "f2.log").write_bytes(b"not evidence")

    def pack_with_swap(self, swap: Callable[[], None]) -> None:
        def pause(point: str, parent: str, name: str) -> None:
            if point == "mid_copy":
                swap()

        with patch.object(packager, "_pause", pause):
            with self.assertRaisesRegex(ValueError, "changed after collection"):
                packager.pack(str(self.evidence), str(self.output), "bundle-s")
        self.assertEqual(os.listdir(self.output), [])

    def test_file_swapped_for_a_symlink_is_refused(self) -> None:
        def swap() -> None:
            (self.evidence / "f2.log").unlink()
            (self.evidence / "f2.log").symlink_to(self.outside / "f2.log")

        self.pack_with_swap(swap)

    def test_directory_swapped_for_a_symlink_is_refused(self) -> None:
        sub = self.evidence / "sub"
        sub.mkdir()
        (sub / "c.log").write_bytes(b"evidence-c")
        outside_sub = self.outside / "sub"
        outside_sub.mkdir()
        (outside_sub / "c.log").write_bytes(b"outside c")

        def swap() -> None:
            sub.rename(self.root / "moved")
            sub.symlink_to(outside_sub, target_is_directory=True)

        self.pack_with_swap(swap)

    def test_file_renamed_into_place_is_refused(self) -> None:
        def swap() -> None:
            os.rename(self.outside / "f2.log", self.evidence / "f2.log")

        self.pack_with_swap(swap)


class RecoverSweepPathRegressions(unittest.TestCase):
    """--recover-sweep reads OUT_PARENT the way pack resolved it: one
    string through a symlinked '..' must not name two directories."""

    def setUp(self) -> None:
        _unprivileged(self)
        temp = tempfile.TemporaryDirectory(prefix="litmus-sweeppath-")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)

    def test_sweep_acts_where_pack_staged(self) -> None:
        pub = self.root / "pub"
        (pub / "deep").mkdir(parents=True)
        elsewhere = self.root / "elsewhere"
        elsewhere.mkdir()
        (elsewhere / "hop").symlink_to(pub / "deep", target_is_directory=True)
        out_parent = elsewhere / "hop" / ".."
        # pack publishes and stages under abspath(OUT_PARENT) = elsewhere.
        residue = elsewhere / ".staging-leftover-x"
        residue.mkdir()
        foreign = pub / ".staging-foreign-x"
        foreign.mkdir()
        (foreign / "payload").write_bytes(b"not this sweep's")
        removed, _skipped = packager.recover_sweep(str(out_parent))
        self.assertIn(".staging-leftover-x", removed)
        self.assertFalse(residue.exists())
        self.assertNotIn(".staging-foreign-x", removed)
        self.assertEqual((foreign / "payload").read_bytes(), b"not this sweep's")


class WorktreeCleanRegressions(unittest.TestCase):
    """A user-level core.ignoreCase cannot fold an untracked file into a
    tracked one that differs only by case: worktree_clean stays false."""

    def setUp(self) -> None:
        _unprivileged(self)
        temp = tempfile.TemporaryDirectory(prefix="litmus-ignorecase-")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)

    def test_user_level_ignorecase_cannot_hide_an_untracked_file(self) -> None:
        repo = self.root / "repo"
        repo.mkdir()

        def git(*args: str) -> None:
            r = subprocess.run(
                ["git", "-C", str(repo), *args], capture_output=True, text=True
            )
            self.assertEqual(r.returncode, 0, r.stderr)

        git("init", "-q")
        git("config", "user.email", "x@example.invalid")
        git("config", "user.name", "x")
        (repo / "README.md").write_bytes(b"tracked")
        git("add", "README.md")
        git("commit", "-qm", "init")
        (repo / "README.MD").write_bytes(b"not committed")
        home = self.root / "home"
        home.mkdir()
        (home / ".gitconfig").write_bytes(b"[core]\n\tignoreCase = true\n")
        import recorder

        with patch.dict(os.environ, {"HOME": str(home)}):
            commit, worktree_clean = recorder.resolve_commit(str(repo), None)
        self.assertIsNotNone(commit)
        self.assertFalse(worktree_clean)


class CleanupKillRegressions(unittest.TestCase):
    """R3's cleanup signals only the exact processes that anchored
    themselves, each named by a pidfd the process opened on itself and
    passed to the gate: a passing run's cleanup signals nothing at all,
    and a reused live pid is never signalled."""

    def setUp(self) -> None:
        _unprivileged(self)
        temp = tempfile.TemporaryDirectory(prefix="litmus-cleanup-")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)

    def test_passing_r3_cleanup_signals_nothing(self) -> None:
        rc = _load_recorder_checks()
        kills: list[int] = []
        real_send = signal.pidfd_send_signal
        real_kill = os.kill

        def observed_send(fd: int, sig: int) -> None:
            if sig == signal.SIGKILL:
                kills.append(fd)
                raise ProcessLookupError  # recorded, never delivered
            real_send(fd, sig)

        def observed_kill(pid: int, sig: int) -> None:
            if sig == signal.SIGKILL:
                kills.append(pid)
                raise ProcessLookupError  # recorded, never delivered
            real_kill(pid, sig)

        t = tempfile.mkdtemp(dir=self.root)
        # Both delivery mechanisms are observed: pidfd_send_signal on this
        # design, os.kill on the previous sources, where the same passing
        # run recorded 8 SIGKILL attempts against proven-dead pids.
        with patch.object(signal, "pidfd_send_signal", observed_send):
            with patch.object(os, "kill", observed_kill):
                rc.r3(t)
        self.assertEqual(kills, [], f"cleanup signalled proven-dead pids {kills}")

    def test_anchor_names_the_sending_process(self) -> None:
        rc = _load_recorder_checks()
        sock_path = os.path.join(self.root, "anchor.sock")
        server = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        self.addCleanup(server.close)
        server.bind(sock_path)
        member = subprocess.Popen(
            [
                sys.executable,
                "-c",
                rc.anchor_payload(sock_path) + "; import time; time.sleep(30)",
            ]
        )
        self.addCleanup(member.kill)
        msg, ancdata, _flags, _addr = server.recvmsg(
            64, socket.CMSG_LEN(array.array("i").itemsize)
        )
        self.assertEqual(int(msg.decode()), member.pid)
        fds = array.array("i")
        for level, ctype, cdata in ancdata:
            if level == socket.SOL_SOCKET and ctype == socket.SCM_RIGHTS:
                fds.frombytes(cdata[: fds.itemsize])
        self.assertEqual(len(fds), 1, "anchor carried no pidfd")
        fd = int(fds[0])
        # The descriptor names the sender itself: signal 0 succeeds while
        # it lives, and once it is dead the descriptor fails
        # ProcessLookupError rather than ever naming another process.
        signal.pidfd_send_signal(fd, 0)
        member.kill()
        member.wait()
        with self.assertRaises(ProcessLookupError):
            signal.pidfd_send_signal(fd, signal.SIGKILL)
        os.close(fd)

    def test_reap_never_signals_a_reused_pid(self) -> None:
        rc = _load_recorder_checks()
        # The process a survivor entry was collected for: dead, descriptor
        # retained.
        collected = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(30)"]
        )
        self.addCleanup(collected.kill)
        dead_fd = os.pidfd_open(collected.pid)
        collected.kill()
        collected.wait()
        # An unrelated live process now standing at some pid: the entry
        # pairs its pid with the dead process's descriptor, as a reused
        # pid would.
        unrelated = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(30)"]
        )
        self.addCleanup(unrelated.kill)
        rc.reap([(unrelated.pid, dead_fd)])
        self.assertIsNone(unrelated.poll(), "cleanup signalled an unrelated reused pid")
        # Control: a valid entry for a live process is still signalled.
        live = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
        live_fd = os.pidfd_open(live.pid)
        rc.reap([(live.pid, live_fd)])
        self.assertEqual(live.wait(), -signal.SIGKILL)


class ConcurrentStagingRegressions(unittest.TestCase):
    """C1-e judges and removes only its own attempt's staging, never a
    concurrent run's staging created during the attempt."""

    def setUp(self) -> None:
        _unprivileged(self)
        temp = tempfile.TemporaryDirectory(prefix="litmus-concurrent-")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)

    def test_c1e_leaves_another_runs_staging_untouched(self) -> None:
        checks = _load_checks()
        if checks.SECOND_FS is None:
            self.skipTest("no second filesystem in this environment")
        foreign = Path(checks.SECOND_FS) / ".staging-bundle-c1e-foreignrun"
        self.addCleanup(lambda: shutil.rmtree(foreign, ignore_errors=True))

        def pause(point: str, parent: str, name: str) -> None:
            if point == "after_staging_created" and not foreign.exists():
                foreign.mkdir()

        t = tempfile.mkdtemp(dir=self.root)
        with patch.object(packager, "_pause", pause):
            checks.c1e(t)
        self.assertTrue(foreign.is_dir(), "C1-e removed another run's live staging")


class EntryPointRegression(unittest.TestCase):
    def test_main_guard_is_the_last_statement(self) -> None:
        tree = ast.parse(Path(__file__).read_text())
        guards = [
            node
            for node in tree.body
            if isinstance(node, ast.If) and "__main__" in ast.unparse(node.test)
        ]
        self.assertEqual(guards, [tree.body[-1]], "tests after the guard never run")


if __name__ == "__main__":
    unittest.main()
