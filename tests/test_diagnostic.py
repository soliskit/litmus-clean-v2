"""Diagnostic session tests. Real child commands, isolated temporary Git worktrees."""

import fcntl
import hashlib
import itertools
import json
import os
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from collections.abc import Callable
from pathlib import Path
from typing import Any
from unittest.mock import patch

import diagnostic
from local_mirror import LocalMirror


class DiagnosticTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="litmus-session-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        subprocess.run(["git", "init", "-q", str(self.repo)], check=True)
        subprocess.run(
            [
                "git",
                "-C",
                str(self.repo),
                "-c",
                "user.name=Fixture",
                "-c",
                "user.email=fixture@example.invalid",
                "commit",
                "--allow-empty",
                "-qm",
                "Fixture",
            ],
            check=True,
        )
        self.profile = self.root / "selected.json"
        self.destination = self.root / "session"

    def select(self, code: str, artifacts: list[str] | None = None) -> None:
        self.profile.write_text(
            json.dumps(
                {
                    "version": 1,
                    "repo": "fixture",
                    "check": "selected",
                    "scope": "synthetic wrapper qualification, not an app check",
                    "argv": [sys.executable, "-c", code],
                    "artifacts": artifacts or [],
                }
            )
        )

    def test_pass_records_exact_argv_and_original_log(self) -> None:
        self.select("print('observed output')")
        session, status = diagnostic.run(self.profile, self.repo, self.destination)
        receipt = json.loads((self.destination / "receipt.json").read_text())
        self.assertEqual(status, 0)
        self.assertEqual(receipt["argv"], json.loads(self.profile.read_text())["argv"])
        self.assertEqual(
            (self.destination / "receipt.json.log").read_bytes(), b"observed output\n"
        )
        self.assertEqual(
            session["receipt"]["sha256"],
            hashlib.sha256(
                (self.destination / "receipt.json").read_bytes()
            ).hexdigest(),
        )

    def test_failure_is_not_hidden_by_missing_attachment(self) -> None:
        self.select("raise SystemExit(7)", ["missing.json"])
        session, status = diagnostic.run(self.profile, self.repo, self.destination)
        self.assertEqual(status, 7)
        self.assertEqual(session["command_exit"], 7)
        self.assertEqual(session["evidence_status"], "incomplete")

    def test_success_with_missing_evidence_is_not_complete(self) -> None:
        self.select("pass", ["missing.json"])
        session, status = diagnostic.run(self.profile, self.repo, self.destination)
        self.assertEqual(status, 125)
        self.assertEqual(session["command_exit"], 0)
        self.assertEqual(session["attachments"][0]["status"], "unavailable")

    def test_native_attachment_is_copied_not_edited(self) -> None:
        original = b"native report\x00\xff"
        self.select(
            f"import pathlib; pathlib.Path('result.bin').write_bytes({original!r})",
            ["result.bin"],
        )
        session, status = diagnostic.run(self.profile, self.repo, self.destination)
        self.assertEqual(status, 0)
        attachment = session["attachments"][0]
        self.assertEqual((self.destination / attachment["path"]).read_bytes(), original)
        self.assertEqual(attachment["sha256"], hashlib.sha256(original).hexdigest())

    def test_destination_reuse_refuses_before_command(self) -> None:
        marker = self.repo / "ran"
        self.select("open('ran','w').close()")
        self.destination.mkdir()
        with self.assertRaises(FileExistsError):
            diagnostic.run(self.profile, self.repo, self.destination)
        self.assertFalse(marker.exists())

    def test_traversal_refuses_before_command(self) -> None:
        self.select("open('ran','w').close()", ["../outside"])
        with self.assertRaises(ValueError):
            diagnostic.run(self.profile, self.repo, self.destination)
        self.assertFalse((self.repo / "ran").exists())

    def test_symlink_attachment_not_followed(self) -> None:
        (self.root / "private").write_text("must not copy")
        (self.repo / "report").symlink_to(self.root / "private")
        self.select("pass", ["report"])
        session, status = diagnostic.run(self.profile, self.repo, self.destination)
        self.assertEqual(status, 125)
        self.assertEqual(session["evidence_status"], "incomplete")
        self.assertFalse((self.destination / "attachment-00.bin").exists())

    def test_symlink_parent_not_followed(self) -> None:
        (self.repo / "linked").symlink_to(self.root, target_is_directory=True)
        (self.root / "private").write_text("must not copy")
        self.select("pass", ["linked/private"])
        _, status = diagnostic.run(self.profile, self.repo, self.destination)
        self.assertEqual(status, 125)

    def test_unknown_profile_fields_refused(self) -> None:
        self.select("pass")
        profile = json.loads(self.profile.read_text())
        profile["upload"] = True
        self.profile.write_text(json.dumps(profile))
        with self.assertRaises(ValueError):
            diagnostic.run(self.profile, self.repo, self.destination)

    def test_integrity_rechecks_log_bytes(self) -> None:
        self.select("print('observed')")
        diagnostic.run(self.profile, self.repo, self.destination)
        self.assertEqual(diagnostic.verify(self.destination)["command_exit"], 0)
        (self.destination / "receipt.json.log").write_bytes(b"edited\n")
        with self.assertRaises(ValueError):
            diagnostic.verify(self.destination)

    def test_integrity_rechecks_attachment(self) -> None:
        self.select(
            "import pathlib; pathlib.Path('native').write_bytes(b'original')",
            ["native"],
        )
        diagnostic.run(self.profile, self.repo, self.destination)
        diagnostic.verify(self.destination)
        (self.destination / "attachment-00.bin").write_bytes(b"modified")
        with self.assertRaises(ValueError):
            diagnostic.verify(self.destination)

    def test_integrity_does_not_upgrade_missing_evidence(self) -> None:
        self.select("pass", ["missing"])
        diagnostic.run(self.profile, self.repo, self.destination)
        self.assertEqual(
            diagnostic.verify(self.destination)["evidence_status"], "incomplete"
        )

    def test_session_write_error_keeps_original_failure(self) -> None:
        self.select("raise SystemExit(7)")
        original = diagnostic.write_new

        def fail_session(path: Path, data: bytes) -> None:
            if path.name == "session.json":
                raise OSError("synthetic publication fault")
            original(path, data)

        with patch.object(diagnostic, "write_new", fail_session):
            session, status = diagnostic.run(self.profile, self.repo, self.destination)
        self.assertEqual(status, 7)
        self.assertTrue(session["session_write_failed"])
        self.assertEqual(session["evidence_status"], "incomplete")

    def test_tampered_summary_does_not_override_receipt(self) -> None:
        self.select("raise SystemExit(7)")
        diagnostic.run(self.profile, self.repo, self.destination)
        path = self.destination / "session.json"
        data = json.loads(path.read_text())
        data["command_exit"] = 0
        path.write_text(json.dumps(data))
        with self.assertRaises(ValueError):
            diagnostic.verify(self.destination)

    def test_tampered_attachment_census_refused(self) -> None:
        self.select("pass", ["missing"])
        diagnostic.run(self.profile, self.repo, self.destination)
        path = self.destination / "session.json"
        data = json.loads(path.read_text())
        data["attachments"] = []
        path.write_text(json.dumps(data))
        with self.assertRaises(ValueError):
            diagnostic.verify(self.destination)

    def test_explicit_timeout_records_real_kill(self) -> None:
        self.select("import time; time.sleep(10)")
        session, status = diagnostic.run(
            self.profile, self.repo, self.destination, 0.05
        )
        self.assertEqual(status, 124)
        receipt = json.loads((self.destination / "receipt.json").read_text())
        self.assertTrue(receipt["timed_out"])
        self.assertEqual(receipt["signal"], 9)
        self.assertEqual(session["command_exit"], 124)
        diagnostic.verify(self.destination)

    def test_invalid_timeout_never_starts_command(self) -> None:
        self.select("open('ran','w').close()")
        for timeout in (0, -1, float("nan"), float("inf")):
            with self.assertRaises(ValueError):
                diagnostic.run(self.profile, self.repo, self.destination, timeout)
        self.assertFalse((self.repo / "ran").exists())

    def test_noncanonical_artifact_path_refused(self) -> None:
        for path in ("a//b", "./a", "a/", "a/./b"):
            self.select("pass", [path])
            with self.assertRaises(ValueError):
                diagnostic.run(self.profile, self.repo, self.destination)
        self.assertFalse(self.destination.exists())

    def test_oversized_profile_refused_before_launch(self) -> None:
        self.profile.write_bytes(b" " * (diagnostic.MAX_PROFILE_BYTES + 1))
        with self.assertRaises(ValueError):
            diagnostic.run(self.profile, self.repo, self.destination)
        self.assertFalse(self.destination.exists())

    def test_attachment_file_budget_marks_incomplete(self) -> None:
        (self.repo / "large").write_bytes(b"12345")
        self.select("pass", ["large"])
        with patch.object(diagnostic, "MAX_ARTIFACT_BYTES", 4):
            session, status = diagnostic.run(self.profile, self.repo, self.destination)
        self.assertEqual(status, 125)
        self.assertEqual(session["attachments"][0]["status"], "unavailable")

    def test_attachment_total_budget_marks_incomplete(self) -> None:
        self.select(
            "import pathlib; pathlib.Path('a').write_bytes(b'123');"
            " pathlib.Path('b').write_bytes(b'456')",
            ["a", "b"],
        )
        with patch.object(diagnostic, "MAX_TOTAL_BYTES", 4):
            session, status = diagnostic.run(self.profile, self.repo, self.destination)
        self.assertEqual(status, 125)
        self.assertEqual(
            [a["status"] for a in session["attachments"]], ["captured", "unavailable"]
        )

    def test_cli_failure_keeps_command_status(self) -> None:
        self.select("raise SystemExit(7)")
        result = subprocess.run(
            [
                sys.executable,
                str(Path(diagnostic.__file__)),
                str(self.profile),
                str(self.destination),
                "--cwd",
                str(self.repo),
            ],
            capture_output=True,
        )
        self.assertEqual(result.returncode, 7)
        self.assertEqual(json.loads(result.stdout)["command_exit"], 7)

    def test_cli_verify_failure_is_nonzero(self) -> None:
        result = subprocess.run(
            [
                sys.executable,
                str(Path(diagnostic.__file__)),
                "--verify",
                str(self.destination),
            ],
            capture_output=True,
        )
        self.assertEqual(result.returncode, 125)

    def test_cli_interrupt_kills_live_child_without_completed_session(self) -> None:
        self.select(
            "import os,time; open('pid','w').write(str(os.getpid())); time.sleep(10)"
        )
        process = subprocess.Popen(
            [
                sys.executable,
                str(Path(diagnostic.__file__)),
                str(self.profile),
                str(self.destination),
                "--cwd",
                str(self.repo),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            deadline = time.monotonic() + 3
            marker = self.repo / "pid"
            while not marker.exists() and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertTrue(marker.exists())
            child = int(marker.read_text())
            process.send_signal(signal.SIGTERM)
            process.communicate(timeout=3)
            self.assertEqual(process.returncode, 143)
            self.assertFalse((self.destination / "session.json").exists())
            with self.assertRaises(ProcessLookupError):
                os.kill(child, 0)
        finally:
            if process.poll() is None:
                process.kill()
                process.communicate(timeout=3)

    def test_outcome_framing_refuses_missing_or_conflicting_signal(self) -> None:
        for row in (
            {"timed_out": False, "exit": None, "signal": None},
            {"timed_out": False, "exit": 0, "signal": 9},
            {"timed_out": "false", "exit": 0, "signal": None},
        ):
            with self.assertRaises(ValueError):
                diagnostic.command_status(row)

    def test_direct_argv_tamper_is_rejected(self) -> None:
        self.select("pass")
        diagnostic.run(self.profile, self.repo, self.destination)
        receipt_path = self.destination / "receipt.json"
        receipt = json.loads(receipt_path.read_text())
        receipt["argv"] = ["different"]
        receipt_path.write_text(json.dumps(receipt))
        session_path = self.destination / "session.json"
        session = json.loads(session_path.read_text())
        session["receipt"]["sha256"] = hashlib.sha256(
            receipt_path.read_bytes()
        ).hexdigest()
        session_path.write_text(json.dumps(session))
        with self.assertRaises(ValueError):
            diagnostic.verify(self.destination)

    def test_source_after_failure_does_not_hide_child_failure(self) -> None:
        self.select("raise SystemExit(7)")
        original = diagnostic.git_identity
        calls = 0

        def fail_after(path: Path) -> dict[str, object]:
            nonlocal calls
            calls += 1
            if calls == 3:
                raise ValueError("synthetic post-checkout failure")
            return original(path)

        with patch.object(diagnostic, "git_identity", fail_after):
            session, status = diagnostic.run(self.profile, self.repo, self.destination)
        self.assertEqual(status, 7)
        self.assertIsNone(session["source_after"])
        self.assertEqual(session["evidence_status"], "incomplete")

    def test_runtime_and_tool_hashes_are_explicit(self) -> None:
        self.select("pass")
        session, _ = diagnostic.run(self.profile, self.repo, self.destination)
        self.assertEqual(
            set(session["runtime"]), {"python", "system", "machine", "git"}
        )
        self.assertEqual(
            set(session["tool_files"]),
            {"diagnostic.py", "recorder.py", "local_mirror.py"},
        )
        self.assertNotIn("environment", session)

    def test_cli_verify_success(self) -> None:
        self.select("pass")
        diagnostic.run(self.profile, self.repo, self.destination)
        result = subprocess.run(
            [
                sys.executable,
                str(Path(diagnostic.__file__)),
                "--verify",
                str(self.destination),
            ],
            capture_output=True,
        )
        self.assertEqual(result.returncode, 0)
        self.assertEqual(json.loads(result.stdout)["command_exit"], 0)

    def test_optional_node_probe_failure_does_not_block_command(self) -> None:
        executable = self.root / "node"
        executable.symlink_to(sys.executable)
        self.select("print('real command ran')")
        profile = json.loads(self.profile.read_text())
        profile["argv"][0] = str(executable)
        self.profile.write_text(json.dumps(profile))
        original = subprocess.run

        def missing_probe(
            argv: list[str], **kwargs: Any
        ) -> subprocess.CompletedProcess[str]:
            if argv == ["node", "--version"]:
                raise FileNotFoundError("synthetic unavailable PATH probe")
            return original(argv, **kwargs)

        with patch.object(subprocess, "run", missing_probe):
            session, status = diagnostic.run(self.profile, self.repo, self.destination)
        self.assertEqual(status, 0)
        self.assertEqual(session["runtime"]["path_node_probe"], "unknown")
        self.assertEqual(
            (self.destination / "receipt.json.log").read_bytes(), b"real command ran\n"
        )

    def test_optional_node_probe_timeout_does_not_block_command(self) -> None:
        executable = self.root / "node"
        executable.symlink_to(sys.executable)
        self.select("pass")
        profile = json.loads(self.profile.read_text())
        profile["argv"][0] = str(executable)
        self.profile.write_text(json.dumps(profile))
        original = subprocess.run

        def timeout_probe(
            argv: list[str], **kwargs: Any
        ) -> subprocess.CompletedProcess[str]:
            if argv == ["node", "--version"]:
                raise subprocess.TimeoutExpired(argv, 5)
            return original(argv, **kwargs)

        with patch.object(subprocess, "run", timeout_probe):
            session, status = diagnostic.run(self.profile, self.repo, self.destination)
        self.assertEqual(status, 0)
        self.assertEqual(session["runtime"]["path_node_probe"], "unknown")

    def test_live_fifo_matches_small_authoritative_log(self) -> None:
        fifo = self.root / "live"
        os.mkfifo(fifo, 0o600)
        reader = os.open(fifo, os.O_RDONLY | os.O_NONBLOCK)
        try:
            self.select("print('live output')")
            session, status = diagnostic.run(
                self.profile, self.repo, self.destination, mirror_path=fifo
            )
            self.assertEqual(status, 0)
            self.assertEqual(
                os.read(reader, 65536),
                (self.destination / "receipt.json.log").read_bytes(),
            )
            self.assertEqual(session["mirror"]["status"], "complete")
        finally:
            os.close(reader)

    def test_live_fifo_backpressure_does_not_block_timeout(self) -> None:
        fifo = self.root / "live"
        os.mkfifo(fifo, 0o600)
        reader = os.open(fifo, os.O_RDONLY | os.O_NONBLOCK)
        try:
            self.select(
                "import sys,time; sys.stdout.write('x'*100000); sys.stdout.flush(); time.sleep(10)"
            )
            start = time.monotonic()
            session, status = diagnostic.run(
                self.profile, self.repo, self.destination, 0.1, fifo
            )
            self.assertEqual(status, 124)
            self.assertLess(time.monotonic() - start, 3)
            self.assertEqual(session["mirror"]["status"], "incomplete")
        finally:
            os.close(reader)

    def test_live_fifo_unavailable_preserves_command_failure(self) -> None:
        fifo = self.root / "live"
        os.mkfifo(fifo, 0o600)
        self.select("raise SystemExit(7)")
        session, status = diagnostic.run(
            self.profile, self.repo, self.destination, mirror_path=fifo
        )
        self.assertEqual(status, 7)
        self.assertEqual(session["mirror"]["status"], "incomplete")

    def test_live_regular_sink_refused_without_writing(self) -> None:
        sink = self.root / "not-fifo"
        sink.write_bytes(b"preserve")
        self.select("print('secret')")
        session, status = diagnostic.run(
            self.profile, self.repo, self.destination, mirror_path=sink
        )
        self.assertEqual(status, 0)
        self.assertEqual(sink.read_bytes(), b"preserve")
        self.assertEqual(session["mirror"]["status"], "incomplete")

    def test_live_raw_mirror_refused_in_actions(self) -> None:
        self.select("open('ran','w').close()")
        with patch.dict(os.environ, {"GITHUB_ACTIONS": "true"}):
            with self.assertRaises(ValueError):
                diagnostic.run(
                    self.profile,
                    self.repo,
                    self.destination,
                    mirror_path=self.root / "fifo",
                )
        self.assertFalse((self.repo / "ran").exists())

    def test_active_mirror_interrupt_kills_child(self) -> None:
        fifo = self.root / "live"
        os.mkfifo(fifo, 0o600)
        reader = os.open(fifo, os.O_RDONLY | os.O_NONBLOCK)
        self.select(
            "import os,time; open('pid','w').write(str(os.getpid())); print('ready',flush=True); time.sleep(10)"
        )
        process = subprocess.Popen(
            [
                sys.executable,
                str(Path(diagnostic.__file__)),
                str(self.profile),
                str(self.destination),
                "--cwd",
                str(self.repo),
                "--mirror-fifo",
                str(fifo),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            deadline = time.monotonic() + 3
            marker = self.repo / "pid"
            while not marker.exists() and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertTrue(marker.exists())
            child = int(marker.read_text())
            process.send_signal(signal.SIGTERM)
            process.communicate(timeout=3)
            self.assertEqual(process.returncode, 143)
            self.assertFalse((self.destination / "session.json").exists())
            with self.assertRaises(ProcessLookupError):
                os.kill(child, 0)
        finally:
            os.close(reader)
            if process.poll() is None:
                process.kill()
                process.communicate(timeout=3)

    def test_broken_fifo_does_not_change_shared_flags(self) -> None:
        fifo = self.root / "live"
        os.mkfifo(fifo, 0o600)
        reader = os.open(fifo, os.O_RDONLY | os.O_NONBLOCK)
        duplicate = os.dup(reader)
        before = fcntl.fcntl(reader, fcntl.F_GETFL)
        mirror = LocalMirror(fifo)
        self.assertEqual(fcntl.fcntl(duplicate, fcntl.F_GETFL), before)
        os.close(reader)
        os.close(duplicate)
        source = self.root / "captured"
        source.write_bytes(b"live bytes")
        mirror.drain(str(source))
        self.assertIsNone(mirror.fd)
        self.assertEqual(mirror.report(10)["status"], "incomplete")
        mirror.close()

    def test_final_mirror_drain_is_bounded_and_does_not_chase_growth(self) -> None:
        fifo = self.root / "live"
        os.mkfifo(fifo, 0o600)
        reader = os.open(fifo, os.O_RDONLY | os.O_NONBLOCK)
        try:
            mirror = LocalMirror(fifo)
            source = self.root / "captured"
            source.write_bytes(b"x" * (2 * 1024 * 1024))
            start = time.monotonic()
            mirror.finish(str(source))
            self.assertLess(time.monotonic() - start, 1)
            self.assertLessEqual(mirror.offset, 1024 * 1024)
            self.assertEqual(mirror.report(2 * 1024 * 1024)["status"], "incomplete")
            mirror.close()
        finally:
            os.close(reader)

    def test_ci_context_is_allowlisted_not_authenticated(self) -> None:
        context = diagnostic.ci_context(
            {
                "GITHUB_ACTIONS": "true",
                "GITHUB_REPOSITORY": "fixture/target",
                "GITHUB_RUN_ID": "12",
                "GITHUB_RUN_ATTEMPT": "2",
                "GITHUB_JOB": "selected-check",
                "GITHUB_EVENT_NAME": "pull_request",
                "GITHUB_SHA": "a" * 40,
                "SECRET": "never recorded",
            }
        )
        if context is None:
            self.fail("CI context missing")
        self.assertEqual(context["event_sha"], "a" * 40)
        self.assertNotIn("SECRET", context)
        self.assertIn("not independently authenticated", context["provenance"])

    def test_ci_event_sha_does_not_replace_checkout_commit(self) -> None:
        self.select("pass")
        with patch.dict(os.environ, {"GITHUB_ACTIONS": "true", "GITHUB_SHA": "a" * 40}):
            session, status = diagnostic.run(self.profile, self.repo, self.destination)
        self.assertEqual(status, 0)
        self.assertNotEqual(
            session["source_before"]["commit"], session["ci"]["event_sha"]
        )

    def test_invalid_ci_identity_is_not_recorded(self) -> None:
        with self.assertRaises(ValueError):
            diagnostic.ci_context({"GITHUB_ACTIONS": "true", "GITHUB_RUN_ID": "bad"})
        self.assertIsNone(diagnostic.ci_context({"GITHUB_ACTIONS": "false"}))

    def test_dirty_state_not_hidden(self) -> None:
        (self.repo / "untracked").write_text("fixture")
        self.select("pass")
        diagnostic.run(self.profile, self.repo, self.destination)
        receipt = json.loads((self.destination / "receipt.json").read_text())
        self.assertFalse(receipt["worktree_clean"])

    def good_session(
        self, code: str = "pass", artifacts: list[str] | None = None
    ) -> dict[str, Any]:
        self.select(code, artifacts)
        session, status = diagnostic.run(self.profile, self.repo, self.destination)
        self.assertEqual(status, 0)
        return session

    def edit_session(self, change: Callable[[dict[str, Any]], object]) -> None:
        session = json.loads((self.destination / "session.json").read_text())
        change(session)
        (self.destination / "session.json").write_text(
            json.dumps(session, indent=2) + "\n"
        )

    def test_stale_artifact_is_not_complete_evidence(self) -> None:
        (self.repo / "report.xml").write_text("<old-run/>")
        self.select("print('crashed before writing report')", ["report.xml"])
        session, status = diagnostic.run(self.profile, self.repo, self.destination)
        self.assertEqual(status, 125)
        self.assertEqual(session["evidence_status"], "incomplete")
        entry = session["attachments"][0]
        self.assertEqual(entry["status"], "unavailable")
        self.assertEqual(entry["reason"], "unchanged_since_launch")
        self.assertEqual(diagnostic.verify(self.destination)["command_exit"], 0)

    def test_artifact_rewritten_by_the_run_is_captured(self) -> None:
        (self.repo / "report.xml").write_text("<old-run/>")
        self.select(
            "import pathlib; pathlib.Path('report.xml').write_text('<new-run/>')",
            ["report.xml"],
        )
        session, status = diagnostic.run(self.profile, self.repo, self.destination)
        self.assertEqual(status, 0)
        self.assertEqual(session["evidence_status"], "complete")
        self.assertEqual(
            (self.destination / "attachment-00.bin").read_text(), "<new-run/>"
        )

    def test_session_with_large_argv_still_verifies(self) -> None:
        self.profile.write_text(
            json.dumps(
                {
                    "version": 1,
                    "repo": "fixture",
                    "check": "selected",
                    "scope": "synthetic wrapper qualification, not an app check",
                    "argv": ["true"] + ["x"] * 10000,
                    "artifacts": [],
                }
            )
        )
        _session, status = diagnostic.run(self.profile, self.repo, self.destination)
        self.assertEqual(status, 0)
        self.assertGreater(len((self.destination / "receipt.json").read_bytes()), 65536)
        self.assertEqual(diagnostic.verify(self.destination)["command_exit"], 0)

    def test_cli_deeply_nested_profile_is_a_typed_failure(self) -> None:
        self.profile.write_text("[" * 30000 + "]" * 30000)
        result = subprocess.run(
            [
                sys.executable,
                str(Path(diagnostic.__file__)),
                str(self.profile),
                str(self.destination),
                "--cwd",
                str(self.repo),
            ],
            capture_output=True,
        )
        self.assertEqual(result.returncode, 125)
        self.assertNotIn(b"Traceback", result.stderr)

    def test_cli_deeply_nested_session_is_a_typed_failure(self) -> None:
        self.good_session()
        (self.destination / "session.json").write_text("[" * 30000 + "]" * 30000)
        result = subprocess.run(
            [
                sys.executable,
                str(Path(diagnostic.__file__)),
                "--verify",
                str(self.destination),
            ],
            capture_output=True,
        )
        self.assertEqual(result.returncode, 125)
        self.assertNotIn(b"Traceback", result.stderr)

    def test_verify_rederives_session_invariants(self) -> None:
        self.good_session()
        original = (self.destination / "session.json").read_text()
        edits: dict[str, Callable[[dict[str, Any]], object]] = {
            "claims": lambda s: s.update(claims="Whole repo passed."),
            "complete without source_after": lambda s: s.update(source_after=None),
            "flag true while dirty": lambda s: (
                s["source_before"].update(worktree_clean=False),
                s["source_after"].update(worktree_clean=False),
            ),
            "flag flipped": lambda s: s.update(observed_clean_checkout_unchanged=False),
            "bool command_exit": lambda s: s.update(command_exit=False),
            "write failed flag": lambda s: s.update(session_write_failed=True),
        }
        for name, change in edits.items():
            with self.subTest(name):
                (self.destination / "session.json").write_text(original)
                self.edit_session(change)
                with self.assertRaises(ValueError):
                    diagnostic.verify(self.destination)

    def test_signal_killed_command_exits_128_plus_signal(self) -> None:
        self.select("import os, signal; os.kill(os.getpid(), signal.SIGKILL)")
        session, status = diagnostic.run(self.profile, self.repo, self.destination)
        self.assertEqual(session["command_exit"], 128 + signal.SIGKILL)
        self.assertEqual(status, 128 + signal.SIGKILL)

    def test_verify_refuses_unavailable_evidence_labeled_complete(self) -> None:
        self.select("pass", ["missing"])
        diagnostic.run(self.profile, self.repo, self.destination)
        self.edit_session(lambda s: s.update(evidence_status="complete"))
        with self.assertRaises(ValueError):
            diagnostic.verify(self.destination)

    def test_verify_refuses_reordered_attachments_and_budget(self) -> None:
        self.good_session(
            "import pathlib; pathlib.Path('a').write_bytes(b'1');"
            " pathlib.Path('b').write_bytes(b'2')",
            ["a", "b"],
        )
        original = (self.destination / "session.json").read_text()
        self.edit_session(
            lambda s: s.update(attachments=list(reversed(s["attachments"])))
        )
        with self.assertRaises(ValueError):
            diagnostic.verify(self.destination)
        (self.destination / "session.json").write_text(original)
        with patch.object(diagnostic, "MAX_TOTAL_BYTES", 1):
            with self.assertRaises(ValueError):
                diagnostic.verify(self.destination)

    def test_verify_rehashes_log_of_equal_size(self) -> None:
        self.good_session("print('observed output')")
        log = self.destination / "receipt.json.log"
        original = log.read_bytes()
        log.write_bytes(b"x" * len(original))
        with self.assertRaises(ValueError):
            diagnostic.verify(self.destination)

    def test_verify_refuses_changed_labels_scope_and_binding(self) -> None:
        self.good_session()
        original = (self.destination / "session.json").read_text()
        edits: dict[str, Callable[[dict[str, Any]], object]] = {
            "label": lambda s: s.update(repo_label="other"),
            "check": lambda s: s.update(check="other"),
            "scope": lambda s: s.update(scope="other"),
            "binding path": lambda s: s["profile"].update(path="other.json"),
            "version": lambda s: s.update(version=2),
        }
        for name, change in edits.items():
            with self.subTest(name):
                (self.destination / "session.json").write_text(original)
                self.edit_session(change)
                with self.assertRaises(ValueError):
                    diagnostic.verify(self.destination)

    def test_verify_refuses_receipt_with_extra_field_even_if_rehashed(self) -> None:
        self.good_session()
        receipt_path = self.destination / "receipt.json"
        receipt = json.loads(receipt_path.read_text())
        receipt["injected"] = True
        receipt_path.write_text(json.dumps(receipt, indent=2) + "\n")
        self.edit_session(
            lambda s: s["receipt"].update(
                sha256=hashlib.sha256(receipt_path.read_bytes()).hexdigest()
            )
        )
        with self.assertRaises(ValueError):
            diagnostic.verify(self.destination)

    def test_profile_limits(self) -> None:
        base = {
            "version": 1,
            "repo": "fixture",
            "check": "selected",
            "scope": "synthetic wrapper qualification, not an app check",
            "argv": ["true"],
            "artifacts": [],
        }
        changes: tuple[Callable[[dict[str, Any]], object], ...] = (
            lambda p: p.update(artifacts=["a", "a"]),
            lambda p: p.update(artifacts=[f"f{n}" for n in range(33)]),
            lambda p: p.update(argv=["", "x"]),
        )
        for change in changes:
            profile = dict(base)
            change(profile)
            self.profile.write_text(json.dumps(profile))
            with self.assertRaises(ValueError):
                diagnostic.read_profile(self.profile)

    def test_destination_is_private_and_session_files_are_exclusive(self) -> None:
        self.good_session()
        self.assertEqual(self.destination.stat().st_mode & 0o777, 0o700)
        with self.assertRaises(FileExistsError):
            diagnostic.write_new(self.destination / "session.json", b"again")

    def test_ci_context_value_checks(self) -> None:
        with self.assertRaises(ValueError):
            diagnostic.ci_context({"GITHUB_ACTIONS": "true", "GITHUB_JOB": "x" * 513})
        with self.assertRaises(ValueError):
            diagnostic.ci_context({"GITHUB_ACTIONS": "true", "GITHUB_RUN_ATTEMPT": "0"})
        with self.assertRaises(ValueError):
            diagnostic.ci_context({"GITHUB_ACTIONS": "true", "GITHUB_SHA": "not-a-sha"})

    def test_mirror_refuses_symlink(self) -> None:
        target = self.root / "target.fifo"
        os.mkfifo(target)
        link = self.root / "link.fifo"
        link.symlink_to(target)
        mirror = LocalMirror(link)
        mirror.close()
        self.assertEqual(mirror.state, "unavailable")
        self.assertIsNone(mirror.fd)

    def test_mirror_partial_write_is_counted_as_dropped(self) -> None:
        fifo = self.root / "live.fifo"
        os.mkfifo(fifo)
        reader = os.open(fifo, os.O_RDONLY | os.O_NONBLOCK)
        self.addCleanup(os.close, reader)
        source = self.root / "source.log"
        total = 5 * 16384
        source.write_bytes(b"x" * total)
        mirror = LocalMirror(fifo)
        self.addCleanup(mirror.close)
        for _ in range(8):
            mirror.drain(str(source))
        self.assertEqual(mirror.state, "active")
        self.assertGreater(mirror.written, 0)
        self.assertGreater(mirror.dropped, 0)
        self.assertEqual(mirror.written + mirror.dropped, total)

    def test_mirror_refuses_foreign_owner(self) -> None:
        fifo = self.root / "foreign.fifo"
        os.mkfifo(fifo)
        reader = os.open(fifo, os.O_RDONLY | os.O_NONBLOCK)
        self.addCleanup(os.close, reader)
        with patch("local_mirror.os.geteuid", return_value=os.geteuid() + 1):
            mirror = LocalMirror(fifo)
        mirror.close()
        self.assertEqual(mirror.state, "unavailable")
        self.assertIsNone(mirror.fd)

    def test_mirror_final_drain_honors_its_deadline(self) -> None:
        fifo = self.root / "drain.fifo"
        os.mkfifo(fifo)
        reader = os.open(fifo, os.O_RDONLY | os.O_NONBLOCK)
        self.addCleanup(os.close, reader)
        source = self.root / "big.log"
        total = 512 * 1024
        source.write_bytes(b"y" * total)
        mirror = LocalMirror(fifo)
        self.addCleanup(mirror.close)
        # A patched clock isolates the deadline branch: with a real clock the
        # regular-file loop ends on its byte target long before 10 ms pass.
        with patch(
            "local_mirror.time.monotonic", side_effect=itertools.count(0.0, 0.004)
        ):
            mirror.finish(str(source))
        self.assertEqual(mirror.state, "active")
        self.assertGreater(mirror.offset, 0)
        self.assertLess(mirror.offset, total)


if __name__ == "__main__":
    unittest.main()
