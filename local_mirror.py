"""Optional local live mirror to a caller-selected, already-opened FIFO reader.

No inherited descriptor flags change. No thread, PTY, retry or upload. Mirror
availability is independent of the authoritative recorder capture and outcome.
"""

import os
import stat
import time
from pathlib import Path


class LocalMirror:
    def __init__(self, destination: Path) -> None:
        self.fd: int | None = None
        self.offset = 0
        self.written = 0
        self.dropped = 0
        self.state = "unavailable"
        self.source: int | None = None
        try:
            fd = os.open(destination, os.O_WRONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
            info = os.fstat(fd)
            if not stat.S_ISFIFO(info.st_mode) or info.st_uid != os.geteuid():
                os.close(fd)
                return
            self.fd = fd
            self.state = "active"
        except OSError:
            pass

    def drain(self, source: str) -> None:
        if self.fd is None:
            return
        try:
            if self.source is None:
                self.source = os.open(
                    source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
                )
            # One bounded read and one nonblocking FIFO write per wait interval.
            data = os.pread(self.source, 16384, self.offset)
            self.offset += len(data)
            if not data:
                return
            try:
                count = os.write(self.fd, data)
                self.written += count
                self.dropped += len(data) - count
            except BlockingIOError:
                self.dropped += len(data)
        except OSError:
            self.state = "unavailable"
            self.close()

    def finish(self, source: str) -> None:
        """Drain a fixed EOF at most 1 MiB/10 ms, with no waits for readers."""
        if self.fd is None:
            return
        try:
            cutoff = os.stat(source, follow_symlinks=False).st_size
            target = min(cutoff, self.offset + 1024 * 1024)
            deadline = time.monotonic() + 0.01
            while self.offset < target and time.monotonic() < deadline:
                before = self.offset
                self.drain(source)
                if self.fd is None or self.offset == before:
                    break
        except OSError:
            self.state = "unavailable"
            self.close()

    def close(self) -> None:
        if self.source is not None:
            os.close(self.source)
            self.source = None
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None

    def report(self, authoritative_bytes: int) -> dict[str, str | int]:
        return {
            "status": "complete"
            if self.state == "active" and self.written == authoritative_bytes
            else "incomplete",
            "written_bytes": self.written,
            "dropped_bytes": self.dropped,
            "unmirrored_bytes": max(0, authoritative_bytes - self.written),
        }
