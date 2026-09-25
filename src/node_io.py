"""Per-frame I/O deadlines for the private development ABCI connection.

Idle engine channels have no timer: they may legitimately wait for
consensus work. A started frame has one absolute receive deadline, not a fresh
allowance per byte. Replies have a separate absolute send deadline. This bounds
socket I/O only, not native execution time, OS scheduling, or hostile-host access.
"""
from __future__ import annotations
import math
import socket
import time

class FrameDeadline(TimeoutError):
    pass


def duration(value: float, name: str) -> float:
    if type(value) not in (int,float) or not math.isfinite(value) or not .01 <= value <= 120:
        raise ValueError(f'{name} must be finite and between 0.01 and 120 seconds')
    return float(value)

class FrameIO:
    """Unbuffered stream adapter for the existing unchanged ABCI frame codec."""
    def __init__(self, sock: socket.socket, *, receive_seconds=5.0, send_seconds=5.0,
                 clock=time.monotonic):
        self.sock = sock
        self.receive_seconds = duration(receive_seconds, 'receive deadline')
        self.send_seconds = duration(send_seconds, 'send deadline')
        self.clock = clock
        self.deadline = None
        self.direction = 'read'

    def begin_read(self):
        self.direction = 'read'
        self.deadline = None
        self.sock.settimeout(None)

    def begin_write(self):
        self.direction = 'write'
        self.deadline = self.clock() + self.send_seconds

    def _remaining(self):
        if self.deadline is None:
            return None
        left = self.deadline - self.clock()
        if left <= 0:
            raise FrameDeadline('ABCI frame deadline exceeded')
        return left

    def read(self, size: int):
        if self.direction != 'read' or type(size) is not int or size <= 0:
            raise ValueError('invalid bounded frame read')
        self.sock.settimeout(self._remaining())
        try:
            data = self.sock.recv(size)
        except socket.timeout as exc:
            raise FrameDeadline('ABCI receive deadline exceeded') from exc
        if data and self.deadline is None:
            self.deadline = self.clock() + self.receive_seconds
        return data

    def write(self, data: bytes):
        if self.direction != 'write' or type(data) is not bytes:
            raise ValueError('invalid bounded frame write')
        self.sock.settimeout(self._remaining())
        try:
            self.sock.sendall(data)
        except socket.timeout as exc:
            raise FrameDeadline('ABCI response deadline exceeded') from exc
        return len(data)

    def flush(self):
        pass  # Unbuffered sendall has already completed or raised.
