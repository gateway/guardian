"""Bounded reads for the offline trust inventory; never execute inspected files."""

import os
from pathlib import Path
import stat

MAX_BYTES = 4 * 1024 * 1024


def read_file(path: Path, max_bytes: int = MAX_BYTES) -> bytes:
    # Nonblocking open prevents a substituted FIFO from hanging the audit.
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > max_bytes:
            raise ValueError(f"not a regular file or exceeds {max_bytes} byte limit")
        data = stream.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise ValueError(f"exceeds {max_bytes} byte limit")
    return data
