"""Small bounded proof-file interface; never opens node or wallet databases."""
from pathlib import Path
import os
import stat
from commit_verifier import load_json, encode
from validator_sets import need, MAX_DOCUMENT_BYTES


def read_json(path, limit=MAX_DOCUMENT_BYTES):
    with Path(path).open('rb') as stream:
        raw = stream.read(limit + 1)
    return load_json(raw, max_bytes=limit)


def write_new(path, value):
    raw = encode(value)
    need(len(raw) <= MAX_DOCUMENT_BYTES, 'output exceeds limit')
    p = Path(os.path.abspath(path))
    for ancestor in (p.parent, *p.parent.parents):
        need(not ancestor.is_symlink(), 'output ancestor symlink refused')
    info = p.parent.stat()
    need(os.name == 'posix' and stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
         and not stat.S_IMODE(info.st_mode) & 0o077, 'private owned output directory required')
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())
    directory = os.open(p.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try: os.fsync(directory)
    finally: os.close(directory)
