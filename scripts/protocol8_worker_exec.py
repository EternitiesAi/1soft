#!/usr/bin/env python3
"""Child limits then exec the parent's measured open inode. POSIX only."""
import os
import resource
import sys

if len(sys.argv) != 3 or sys.argv[2] not in ('verify', 'note-root', 'network-domain', 'identities'):
    raise SystemExit(2)
fd = int(sys.argv[1])
os.fstat(fd)
for what, limit in ((resource.RLIMIT_CPU, 30), (resource.RLIMIT_AS, 2 * 1024**3),
                    (resource.RLIMIT_FSIZE, 1024), (resource.RLIMIT_CORE, 0),
                    (resource.RLIMIT_NOFILE, 32)):
    resource.setrlimit(what, (limit, limit))
os.set_inheritable(fd, True)
os.execve('/proc/self/fd/' + str(fd), ['recipient-consensus-bridge', sys.argv[2]], {})
