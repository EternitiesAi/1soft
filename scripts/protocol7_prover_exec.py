#!/usr/bin/env python3
"""Prover child only: bounded resources, no core dump, measured executable inode."""
import os, resource, sys
if len(sys.argv) != 2:
    raise SystemExit(2)
fd = int(sys.argv[1])
os.fstat(fd)
for what, limit in (
    (resource.RLIMIT_CPU, 300), (resource.RLIMIT_AS, 3 * 1024**3),
    (resource.RLIMIT_FSIZE, 4168), (resource.RLIMIT_CORE, 0),
    (resource.RLIMIT_NOFILE, 32),
):
    resource.setrlimit(what, (limit, limit))
os.set_inheritable(fd, True)
os.execve('/proc/self/fd/' + str(fd), ['owner-payment-prover'], {'RAYON_NUM_THREADS': '2'})
