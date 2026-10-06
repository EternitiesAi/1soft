#!/usr/bin/env python3
"""Private child only: measured executable fd, finite resources, no core dumps."""
import os, resource, sys
if len(sys.argv) != 3 or sys.argv[2] not in ('key','inspect-note','construct','prove'):
    raise SystemExit(2)
fd = int(sys.argv[1]); os.fstat(fd)
proving = sys.argv[2] == 'prove'
for what, limit in ((resource.RLIMIT_CPU,300 if proving else 30),
                    (resource.RLIMIT_AS,3*1024**3 if proving else 2*1024**3),
                    (resource.RLIMIT_FSIZE,3560 if proving else 1192),
                    (resource.RLIMIT_CORE,0),(resource.RLIMIT_NOFILE,32)):
    resource.setrlimit(what,(limit,limit))
os.set_inheritable(fd,True)
os.execve('/proc/self/fd/'+str(fd),['recipient-prover'] if proving else ['recipient-wallet-helper',sys.argv[2]],
          {'RAYON_NUM_THREADS':'2'} if proving else {})
