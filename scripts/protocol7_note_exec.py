"""Private note-controller child limits; no credential environment or core dump."""
import os,resource,sys
fd=int(sys.argv[1]);op=sys.argv[2]
if op not in ('derive','construct'):raise SystemExit(1)
resource.setrlimit(resource.RLIMIT_CPU,(20,20))
resource.setrlimit(resource.RLIMIT_AS,(256*1024*1024,256*1024*1024))
resource.setrlimit(resource.RLIMIT_FSIZE,(2088,2088))
resource.setrlimit(resource.RLIMIT_CORE,(0,0))
resource.setrlimit(resource.RLIMIT_NOFILE,(32,32))
os.execve('/proc/self/fd/'+str(fd),['owner-note-controller',op],{})
