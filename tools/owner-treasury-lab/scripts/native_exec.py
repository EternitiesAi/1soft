"""Child-only limits and execution of the measured open native-lab inode."""
import os,resource,sys
if len(sys.argv)!=3 or sys.argv[2] not in ('verify','context-root','note-root','owner-key','identities'):raise SystemExit(2)
fd=int(sys.argv[1]);os.fstat(fd)
for kind,limit in ((resource.RLIMIT_CPU,30),(resource.RLIMIT_AS,2*1024**3),(resource.RLIMIT_FSIZE,256),(resource.RLIMIT_CORE,0),(resource.RLIMIT_NOFILE,32)):
    resource.setrlimit(kind,(limit,limit))
os.set_inheritable(fd,True)
os.execve('/proc/self/fd/'+str(fd),['owner-treasury-lab',sys.argv[2]],{})
