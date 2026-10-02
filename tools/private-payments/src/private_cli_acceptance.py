"""Bounded actual CLI terminal driver for disposable local qualification only.

Passwords enter the owned child's TTY after getpass disables echo. They never
enter argv, environment or retained logs. This is not a production password API.
"""
import hashlib
import os
import pty
import select
import signal
import subprocess
import sys
import termios
import time

from commit_verifier import load_json
from local_devnet import ROOT
from p4_evidence import need

MAX_OUTPUT = 2*1024*1024
MAX_TERMINAL = 16384


def terminal_command(argv, *, password=None, seconds=60):
    need(type(argv) is list and all(type(a) is str for a in argv), 'exact local command required')
    need(password is None or type(password) is bytes and 0<len(password)<=1024 and
         b'\n' not in password and b'\r' not in password, 'bounded terminal password required')
    need(type(seconds) in (int, float) and 0<seconds<=120, 'bounded command timeout required')
    if password is not None:
        need(all(password not in a.encode() for a in argv), 'password argument refused')
    master, slave = pty.openpty(); child = None; raw = bytearray(); terminal = bytearray(); pending = bytearray(); prompts=0
    stdout_closed = False
    try:
        child = subprocess.Popen(argv, stdin=slave, stdout=subprocess.PIPE, stderr=slave,
            start_new_session=True, cwd=ROOT, umask=0o077,
            env={**os.environ, 'PYTHONPATH': '', 'PYTHONDONTWRITEBYTECODE': '1'})
        deadline = time.monotonic()+seconds
        while True:
            need(time.monotonic()<deadline, 'private CLI terminal timed out')
            ready, _, _ = select.select([master]+([] if stdout_closed else [child.stdout]), [], [], .05)
            for fd in ready:
                if fd==master:
                    block=os.read(master, 4096); terminal.extend(block); pending.extend(block)
                    need(len(terminal)<=MAX_TERMINAL, 'private CLI terminal output exceeds bound')
                    if pending.endswith(b': '):
                        need(password is not None and prompts<2, 'unexpected private CLI password prompt')
                        need(not termios.tcgetattr(slave)[3]&termios.ECHO, 'terminal password echo is enabled')
                        need(os.write(master, password+b'\n')==len(password)+1, 'terminal password entry incomplete')
                        prompts+=1; pending.clear()
                else:
                    block=os.read(child.stdout.fileno(), 65536); raw.extend(block)
                    if not block: stdout_closed = True
                    need(len(raw)<=MAX_OUTPUT, 'private CLI result exceeds bound')
                    need(not raw.endswith(b': '), 'password prompt on result channel refused')
            if password is not None:
                need(password not in raw and password not in terminal, 'private CLI exposed password')
            if child.poll() is not None and stdout_closed:
                # EOF must be observed through select under the same deadline.
                # A descendant holding the pipe cannot bypass that deadline.
                need(len(raw)<=MAX_OUTPUT and child.returncode==0, 'private CLI did not complete')
                if password is not None: need(password not in raw and password not in terminal, 'private CLI exposed password')
                break
        value=load_json(bytes(raw), max_bytes=MAX_OUTPUT)
        need(type(value) is dict, 'private CLI did not return structured metadata')
        return {'value': value, 'password_prompts': prompts, 'returncode': child.returncode,
                'stdout_sha256': hashlib.sha256(raw).hexdigest(),
                'terminal_sha256': hashlib.sha256(terminal).hexdigest(),
                'owned_processes_after_cleanup': 0}
    finally:
        if child is not None:
            # This exact process group was created by start_new_session here;
            # no global process enumeration or name-based termination occurs.
            try: os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError: pass
            child.wait(timeout=3)
            if child.stdout is not None: child.stdout.close()
        os.close(master); os.close(slave)


def invoke(command, args, *, password=None):
    return terminal_command([sys.executable, '-B', str(ROOT/'tools/private-payments/scripts/1soft_private.py'),
                             command, *args], password=password)
