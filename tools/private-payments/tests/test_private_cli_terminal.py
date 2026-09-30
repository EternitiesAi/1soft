"""Real terminal echo, process and secret-output checks for local acceptance."""
import os
from pathlib import Path
import sys
import tempfile
import unittest
try:
    from private_cli_acceptance import terminal_command
except ImportError:
    terminal_command = None

class TerminalTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(terminal_command, 'actual private CLI terminal runner missing')
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name); self.root.chmod(0o700)
        self.secret = b'private-terminal-test-passphrase'

    def child(self, source, **kwargs):
        path = self.root/'fixture.py'; path.write_text(source); path.chmod(0o600)
        return terminal_command([sys.executable, '-B', str(path)], **kwargs)

    def test_actual_getpass_two_prompts_with_no_echo_and_json_stdout(self):
        result = self.child('import getpass,json,sys\nassert sys.stdin.isatty() and sys.stderr.isatty()\na=getpass.getpass("Passphrase: ")\nb=getpass.getpass("Confirm passphrase: ")\nprint(json.dumps({"equal":a==b,"size":len(a)}))\n', password=self.secret)
        self.assertEqual(2, result['password_prompts']); self.assertTrue(result['value']['equal'])
        self.assertEqual(len(self.secret), result['value']['size'])
        self.assertNotIn(self.secret, str(result).encode())

    def test_noninteractive_json_command_needs_no_password(self):
        result = self.child('print("{\\"status\\":\\"inspected\\"}")\n')
        self.assertEqual('inspected', result['value']['status']); self.assertEqual(0, result['password_prompts'])

    def test_plain_input_with_terminal_echo_is_refused_before_secret_write(self):
        with self.assertRaises(ValueError):
            self.child('import json\na=input("Passphrase: ")\nprint(json.dumps({"secret":a}))\n', password=self.secret, seconds=.5)

    def test_secret_in_result_is_rejected_and_not_returned_in_error(self):
        with self.assertRaises(ValueError) as raised:
            self.child('import getpass,json\na=getpass.getpass("Passphrase: ")\nprint(json.dumps({"secret":a}))\n', password=self.secret)
        self.assertNotIn(self.secret.decode(), str(raised.exception))

    def test_timeout_reaps_only_the_owned_child(self):
        with self.assertRaises(ValueError): self.child('import time\ntime.sleep(5)\n', seconds=.2)

    def test_unexpected_failure_is_generic(self):
        with self.assertRaises(ValueError): self.child('raise RuntimeError("private diagnostic")\n')

    def test_descendant_holding_stdout_cannot_escape_deadline(self):
        import time
        source = 'import subprocess,sys\np=subprocess.Popen([sys.executable,"-c","import time;time.sleep(30)"])\nprint("{}")\n'
        started = time.monotonic()
        with self.assertRaises(ValueError): self.child(source, seconds=.2)
        self.assertLess(time.monotonic()-started, 3)

if __name__=='__main__': unittest.main()
