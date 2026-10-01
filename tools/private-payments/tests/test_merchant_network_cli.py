"""TTY and bounded owned-process boundaries; no test launches a real engine."""
import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from local_devnet import ROOT
from private_cli_acceptance import terminal_command
from wallet_fixture import PASSWORD

SCRIPT = ROOT/'tools/private-payments/scripts/1soft_merchant_network.py'
CLI = None
if SCRIPT.is_file():
    spec = importlib.util.spec_from_file_location('merchant_network_cli_tests', SCRIPT)
    CLI = importlib.util.module_from_spec(spec); spec.loader.exec_module(CLI)


class Process:
    def __init__(self): self.alive = True; self.terminated = 0
    def poll(self): return None if self.alive else 0
    def terminate(self): self.terminated += 1; self.alive = False
    def wait(self, *, timeout): return 0
    def kill(self): self.alive = False


class Network:
    def __init__(self, *, ready):
        self.config = {'genesis_sha256': 'a'*64, 'endpoint': 'http://127.0.0.1:24004/',
                       'merchant_recipients': ['lab_'+'b'*64, 'lab_'+'c'*64, 'lab_'+'d'*64]}
        self._ready = ready; self.apps = [Process()]; self.engines = [Process()]
        self.handles = []; self.lock = None; self.stopped = False; self.calls = []
    def ready(self): return self._ready
    def start(self): self.calls.append('start'); return self
    def health(self): self.calls.append('health')
    def bootstrap(self, *, password):
        self.calls.append(('bootstrap', password)); self._ready = True
        return {'trust_renewed': False}
    def stop(self):
        self.calls.append('stop')
        for p in self.apps+self.engines: p.terminate()
        self.stopped = True
        return {'warnings': []}


class MerchantNetworkCliTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(CLI, 'merchant network CLI is missing')
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name); self.root.chmod(0o700); self.workspace = self.root/'fresh'

    def args(self, command, **options):
        values = [command, '--workspace', str(self.workspace), '--engine', '/not-executed']
        for name, value in options.items(): values += ['--'+name.replace('_', '-'), str(value)]
        return CLI.parser().parse_args(values)

    def plain(self, *values):
        return subprocess.run([sys.executable, '-B', str(SCRIPT), *values],
            stdin=subprocess.DEVNULL, capture_output=True, timeout=5,
            cwd=ROOT, env={'PATH': '/usr/bin:/bin', 'PYTHONDONTWRITEBYTECODE': '1'})

    def test_init_requires_repeat_and_forwards_finite_pool_without_secret_output(self):
        q = Network(ready=False).config
        with patch.object(CLI, 'password', return_value=PASSWORD) as secret, \
             patch.object(CLI, 'initialize', return_value=q) as initialize:
            result = CLI.execute(self.args('init', recipient_count=3))
        secret.assert_called_once_with(confirm=True)
        initialize.assert_called_once_with(self.workspace, Path('/not-executed'), password=PASSWORD, recipient_count=3)
        self.assertEqual('merchant_development_workspace_initialized', result['status'])
        self.assertEqual(3, result['merchant_recipient_count']); self.assertFalse(result['production_custody'])
        self.assertNotIn(PASSWORD, str(result).encode())

    def test_invalid_pool_or_run_window_refused_before_password_and_network(self):
        for command, options in (('init', {'recipient_count': 1}), ('init', {'recipient_count': 17}),
                                 ('run', {'seconds': 0}), ('run', {'seconds': 301})):
            with self.subTest(command=command, options=options), \
                 patch.object(CLI, 'password', side_effect=AssertionError('password reached')), \
                 patch.object(CLI, 'MerchantNetwork', side_effect=AssertionError('network reached')):
                with self.assertRaises(ValueError): CLI.execute(self.args(command, **options))
        self.assertFalse(self.workspace.exists())

    def test_ready_run_is_key_free_stops_owned_handles_and_has_bounded_wait(self):
        network = Network(ready=True); ticks = iter((0, 0, .2, .4, .6, 1.1))
        with patch.object(CLI, 'MerchantNetwork', return_value=network), \
             patch.object(CLI, 'password', side_effect=AssertionError('password reached')):
            result = CLI.run_network(self.args('run', seconds=1), monotonic=lambda: next(ticks), sleep=lambda _: None)
        self.assertEqual('start', network.calls[0]); self.assertEqual('stop', network.calls[-1])
        self.assertEqual(0, result['owned_processes_after_cleanup']); self.assertEqual([], result['cleanup_errors'])
        self.assertFalse(result['trust_renewed']); self.assertFalse(result['onchain_privacy'])
        self.assertTrue(all(p.terminated == 1 for p in network.apps+network.engines))

    def test_unready_run_prompts_once_bootstraps_once_and_never_renews(self):
        network = Network(ready=False)
        with patch.object(CLI, 'MerchantNetwork', return_value=network), \
             patch.object(CLI, 'password', return_value=PASSWORD) as secret:
            result = CLI.run_network(self.args('run', seconds=1), monotonic=lambda: 1,
                sleep=lambda _: (_ for _ in ()).throw(KeyboardInterrupt()))
        secret.assert_called_once_with(confirm=False)
        self.assertEqual(1, len([call for call in network.calls if isinstance(call, tuple)]))
        self.assertEqual('stop', network.calls[-1]); self.assertFalse(result['trust_renewed'])
        self.assertNotIn(PASSWORD, str(result).encode())

    def test_start_failure_cleans_owned_handles_without_retry(self):
        network = Network(ready=True)
        def failed(): network.calls.append('start'); raise RuntimeError('private start detail')
        network.start = failed
        with patch.object(CLI, 'MerchantNetwork', return_value=network):
            with self.assertRaises(RuntimeError): CLI.run_network(self.args('run', seconds=1))
        self.assertEqual(['start', 'stop'], network.calls)
        self.assertTrue(all(p.poll() == 0 for p in network.apps+network.engines))

    def test_health_failure_cleans_without_bootstrap_or_foreign_process_action(self):
        network = Network(ready=True); foreign = Process()
        def failed(): raise RuntimeError('private health detail')
        network.health = failed
        with patch.object(CLI, 'MerchantNetwork', return_value=network):
            with self.assertRaises(RuntimeError):
                CLI.run_network(self.args('run', seconds=1), monotonic=lambda: 0, sleep=lambda _: None)
        self.assertTrue(foreign.alive); self.assertEqual(0, foreign.terminated)
        self.assertEqual('stop', network.calls[-1])

    def test_cleanup_failure_is_preserved_and_independently_reaps_only_owned_handles(self):
        network = Network(ready=True)
        def failed(): raise RuntimeError('private cleanup detail')
        network.stop = failed; ticks = iter((0, 2))
        with patch.object(CLI, 'MerchantNetwork', return_value=network):
            with self.assertRaises(ValueError):
                CLI.run_network(self.args('run', seconds=1), monotonic=lambda: next(ticks), sleep=lambda _: None)
        self.assertTrue(all(p.poll() == 0 for p in network.apps+network.engines))

    def test_noninteractive_or_password_argument_is_generic_and_never_echoes_secret(self):
        common = ['--workspace', str(self.workspace), '--engine', '/not-executed']
        refused = self.plain('init', *common)
        self.assertNotEqual(0, refused.returncode); self.assertFalse(self.workspace.exists())
        forbidden = self.plain('init', *common, '--password', PASSWORD.decode())
        self.assertNotEqual(0, forbidden.returncode)
        self.assertNotIn(PASSWORD, forbidden.stdout+forbidden.stderr)
        self.assertNotIn(b'Traceback', refused.stderr+forbidden.stderr)

    def test_actual_getpass_two_prompts_without_echo(self):
        source = "import importlib.util,json\ns=importlib.util.spec_from_file_location('network_cli', "+repr(str(SCRIPT))+")\nc=importlib.util.module_from_spec(s);s.loader.exec_module(c)\np=c.password(confirm=True)\nprint(json.dumps({'size':len(p)}))\n"
        result = terminal_command([sys.executable, '-B', '-c', source], password=PASSWORD, seconds=3)
        self.assertEqual(2, result['password_prompts']); self.assertEqual(len(PASSWORD), result['value']['size'])
        self.assertNotIn(PASSWORD, str(result).encode())


if __name__ == '__main__': unittest.main()
