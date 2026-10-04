"""Single AppHash and SQLite commit for protocol-4 money plus validators."""
from __future__ import annotations

import base64
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from commit_verifier import encode
from block_application import BlockApplication
from native_core import Reject, NativeLedger, address, canonical, digest, public, sign
from protocol4_application import Protocol4Application
from protocol4_fixture import fixture
from registry_rules_core import RegistryRules
from validator_sets_core import ValidatorSet

ROOT = Path(__file__).resolve().parents[1]


class Protocol4ApplicationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / 'protocol4.sqlite'
        self.genesis, self.payers, self.admins, self.validators, self.target = fixture()
        self.old_hash = ValidatorSet.parse(self.genesis['validator_registry']['validators']).hash
        self.new_hash = ValidatorSet.parse(self.target).hash
        self.app = Protocol4Application(self.path, expected_genesis=self.genesis)
        self.app.init_chain(self.genesis['chain_id'], self.genesis,
                            self.genesis['validator_registry']['validators'])

    def tearDown(self):
        self.app.close()
        self.temp.cleanup()

    def payment(self):
        payer, recipient = [address(public(k)) for k in self.payers]
        ledger = NativeLedger(':memory:', self.genesis)
        try:
            body = ledger.body(payer, 0, {'type': 'transfer', 'to': recipient, 'units': 7},
                               valid_until=20)
        finally:
            ledger.close()
        return canonical(sign(self.payers[0], body))

    def schedule(self):
        rules = RegistryRules(self.genesis['validator_registry'],
                              bound_genesis_sha256=digest(self.genesis))
        body = rules.body(self.app.state['registry'],
                          {'kind': 'schedule', 'emitted_height': 4,
                           'target_validators': self.target}, valid_from=1, valid_until=3)
        material = rules.signing_bytes(body)
        approvals = sorted(({'public_key': public(k), 'signature': k.sign(material).hex()}
                            for k in self.admins[:3]), key=lambda row: row['public_key'])
        return encode({'body': body, 'approvals': approvals})

    def decide(self, height, txs=(), *, request_suffix=b''):
        roster = self.genesis['validator_registry']['validators'] if height <= 6 else self.target
        votes = [] if height == 1 else [
            {'address': v.address.hex(), 'power': v.power, 'block_id_flag': 2}
            for v in ValidatorSet.parse(roster).validators]
        next_hash = self.old_hash if height <= 4 else self.new_hash
        request = b'fixture-protocol4-finalize:' + str(height).encode() + request_suffix
        result, response = self.app.finalize_block(
            list(txs), height, bytes([height]) * 32, bytes.fromhex(next_hash), votes, request)
        return result, response, request, votes

    def test_legacy_node_refuses_fresh_protocol4_genesis(self):
        with self.assertRaisesRegex(Reject, 'legacy node refuses'):
            BlockApplication(':memory:', expected_genesis=self.genesis)
        old = BlockApplication(':memory:')
        try:
            with self.assertRaisesRegex(Reject, 'legacy node refuses'):
                old.init_chain(self.genesis['chain_id'], self.genesis)
        finally:
            old.close()

    def test_mixed_decided_block_is_atomic_and_replay_exact(self):
        payment, action = self.payment(), self.schedule()
        self.assertEqual(self.app.check_tx(payment)['code'], 0)
        self.assertEqual(self.app.check_tx(action)['code'], 0)
        self.assertTrue(self.app.process_proposal([payment, action], 1, bytes.fromhex(self.old_hash)))
        self.assertFalse(self.app.process_proposal([payment, action], 1, b'\0' * 32))
        self.assertEqual(self.app.prepare_proposal([payment, action], 1, 1_000_000),
                         [payment, action])
        self.assertEqual(self.app.height, 0)
        result, response, request, votes = self.decide(1, (payment, action))
        self.assertEqual([r['code'] for r in result['tx_results']], [0, 0])
        self.assertEqual(self.app.height, 0)
        self.assertEqual(self.app.state['native']['receipts'], [])
        with self.assertRaisesRegex(RuntimeError, 'after response'):
            self.app.commit(fault='after_result')
        self.app.close()
        self.app = Protocol4Application(self.path, expected_genesis=self.genesis)
        self.assertEqual(self.app.height, 0)
        self.assertEqual(self.app.state['native']['receipts'], [])
        self.assertEqual(self.app.state['registry']['sequence'], 0)
        reproduced, reproduced_wire = self.app.finalize_block(
            [payment, action], 1, bytes([1]) * 32, bytes.fromhex(self.old_hash), votes, request)
        self.assertEqual((reproduced, reproduced_wire), (result, response))
        self.app.commit()
        self.assertEqual(self.app.height, 1)
        self.assertEqual(len(self.app.state['native']['receipts']), 1)
        self.assertEqual(self.app.state['registry']['sequence'], 1)
        replayed, replay_wire = self.app.finalize_block(
            [payment, action], 1, bytes([1]) * 32, bytes.fromhex(self.old_hash), votes, request)
        self.assertEqual((replayed, replay_wire), (result, response))
        with self.assertRaisesRegex(Reject, 'conflicting committed'):
            self.app.finalize_block([payment, action], 1, bytes([1]) * 32,
                                    bytes.fromhex(self.old_hash), votes, request + b'changed')
        self.app.close()
        self.app = Protocol4Application(self.path, expected_genesis=self.genesis)
        self.assertEqual(self.app.committed_result(1), result)
        self.assertEqual(self.app.app_hash, result['app_hash'])

    def test_validator_change_preserves_payment_and_composite_state(self):
        payment, action = self.payment(), self.schedule()
        self.decide(1, (payment, action))
        self.app.commit()
        for height in range(2, 8):
            result, _, _, _ = self.decide(height)
            if height == 4:
                self.assertEqual(len(result['validator_updates']), 3)
            else:
                self.assertEqual(result['validator_updates'], [])
            self.app.commit()
            self.assertEqual(self.app.app_hash, result['app_hash'])
            self.assertEqual(len(self.app.state['native']['receipts']), 1)
        self.assertEqual(self.app.state['registry']['active_hash'], self.new_hash)
        self.assertEqual(self.app.state['registry']['epoch'], 1)
        self.app.close()
        self.app = Protocol4Application(self.path, expected_genesis=self.genesis)
        self.assertEqual(self.app.height, 7)
        self.assertEqual(self.app.state['registry']['active_hash'], self.new_hash)
        self.assertEqual(len(self.app.state['native']['receipts']), 1)

    def _subprocess_exit_around_commit(self, fault: str, expected_exit: int):
        payment, action = self.payment(), self.schedule()
        txs = [base64.b64encode(raw).decode() for raw in (payment, action)]
        self.app.close()
        program = '''
import base64, json, sys
from protocol4_application import Protocol4Application
from protocol4_fixture import fixture
from validator_sets_core import ValidatorSet
genesis, *_ = fixture()
app = Protocol4Application(sys.argv[1], expected_genesis=genesis)
txs = [base64.b64decode(raw) for raw in json.loads(sys.argv[3])]
old = ValidatorSet.parse(genesis['validator_registry']['validators']).hash
app.finalize_block(txs, 1, bytes([1])*32, bytes.fromhex(old), [], b'crash-replay-fixture')
app.commit(fault=sys.argv[2])
'''
        child_env = dict(os.environ)
        child_paths = [str(ROOT / 'src'), str(ROOT / 'tests')]
        existing = child_env.get('PYTHONPATH')
        child_env['PYTHONPATH'] = os.pathsep.join(child_paths + ([existing] if existing else []))
        completed = subprocess.run([sys.executable, '-c', program,
                                    str(self.path), fault, json.dumps(txs)],
                                   capture_output=True, text=True, timeout=15,
                                   env=child_env)
        self.assertEqual(completed.returncode, expected_exit, completed.stderr)
        self.app = Protocol4Application(self.path, expected_genesis=self.genesis)
        return payment, action

    def test_process_exit_before_commit_rolls_back_money_registry_and_response(self):
        payment, action = self._subprocess_exit_around_commit('exit_before_commit', 94)
        self.assertEqual(self.app.height, 0)
        self.assertEqual(self.app.state['native']['receipts'], [])
        self.assertEqual(self.app.state['registry']['sequence'], 0)
        self.assertEqual(self.app.history(), [])
        self.assertIsNone(self.app.db.execute('SELECT 1 FROM blocks').fetchone())
        result, response = self.app.finalize_block(
            [payment, action], 1, bytes([1])*32, bytes.fromhex(self.old_hash),
            [], b'crash-replay-fixture')
        self.app.commit()
        self.assertEqual(self.app.height, 1)
        self.assertEqual(self.app.committed_result(1), result)

    def test_process_exit_after_commit_replays_exact_response(self):
        payment, action = self._subprocess_exit_around_commit('exit_after_commit', 95)
        self.assertEqual(self.app.height, 1)
        self.assertEqual(len(self.app.state['native']['receipts']), 1)
        self.assertEqual(self.app.state['registry']['sequence'], 1)
        result, response = self.app.finalize_block(
            [payment, action], 1, bytes([1])*32, bytes.fromhex(self.old_hash),
            [], b'crash-replay-fixture')
        self.assertEqual(self.app.committed_result(1), result)
        with self.assertRaisesRegex(Reject, 'conflicting committed'):
            self.app.finalize_block([payment, action], 1, bytes([1])*32,
                                    bytes.fromhex(self.old_hash), [], b'forged-replay')


if __name__ == '__main__':
    unittest.main()
