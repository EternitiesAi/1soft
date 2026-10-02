"""Actual sequential monetary/registry execution; no receipt or trust bypass."""
import copy
import unittest
from unittest.mock import patch

from block_application import encode
from native_core import NativeLedger
from p4_evidence import verify_evidence
from p4_fixture import build, bundle
from protocol4_application import Protocol4Application, Protocol4Replay
import protocol4_application


class LegacyReplay:
    """Parity oracle retaining the full node restore at every replayed block."""
    def __init__(self, genesis):
        self.app = Protocol4Application(':memory:', expected_genesis=genesis)
        self.app.init_chain(genesis['chain_id'], genesis, genesis['validator_registry']['validators'])
    def __enter__(self): return self
    def __exit__(self, *_): self.app.close()
    def __getattr__(self, name): return getattr(self.app, name)
    def advance(self, txs, height):
        state, result = self.app._execute(txs, height)
        self.app.state, self.app.height, self.app.app_hash = state, height, result['app_hash']
        return state, result
    def audit(self):
        self.app._audit_state(self.app.genesis, self.app.state, self.app.height, self.app.app_hash)


class SequentialReplayTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = build(count=16, rejected=True)
        cls.evidence = bundle(cls.fixture)

    def verify(self, evidence=None, now=None):
        f = self.fixture
        return verify_evidence(self.evidence if evidence is None else evidence,
                               f['genesis'], f['policy'], now_ns=f['now_ns'] if now is None else now)

    def test_entire_report_matches_original_per_block_restore(self):
        with patch('p4_evidence.Protocol4Replay', LegacyReplay):
            original = self.verify()
        self.assertEqual(encode(original), encode(self.verify()))
        self.assertEqual(original['registry_epoch'], 2)
        self.assertTrue(any(a['code'] != 0 for a in original['attempts']))

    def test_receipt_prefix_verification_is_bounded_to_final_audit(self):
        inspected = []
        original = NativeLedger.verify_receipts
        def counted(ledger):
            inspected.append(ledger.db.execute('SELECT COUNT(*) FROM receipts').fetchone()[0])
            return original(ledger)
        with patch.object(NativeLedger, 'verify_receipts', counted):
            report = self.verify()
        count = len(report['receipts'])
        self.assertGreater(count, 0)
        self.assertEqual([n for n in inspected if n], [count, count])

    def test_every_block_state_and_result_match_native_application(self):
        g = self.fixture['g']
        with LegacyReplay(g) as old, Protocol4Replay(g) as new:
            for row in self.evidence['history']:
                txs = [Protocol4Application._wire_from_b64(raw) for raw in row['txs']]
                self.assertEqual(encode(old.advance(txs, row['height'])),
                                 encode(new.advance(txs, row['height'])))
            new.audit()

    def test_node_execution_still_restores_and_audits_prior_snapshot(self):
        g = self.fixture['g']
        with Protocol4Application(':memory:', expected_genesis=g) as app:
            app.init_chain(g['chain_id'], g, g['validator_registry']['validators'])
            with patch('protocol4_application.restore', wraps=protocol4_application.restore) as restored:
                app._execute([], 1)
            self.assertEqual(restored.call_count, 1)

    def test_headers_rejected_before_monetary_replay(self):
        bad = copy.deepcopy(self.evidence)
        bad['headers'][-1]['signed_header']['commit']['signatures'][0]['signature'] = 'AAAA'
        with patch('protocol4_application.BlockApplication._apply', side_effect=AssertionError('must not execute')):
            with self.assertRaises(ValueError): self.verify(bad)

    def test_replay_has_no_checkpoint_or_ledger_import_argument(self):
        with self.assertRaises(TypeError):
            Protocol4Replay(self.fixture['g'], state=self.evidence['state']['native'])

    def test_replay_cannot_skip_repeat_or_execute_after_close(self):
        with Protocol4Replay(self.fixture['g']) as replay:
            with self.assertRaises(ValueError): replay.advance([], 2)
            replay.advance([], 1)
            with self.assertRaises(ValueError): replay.advance([], 1)
        with self.assertRaises(ValueError): replay.advance([], 2)

    def test_unexpected_partial_execution_failure_closes_disposable_replay(self):
        with Protocol4Replay(self.fixture['g']) as replay:
            txs = [Protocol4Application._wire_from_b64(raw) for raw in self.evidence['history'][0]['txs']]
            apply = protocol4_application._native_results
            def interrupted(ledger, wires, classes, results, height):
                apply(ledger, wires[:1], classes[:1], results, height)
                raise RuntimeError('fixture interruption after first monetary operation')
            with patch('protocol4_application._native_results', interrupted):
                with self.assertRaises(RuntimeError): replay.advance(txs, 1)
            self.assertTrue(replay.closed)
            with self.assertRaises(ValueError): replay.advance([], 1)

    def test_genesis_is_frozen_before_replay(self):
        incoming = copy.deepcopy(self.fixture['g'])
        with Protocol4Replay(incoming) as replay:
            incoming['allocations'][0]['units'] += 1000
            self.assertEqual(replay.genesis, self.fixture['g'])
            replay.audit()

    def test_separate_calls_do_not_preserve_trust_or_proof_cache(self):
        first = self.verify()
        with self.assertRaises(ValueError): self.verify(now=first['trust_expires_ns'])
        bad = copy.deepcopy(self.evidence)
        bad['state']['app_hash'] = '0' * 64
        with self.assertRaises(ValueError): self.verify(bad)
        self.assertEqual(encode(self.verify()), encode(first))
