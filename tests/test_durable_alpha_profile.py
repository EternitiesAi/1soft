"""Detect explicitly opted-in node limits; fixtures are not engine qualification."""
import copy
import hashlib
from pathlib import Path
import tempfile
import unittest
from native_core import NativeLedger, Reject
from protocol4_application import Protocol4Application, Protocol4Replay
from protocol4_fixture import fixture
from protocol4_state_sync import _metadata, _parse_metadata
from validator_sets_core import ValidatorSet

PROFILE = 'durable-private-alpha-v1'

class DurableAlphaProfileTests(unittest.TestCase):
    def genesis(self, alpha=True):
        g = fixture()[0]
        if alpha: g['development_profile'] = PROFILE
        return g

    def test_explicit_alpha_replays_past_512_and_audits(self):
        try: replay = Protocol4Replay(self.genesis())
        except Reject as exc: self.fail(f'explicit new alpha rejected: {exc}')
        with replay:
            for h in range(1, 514): replay.advance([], h)
            replay.audit()
            self.assertEqual(replay.height, 513)

    def test_legacy_replay_still_refuses_513(self):
        with Protocol4Replay(self.genesis(False)) as replay:
            for h in range(1, 513): replay.advance([], h)
            with self.assertRaises(Reject): replay.advance([], 513)

    def test_profile_is_literal_and_p4_only(self):
        for value in (True, 4096, '', PROFILE+'-other', None):
            g=self.genesis();g['development_profile']=value
            with self.subTest(value=value), self.assertRaises(Reject):
                NativeLedger(':memory:',g)
        g=self.genesis();g['protocol_version']=2
        with self.assertRaises(Reject): NativeLedger(':memory:',g)

    def test_alpha_node_commit_reopen_and_block_query_513(self):
        g=self.genesis();roster=ValidatorSet.parse(g['validator_registry']['validators'])
        votes=[{'address':v.address.hex(),'power':v.power,'block_id_flag':2} for v in roster.validators]
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'node.sqlite'
            try: app=Protocol4Application(path,expected_genesis=g)
            except Reject as exc: self.fail(f'explicit new alpha rejected: {exc}')
            with app:
                try: app.init_chain(g['chain_id'],g,g['validator_registry']['validators'])
                except Reject as exc: self.fail(f'explicit new alpha initialization rejected: {exc}')
                for h in range(1,514):
                    app.finalize_block([],h,hashlib.sha256(str(h).encode()).digest(),
                        bytes.fromhex(roster.hash),[] if h==1 else votes,str(h).encode())
                    app.commit()
                self.assertEqual(app.query('/block/513')['code'],0)
                desc=app.list_snapshots()[0]
                recipient_path=Path(temp)/'restored.sqlite'
                with Protocol4Application(recipient_path,expected_genesis=g) as recipient:
                    self.assertEqual(recipient.offer_snapshot(desc,bytes.fromhex(app.app_hash)),1)
                    for i in range(desc['chunks']):
                        self.assertEqual(recipient.apply_snapshot_chunk(i,app.load_snapshot_chunk(513,2,i),'local-fixture')['result'],1)
                    self.assertEqual((recipient.height,recipient.app_hash),(513,app.app_hash))
                with Protocol4Application(recipient_path,expected_genesis=g) as recipient:
                    self.assertEqual(recipient.height,513)
            with Protocol4Application(path,expected_genesis=g) as reopened:
                self.assertEqual(reopened.height,513)
                self.assertEqual(reopened.query('/block/513')['code'],0)

    def test_empty_unpinned_snapshot_lookup_is_read_only(self):
        with Protocol4Application(':memory:') as app:
            try: value=app.load_snapshot_chunk(1,2,0)
            except Reject as exc: self.fail(f'empty lookup rejected: {exc}')
            self.assertEqual(value,b'')
            self.assertIsNone(app.genesis)

    def test_alpha_replay_finite_4096_ceiling(self):
        with Protocol4Replay(self.genesis()) as replay:
            for h in range(1,4097): replay.advance([],h)
            replay.audit()
            self.assertEqual(replay.height,4096)
            with self.assertRaises(Reject): replay.advance([],4097)

    def test_legacy_query_keeps_original_input_grammar(self):
        g=self.genesis(False)
        with Protocol4Application(':memory:',expected_genesis=g) as app:
            app.init_chain(g['chain_id'],g,g['validator_registry']['validators'])
            self.assertEqual(app.query('/block/1000')['log'],'invalid protocol-4 block height')

    def test_snapshot_metadata_default_remains_legacy_bounded(self):
        raw=_metadata(self.genesis(),513,'a'*64,100,1)
        with self.assertRaises(Reject): _parse_metadata(raw)
        # Opt-in uses the independently pinned genesis limit, not metadata-selected limit.
        try: parsed=_parse_metadata(raw,max_height=4096)
        except TypeError as exc: self.fail(f'profile-bound snapshot parser missing: {exc}')
        self.assertEqual(parsed['height'],513)

if __name__=='__main__': unittest.main()
