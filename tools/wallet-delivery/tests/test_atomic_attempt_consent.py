"""Actual SQLite claim interleavings; synthetic local observations, no RPC.

The owner keeps the dispatch file lock throughout. A second SQLite connection
models overlapping operations within that owner, without constructing a second
process dispatcher or changing the journal schema/admission limits.
"""
import hashlib
from pathlib import Path
import sqlite3
import tempfile
import threading
import unittest
from unittest.mock import patch

from commit_verifier import encode
from decision_delivery import DecisionDelivery
from delivery_fixture import Scenario, IDS
from native_core import public
from payment_transport import DispatchJournal
from transport_fixture import fixture, packet, NOW_NS, DEADLINE


DECLINED = {'observation':'endpoint_declined','check_tx_code':7,'response_sha256':'7'*64}
ADMITTED = {'observation':'endpoint_admitted','check_tx_code':0,'response_sha256':'0'*64}


def connection_for(owner, filename):
    peer = object.__new__(DispatchJournal)
    peer.__dict__.update(owner.__dict__)
    peer.db = sqlite3.connect(filename, isolation_level=None, timeout=3)
    peer.db.row_factory = sqlite3.Row
    peer.lock = None
    return peer


class AtomicAttemptTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name); self.root.chmod(0o700)
        owner,_,_,engine,_,_,raw = fixture()
        genesis = encode(engine)
        self.j = DispatchJournal(self.root/'dispatch.sqlite',genesis,hashlib.sha256(genesis).hexdigest(),
            'http://127.0.0.1:27657/',DEADLINE,clock=lambda:NOW_NS)
        self.q = self.j.queue(raw,public(owner)); self.txid = self.q['native_txid']
    def tearDown(self):
        self.j.close(); self.temp.cleanup()
    def test_expected_attempt_requires_exact_bounded_int_and_refusal_is_read_only(self):
        before = list(self.j.db.iterdump())
        with patch('payment_transport._worker',side_effect=AssertionError('no submission')):
            for value in (True,False,0,-1,101,1.0,'1'):
                with self.subTest(value=value),self.assertRaises(ValueError):
                    self.j.dispatch(self.txid,self.q['dispatch_confirmation'],expected_attempt=value)
        self.assertEqual(list(self.j.db.iterdump()),before)
    def test_invalid_expected_status_refuses_without_mutation_or_io(self):
        before=list(self.j.db.iterdump())
        with patch('payment_transport._worker',side_effect=AssertionError('no submission')):
            for value in (True,False,0,1,[],{},'','paid'):
                with self.subTest(value=value),self.assertRaises(ValueError):
                    self.j.dispatch(self.txid,self.q['dispatch_confirmation'],
                        expected_attempt=1,expected_transport_status=value)
        self.assertEqual(list(self.j.db.iterdump()),before)
    def test_same_counter_changed_status_refuses_original_context(self):
        ready = threading.Barrier(2); release = threading.Barrier(2); errors = []
        def observe(*_):
            ready.wait(3); release.wait(3); return DECLINED
        def first():
            peer = connection_for(self.j, self.root/'dispatch.sqlite')
            try: peer.dispatch(self.txid,self.q['dispatch_confirmation'])
            except BaseException as exc: errors.append(exc)
            finally: peer.close()
        with patch('payment_transport._worker',side_effect=observe):
            t=threading.Thread(target=first); t.start(); ready.wait(3)
            reviewed=self.j.status(self.txid)
            self.assertEqual((reviewed['attempts'],reviewed['status']),(1,'dispatching'))
            release.wait(3); t.join(4)
        self.assertFalse(t.is_alive()); self.assertEqual(errors,[])
        before=list(self.j.db.iterdump())
        with patch('payment_transport._worker',side_effect=AssertionError('no submission')):
            with self.assertRaisesRegex(ValueError,'transport status changed'):
                self.j.dispatch(self.txid,self.q['dispatch_confirmation'],replay=True,
                    expected_attempt=2,expected_transport_status=reviewed['status'])
        self.assertEqual(list(self.j.db.iterdump()),before)
    def test_late_observation_does_not_downgrade_verified_receipt(self):
        ready=threading.Barrier(2); release=threading.Barrier(2); errors=[]
        def verify():
            peer=connection_for(self.j, self.root/'dispatch.sqlite')
            try:
                ready.wait(3); peer.prove(self.txid,encode(packet())); release.wait(3)
            except BaseException as exc: errors.append(exc)
            finally: peer.close()
        def late(*_):
            ready.wait(3); release.wait(3); return DECLINED
        t=threading.Thread(target=verify); t.start()
        with patch('payment_transport._worker',side_effect=late):
            result=self.j.dispatch(self.txid,self.q['dispatch_confirmation'])
        t.join(4); self.assertFalse(t.is_alive()); self.assertEqual(errors,[])
        self.assertTrue(result['receipt_verified']); self.assertEqual(self.j.export_receipt(self.txid),encode(packet()))
        event=self.j.events(self.txid)[-1]
        self.assertEqual(event['detail']['attempt'],1); self.assertFalse(event['detail']['status_updated'])
    def test_late_observation_does_not_replace_newer_attempt_state(self):
        ready=threading.Barrier(2); release=threading.Barrier(2); errors=[]
        def newer():
            peer=connection_for(self.j, self.root/'dispatch.sqlite')
            try:
                ready.wait(3); peer.dispatch(self.txid,self.q['dispatch_confirmation'],replay=True)
                release.wait(3)
            except BaseException as exc: errors.append(exc)
            finally: peer.close()
        def observe(endpoint,raw,attempt):
            if attempt==2: return ADMITTED
            ready.wait(3); release.wait(3); return DECLINED
        t=threading.Thread(target=newer); t.start()
        with patch('payment_transport._worker',side_effect=observe):
            result=self.j.dispatch(self.txid,self.q['dispatch_confirmation'])
        t.join(4); self.assertFalse(t.is_alive()); self.assertEqual(errors,[])
        self.assertEqual((result['attempts'],result['status']),(2,'endpoint_admitted'))
        observed=[e['detail'] for e in self.j.events(self.txid) if e['event']=='endpoint_observation_not_settlement']
        self.assertEqual([(e['attempt'],e['status_updated']) for e in observed],[(2,True),(1,False)])


class DecisionClaimRaceTests(unittest.TestCase):
    def test_identical_replay_review_cannot_consume_attempts_two_and_three(self):
        c=Scenario(); signed=c.sign(); selection={'account':IDS[0],'grant_id':'raven'}
        try:
            with DecisionDelivery(c.wallet_path,c.delivery_path,c.raw,c.policy,
                    'http://127.0.0.1:27657/',create=True,clock=lambda:c.clock) as d:
                q=d.queue(signed['decision_id'],**selection)
                submissions=[]
                def observe(endpoint,raw,attempt):
                    submissions.append((raw,attempt)); return DECLINED
                with patch('payment_transport._worker',side_effect=observe):
                    d.send(signed['decision_id'],q['delivery_confirmation'],**selection)
                    review=d.review(signed['decision_id'],replay=True,**selection)
                    ready=threading.Barrier(2); done=threading.Barrier(2); errors=[]; after_competing=[]
                    dispatch=d.dispatch.dispatch
                    def competing():
                        peer=connection_for(d.dispatch, c.delivery_path)
                        try:
                            ready.wait(3)
                            peer.dispatch(q['native_txid'],review['submission_review']['dispatch_confirmation'],replay=True,
                                expected_attempt=review['submission_review']['next_attempt'],
                                expected_transport_status=review['submission_review']['transport_status_before_attempt'])
                            done.wait(3)
                        except BaseException as exc: errors.append(exc)
                        finally: peer.close()
                    def paused(*args,**kwargs):
                        ready.wait(3); done.wait(3)
                        after_competing.extend(d.dispatch.db.iterdump())
                        return dispatch(*args,**kwargs)
                    t=threading.Thread(target=competing); t.start()
                    with patch.object(d.dispatch,'dispatch',side_effect=paused):
                        with self.assertRaisesRegex(ValueError,'attempt changed'):
                            d.send(signed['decision_id'],review['delivery_confirmation'],replay=True,**selection)
                    t.join(4); self.assertFalse(t.is_alive()); self.assertEqual(errors,[])
                    self.assertEqual(list(d.dispatch.db.iterdump()),after_competing)
                current=d.status(signed['decision_id'],**selection)
                self.assertEqual(current['submission_attempts'],2)
                self.assertEqual([a for _,a in submissions],[1,2]); self.assertEqual(submissions[0][0],submissions[1][0])
                self.assertEqual(c.holds(),60)
                claimed=[e['detail']['attempt'] for e in d.dispatch.events(q['native_txid']) if e['event']=='dispatch_committed_before_io']
                self.assertEqual(claimed,[1,2])
        finally: c.close()
