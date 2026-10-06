"""Labeled fake-worker recovery mechanics, separate from actual engine evidence."""
import copy, sqlite3, tempfile, unittest
from pathlib import Path
from test_protocol8_consensus import FakeWorker,f,wire
import protocol8_consensus as p
from protocol8_application import Application
from protocol8_recovery import RecoveryApplication
from protocol8_recovery_abci import dispatch,Request
import protocol8_state_sync as sync
from state_sync import (OFFER_ACCEPT,OFFER_REJECT,OFFER_ABORT,OFFER_REJECT_FORMAT,
                       APPLY_ACCEPT,APPLY_REJECT_SNAPSHOT,APPLY_ABORT,APPLY_RETRY)

class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.w=FakeWorker();fields=[f(v) for v in (8,1,2,3,1,5,6,1,32,1,10,11,12)]
        fields[4]=self.w.root([f(100)]);self.tx=wire(fields)
        self.w.kat_statement=fields;self.w.kat_sha256=p.digest(self.tx)
        self.g={'format':p.GENESIS_FORMAT,'protocol_version':8,'chain_id':'p8-recovery-fake',
            'profile_sha256':p.PROFILE_SHA256,'worker_sha256':self.w.sha256,'kat_sha256':self.w.kat_sha256,
            'validators':[{'public_key':f(v),'power':10} for v in range(1,5)],'pool_id':'cd'*32,
            'asset':f(2),'mission':f(3),'fee':1,'network':f(1),
            'notes':[{'kind':'p8-recipient-v1','commitment':f(100)}]}
        self.raw=p.canonical(self.g);self.temp=tempfile.TemporaryDirectory();self.d=Path(self.temp.name);self.d.chmod(0o700)
        self.source=self.new('source');self.source.init_chain(self.g['chain_id'],self.raw,self.g['validators'])
        self.finalize(self.source,[self.tx]);self.target=self.new('target')
    def new(self,name):return RecoveryApplication(self.d/(name+'.sqlite'),self.w,expected_genesis=self.raw)
    def tearDown(self):self.source.close();self.target.close();self.temp.cleanup()
    def finalize(self,a,txs):
        h=a.height+1;votes=[] if h==1 else [{'address':v.address.hex(),'power':v.power,'block_id_flag':2} for v in a.validators.validators]
        value,response=a.finalize_block(txs,h,b'x'*32,bytes.fromhex(a.validators.hash),votes,b'actual-local-'+str(h).encode());a.commit()
        return value,response
    def snapshot(self):
        d=self.source.list_snapshots()[0];raw=b''.join(self.source.load_snapshot_chunk(d['height'],d['format'],i) for i in range(d['chunks']))
        return d,raw
    def install(self,a=None,d=None,raw=None):
        a=a or self.target
        if d is None:d,raw=self.snapshot()
        self.assertEqual(a.offer_snapshot(d,bytes.fromhex(self.source.app_hash)),OFFER_ACCEPT)
        for i in range(d['chunks']):r=a.apply_snapshot_chunk(i,raw[i*sync.CHUNK_BYTES:(i+1)*sync.CHUNK_BYTES],'peer')
        return r
    def repack(self,value):
        raw=p.canonical(value);m=sync.metadata(self.source,value['height'],value['app_hash'],raw)
        d={'height':value['height'],'format':sync.FORMAT,'chunks':(len(raw)+sync.CHUNK_BYTES-1)//sync.CHUNK_BYTES,'hash':sync.payload_hash(raw),'metadata':m}
        return d,raw
    def test_import_suffix_restart_no_invented_responses(self):
        self.assertEqual(self.install()['result'],APPLY_ACCEPT)
        self.assertEqual(self.target.query('/state'),self.source.query('/state'))
        self.assertEqual(self.target.db.execute('SELECT count(*) FROM p8_blocks').fetchone()[0],0)
        self.target.close();self.target=self.new('target');self.assertTrue(self.target.state_sync.checkpoint_only())
        self.finalize(self.target,[]);self.assertFalse(self.target.state_sync.checkpoint_only())
        self.target.close();self.target=self.new('target');self.assertEqual(self.target.height,2)
        self.assertEqual(self.target.db.execute('SELECT height FROM p8_blocks').fetchall(),[(2,)])
        d,_=self.snapshot();self.assertEqual(self.target.offer_snapshot(d,bytes.fromhex(self.source.app_hash)),OFFER_ABORT)
    def test_trusted_hash_identity_and_geometry_refusals(self):
        d,_=self.snapshot()
        for h in (b'',b'x'*31,b'x'*32):self.assertEqual(self.target.offer_snapshot(d,h),OFFER_REJECT)
        for key,value in [('height',True),('chunks',True),('hash',b'x'*32),('metadata',b'{}')]:
            q=copy.deepcopy(d);q[key]=value;self.assertEqual(self.target.offer_snapshot(q,bytes.fromhex(self.source.app_hash)),OFFER_REJECT)
        q=copy.deepcopy(d);q['format']=1;self.assertEqual(self.target.offer_snapshot(q,bytes.fromhex(self.source.app_hash)),OFFER_REJECT_FORMAT)
        for key,value in [('genesis_sha256','ef'*32),('bootstrap_sha256','ef'*32),('worker_sha256','ef'*32),('kat_sha256','ef'*32),('profile_sha256','ef'*32),('chunk_bytes',True),('payload_bytes',sync.MAX_PAYLOAD_BYTES+1),('chunks',True),('format',True)]:
            q=copy.deepcopy(d);m=p.closed_json(q['metadata'],4096);m[key]=value;q['metadata']=p.canonical(m)
            self.assertEqual(self.target.offer_snapshot(q,bytes.fromhex(self.source.app_hash)),OFFER_REJECT)
        self.assertIsNone(self.target.state)
    def test_rehashed_genesis_state_history_tampers_refused(self):
        _,raw=self.snapshot();base=p.closed_json(raw,sync.MAX_PAYLOAD_BYTES)
        for name in ('genesis','fees','nullifier','history','proof','receipt'):
            v=copy.deepcopy(base)
            if name=='genesis':v['genesis']['notes'][0]['commitment']=f(101)
            elif name=='fees':v['state']['ledger']['fees']+=1
            elif name=='nullifier':v['state']['ledger']['nullifiers'][0]=f(999)
            elif name=='history':v['state']['blocks'][0]['results'][0]['data']='ef'*32
            elif name=='proof':v['state']['blocks'][0]['transactions'][0]=self.tx[:-1].hex()+'01'
            else:v['state']['ledger']['receipts'][0]['statement'][10]=f(999)
            d,b=self.repack(v);self.assertEqual(self.install(d=d,raw=b)['result'],APPLY_REJECT_SNAPSHOT)
            self.assertIsNone(self.target.state)
    def test_order_duplicates_partial_restart_corrupt_payload(self):
        d,raw=self.snapshot();self.assertGreater(d['chunks'],1)
        self.assertEqual(self.target.offer_snapshot(d,bytes.fromhex(self.source.app_hash)),OFFER_ACCEPT)
        self.assertEqual(self.target.apply_snapshot_chunk(1,raw[sync.CHUNK_BYTES:2*sync.CHUNK_BYTES],'peer'),{'result':APPLY_RETRY,'refetch_chunks':[0],'reject_senders':[]})
        first=raw[:sync.CHUNK_BYTES];self.assertEqual(self.target.apply_snapshot_chunk(0,first,'peer')['result'],APPLY_ACCEPT)
        self.assertEqual(self.target.apply_snapshot_chunk(0,first,'peer')['result'],APPLY_ACCEPT)
        self.assertEqual(self.target.apply_snapshot_chunk(0,b'x'+first[1:],'peer')['result'],APPLY_REJECT_SNAPSHOT)
        self.target.close();self.target=self.new('target');self.assertEqual(self.target.apply_snapshot_chunk(1,b'x','peer')['result'],APPLY_ABORT)
        self.assertEqual(self.install()['result'],APPLY_ACCEPT)
        last=d['chunks']-1;chunk=raw[last*sync.CHUNK_BYTES:]
        self.assertEqual(self.target.apply_snapshot_chunk(last,chunk,'peer')['result'],APPLY_ACCEPT)
        self.assertEqual(self.target.apply_snapshot_chunk(last,b'x'+chunk[1:],'peer')['result'],APPLY_REJECT_SNAPSHOT)
    def test_same_newer_rollback_and_pending_refusals(self):
        d1,raw1=self.snapshot();self.assertEqual(self.install()['result'],APPLY_ACCEPT)
        self.assertEqual(self.install()['result'],APPLY_ACCEPT)
        self.finalize(self.source,[]);self.assertEqual(self.install()['result'],APPLY_ACCEPT);self.assertEqual(self.target.height,2)
        self.assertEqual(self.target.offer_snapshot(d1,bytes.fromhex(p.closed_json(raw1,sync.MAX_PAYLOAD_BYTES)['app_hash'])),OFFER_REJECT)
        # Even a self-consistent newer branch cannot replace the known origin.
        changed=copy.deepcopy(self.source.state);changed['blocks'][0]['transactions']=[]
        s=p.initial_state(self.g,self.w)
        for h,b in enumerate(changed['blocks'],1):s,_=p._execute(self.g,s,[bytes.fromhex(t) for t in b['transactions']],h,self.w)
        s,_=p._execute(self.g,s,[],3,self.w);v={'genesis':self.g,'height':3,'state':s,'app_hash':p.application_hash(self.g,3,s)}
        d,b=self.repack(v);self.assertEqual(self.target.offer_snapshot(d,bytes.fromhex(v['app_hash'])),OFFER_ACCEPT)
        for i in range(d['chunks']):r=self.target.apply_snapshot_chunk(i,b[i*sync.CHUNK_BYTES:(i+1)*sync.CHUNK_BYTES],'peer')
        self.assertEqual(r['result'],APPLY_REJECT_SNAPSHOT);self.assertEqual(self.target.height,2)
        votes=[{'address':v.address.hex(),'power':v.power,'block_id_flag':2} for v in self.target.validators.validators]
        self.target.finalize_block([],3,b'x'*32,bytes.fromhex(self.target.validators.hash),votes,b'pending')
        d,_=self.snapshot();self.assertEqual(self.target.offer_snapshot(d,bytes.fromhex(self.source.app_hash)),OFFER_ABORT)
    def test_atomic_install_failure_and_lost_reply_reopen(self):
        self.target.db.execute("CREATE TEMP TRIGGER fail BEFORE INSERT ON p8_snapshot_origin BEGIN SELECT RAISE(ABORT,'injected'); END")
        with self.assertRaises(sqlite3.IntegrityError):self.install()
        self.assertIsNone(self.target.state);self.assertEqual(self.target.db.execute('SELECT count(*) FROM p8_checkpoint').fetchone()[0],0)
        self.target.close();self.target=self.new('target')
        def crash():raise RuntimeError('lost reply after durable commit')
        self.target._after_snapshot_commit=crash
        with self.assertRaises(RuntimeError):self.install()
        self.assertIsNone(self.target.state);self.assertTrue(self.target.closed)
        self.assertEqual(self.target.query('/state')['code'],1)
        with self.assertRaises(p.StateError):self.target.info()
        self.target.close();self.target=self.new('target')
        self.assertEqual(self.target.height,1);self.assertEqual(self.install()['result'],APPLY_ACCEPT)
    def test_origin_and_suffix_tamper_refuse_reopen(self):
        self.install();self.finalize(self.target,[])
        self.target.db.execute("UPDATE p8_blocks SET response=x'00'");self.target.close()
        with self.assertRaises(p.StateError):self.new('target')
        self.source.db.execute("INSERT INTO p8_snapshot_origin VALUES (1,1,?, ?, x'7b7d')",(self.source.app_hash,'ab'*32));self.source.close()
        with self.assertRaises(p.StateError):self.new('source')
    def test_store_versions_refuse_each_other(self):
        old=Application(self.d/'old.sqlite',self.w,expected_genesis=self.raw);old.close()
        with self.assertRaises(p.StateError):self.new('old')
        self.target.close()
        with self.assertRaises(p.StateError):Application(self.d/'target.sqlite',self.w,expected_genesis=self.raw)
    def test_missing_reordered_or_nonextending_suffix_refuse(self):
        self.install();self.finalize(self.target,[]);self.finalize(self.target,[])
        for name in ('missing','reordered','origin-branch'):
            path=self.d/(name+'.sqlite');self.target.db.backup(sqlite3.connect(path));path.chmod(0o600)
            with sqlite3.connect(path) as db:
                if name=='missing':db.execute('DELETE FROM p8_blocks WHERE height=2')
                elif name=='reordered':db.execute('UPDATE p8_blocks SET height=4 WHERE height=2')
                else:
                    s=p.initial_state(self.g,self.w);s,_=p._execute(self.g,s,[],1,self.w)
                    v={'genesis':self.g,'height':1,'state':s,'app_hash':p.application_hash(self.g,1,s)}
                    b=p.canonical(v);db.execute('UPDATE p8_snapshot_origin SET app_hash=?,payload_sha256=?,payload=?',
                                                (v['app_hash'],sync.payload_hash(b).hex(),b))
            with self.assertRaises(p.StateError):self.new(name)
    def test_malformed_final_and_metadata_are_refusals(self):
        d,raw=self.snapshot()
        for metadata in (b'x'*4097,b'['*1100+b']'*1100,b'{}\n'):
            q=copy.deepcopy(d);q['metadata']=metadata
            self.assertEqual(self.target.offer_snapshot(q,bytes.fromhex(self.source.app_hash)),OFFER_REJECT)
        self.assertEqual(self.target.offer_snapshot(d,bytes.fromhex(self.source.app_hash)),OFFER_ACCEPT)
        for i in range(d['chunks']):
            b=raw[i*sync.CHUNK_BYTES:(i+1)*sync.CHUNK_BYTES]
            if i==d['chunks']-1:b=b[:-1]+b'x'
            r=self.target.apply_snapshot_chunk(i,b,'peer')
        self.assertEqual(r['result'],APPLY_REJECT_SNAPSHOT);self.assertIsNone(self.target.state)
    def test_wire_callbacks_cache_and_no_history_invention(self):
        q=Request();q.list_snapshots.SetInParent();r=dispatch(self.source,q);s=r.list_snapshots.snapshots[0]
        d={'height':s.height,'format':s.format,'chunks':s.chunks,'hash':bytes(s.hash),'metadata':bytes(s.metadata)}
        q=Request();q.offer_snapshot.snapshot.CopyFrom(s);q.offer_snapshot.app_hash=bytes.fromhex(self.source.app_hash)
        self.assertEqual(dispatch(self.target,q).offer_snapshot.result,OFFER_ACCEPT)
        self.finalize(self.source,[]);self.source.list_snapshots()
        for i in range(d['chunks']):
            q=Request();q.load_snapshot_chunk.height=d['height'];q.load_snapshot_chunk.format=d['format'];q.load_snapshot_chunk.chunk=i
            b=dispatch(self.source,q).load_snapshot_chunk.chunk
            q=Request();q.apply_snapshot_chunk.index=i;q.apply_snapshot_chunk.chunk=b;q.apply_snapshot_chunk.sender='peer'
            self.assertEqual(dispatch(self.target,q).apply_snapshot_chunk.result,APPLY_ACCEPT)
        self.assertEqual(self.target.height,1)
        self.assertEqual(self.source.load_snapshot_chunk(True,8,0),b'')
        self.assertEqual(self.source.load_snapshot_chunk(1,1,0),b'')
        self.assertEqual(self.source.load_snapshot_chunk(1,8,True),b'')

if __name__=='__main__':unittest.main()
