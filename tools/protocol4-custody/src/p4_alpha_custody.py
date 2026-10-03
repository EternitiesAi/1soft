"""Complete encrypted alpha history; reconstruction is strictly inert.

No private keys, signer, dispatch, active journal restore or trust renewal API.
Portable receipts prove original signed native execution under external pins;
they do not certify private wallet approval history or current authority.
"""
from __future__ import annotations
import base64
from contextlib import closing,contextmanager
import copy
import hashlib
import os
from pathlib import Path
import secrets
import sqlite3
import tempfile
import time

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from block_application import encode
from commit_verifier import exact,load_json
from development_profile import max_height_for
from offline_signer import _password
from p4_evidence import content_id,hash_text,integer,need,p4_genesis,_receipt_from_verified_report
from p4_incremental_evidence import policy_v2_checked
from p4_incremental_store import P4IncrementalStore,APPLICATION_ID as HISTORY_ID,ARCHIVE_FORMAT
from p4_alpha_wallet import P4AlphaWallet,APPLICATION_ID as WALLET_ID
from p4_alpha_delivery import P4AlphaDelivery
from p4_wallet import pending,revision
from p4_delivery import P4Delivery
from p4_custody import (_private_source,_read,separate_paths,_publish_parts,_cell)
from p4_read_store import private_path
from payment_rpc import endpoint_port

MAGIC=b'1SOFTP4A1\n'
RECOVERY_MAGIC=b'1SOFTP4AH1\n'
BACKUP_FORMAT='1soft/p4-alpha-recovery-backup/v1'
SNAPSHOT_FORMAT='1soft/p4-alpha-journal-snapshot/v1'
RECOVERY_FORMAT='1soft/p4-alpha-inert-history/v1'
RECEIPT_FORMAT='1soft/p4-alpha-receipt-capsule/v1'
REFERENCE_FORMAT='1soft/p4-alpha-receipt-reference/v1'
MAX_HISTORY_BYTES=64*1024*1024
MAX_JOURNAL_BYTES=32*1024*1024
MAX_PLAINTEXT_BYTES=128*1024*1024
MAX_BACKUP_BYTES=180*1024*1024
MAX_ARCHIVE_BYTES=MAX_PLAINTEXT_BYTES+4096
MAX_RECEIPT_BYTES=MAX_HISTORY_BYTES+65536
MAX_CELL_BYTES=32768
KDF={'name':'scrypt','n':32768,'r':8,'p':1,'length':32}

WALLET_SCHEMA={
 'config':('id INTEGER PRIMARY KEY CHECK(id=1),version INTEGER NOT NULL,wallet_id TEXT NOT NULL,policy BLOB NOT NULL,created_ns INTEGER NOT NULL,store_id TEXT NOT NULL',1),
 'observations':('seq INTEGER PRIMARY KEY,evidence_id TEXT UNIQUE NOT NULL,parent_id TEXT NOT NULL,checked_ns INTEGER NOT NULL,payload BLOB NOT NULL',4096),
 'decisions':('seq INTEGER PRIMARY KEY,decision_id TEXT UNIQUE NOT NULL,signed_ns INTEGER NOT NULL,payload BLOB NOT NULL',256)}
DELIVERY_SCHEMA={
 'config':('id INTEGER PRIMARY KEY CHECK(id=1),version INTEGER NOT NULL,delivery_id TEXT NOT NULL,wallet_id TEXT NOT NULL,policy_id TEXT NOT NULL,genesis_sha256 TEXT NOT NULL,endpoint TEXT NOT NULL,created_ns INTEGER NOT NULL',1),
 'attempts':('seq INTEGER PRIMARY KEY,decision_id TEXT UNIQUE NOT NULL,claimed_ns INTEGER NOT NULL,review BLOB NOT NULL',256),
 'responses':('decision_id TEXT PRIMARY KEY,observed_ns INTEGER NOT NULL,payload BLOB NOT NULL',256),
 'receipts':('seq INTEGER PRIMARY KEY,decision_id TEXT UNIQUE NOT NULL,evidence_id TEXT NOT NULL,checked_ns INTEGER NOT NULL,payload BLOB NOT NULL',256)}
HISTORY_SCHEMA={
 'config':'id INTEGER PRIMARY KEY CHECK(id=1),version INTEGER NOT NULL,store_id TEXT NOT NULL,genesis_sha256 TEXT NOT NULL,policy_id TEXT NOT NULL,policy BLOB NOT NULL',
 'headers':'height INTEGER PRIMARY KEY,digest TEXT NOT NULL,payload BLOB NOT NULL',
 'blocks':'height INTEGER PRIMARY KEY,digest TEXT NOT NULL,payload BLOB NOT NULL',
 'checkpoints':'seq INTEGER PRIMARY KEY,checkpoint_id TEXT UNIQUE NOT NULL,height INTEGER NOT NULL,checked_ns INTEGER NOT NULL,payload BLOB NOT NULL'}


def _rows(db,schema):
    result={};total=0
    for table,(_,limit) in schema.items():
        payload='review' if table=='attempts' else 'payload'
        count,size=db.execute(f'SELECT count(*),coalesce(sum(length({payload})),0) FROM {table}').fetchone() if table!='config' else (1,0)
        need(count<=limit and size<=MAX_JOURNAL_BYTES,'journal capture quota exceeded')
        rows=db.execute(f'SELECT * FROM {table} ORDER BY 1').fetchmany(limit+1)
        need(len(rows)<=limit,'complete journal row quota exceeded')
        for row in rows:
            for value in row:
                if type(value) is bytes:
                    need(len(value)<=MAX_CELL_BYTES,'journal cell quota exceeded')
                    total+=len(value)
        result[table]=[[_cell(v) for v in row] for row in rows]
    need(total<=MAX_JOURNAL_BYTES,'complete journal byte quota exceeded')
    return result


def _decoded(value):
    if type(value) is dict:
        exact(value,{'hex'},'alpha journal byte cell')
        text=value['hex']
        need(type(text) is str and len(text)<=2*MAX_CELL_BYTES,'bounded journal cell required')
        try:raw=bytes.fromhex(text)
        except ValueError as exc:raise ValueError('invalid journal cell') from exc
        need(raw.hex()==text,'noncanonical journal cell')
        return raw
    need(type(value) in (int,str),'exact journal scalar required')
    if type(value) is int:integer(value)
    else:need(len(value)<=4096,'journal text quota exceeded')
    return value


def _memory(data,schema,app_id):
    exact(data,set(schema),'fixed alpha journal tables')
    db=sqlite3.connect(':memory:',isolation_level=None)
    try:
        db.execute(f'PRAGMA application_id={app_id}')
        total=0
        for table,(columns,limit) in schema.items():
            rows=data[table];need(type(rows) is list and len(rows)<=limit,'journal row quota exceeded')
            db.execute(f'CREATE TABLE {table}({columns})')
            count=len(db.execute(f'PRAGMA table_info({table})').fetchall())
            for row in rows:
                need(type(row) is list and len(row)==count,'fixed journal row shape required')
                cells=[_decoded(v) for v in row]
                total+=sum(len(v) for v in cells if type(v) is bytes)
                need(total<=MAX_JOURNAL_BYTES,'complete journal byte quota exceeded')
                db.execute(f'INSERT INTO {table} VALUES ({",".join("?" for _ in cells)})',cells)
        need(_rows(db,schema)==data,'journal encoding changed during reconstruction')
        db.execute('PRAGMA query_only=ON')
        return db
    except BaseException:db.close();raise


def _history_checked(value,genesis,policy):
    need(len(encode(value))<=MAX_HISTORY_BYTES,'complete history exceeds custody quota; no eviction')
    exact(value,{'schema','format','store_id','genesis_b64','policy','headers','history','checkpoints'},
          'canonical retained alpha history')
    integer(value['schema'],1,1);need(value['format']==ARCHIVE_FORMAT,'unsupported alpha history')
    hash_text(value['store_id']);p=policy_v2_checked(policy)
    need(type(value['genesis_b64']) is str and
         value['genesis_b64']==base64.b64encode(bytes(genesis)).decode() and
         encode(value['policy'])==encode(p),'external original history pins differ')
    p4_genesis(bytes(genesis),p['genesis_sha256'])
    for name in ('headers','history','checkpoints'):
        need(type(value[name]) is list and len(value[name])<=4097,'bounded complete history arrays required')
    height=len(value['history'])
    need(len(value['headers'])==(height+1 if height else 0) and
         len(value['checkpoints'])<=(4096 if height else 0),'complete history lengths differ')
    need(bool(height)==bool(value['checkpoints']),'history has no original checkpoint admission')
    return p


@contextmanager
def _historical_store(value,genesis,policy):
    p=_history_checked(value,genesis,policy)
    with tempfile.TemporaryDirectory(prefix='.1soft-alpha-inert-audit-') as folder:
        path=Path(folder)/'history.sqlite'
        fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600);os.close(fd)
        with closing(sqlite3.connect(path,isolation_level=None)) as db:
            db.execute('PRAGMA journal_mode=WAL');db.execute('PRAGMA synchronous=FULL')
            db.execute('BEGIN IMMEDIATE')
            try:
                db.execute(f'PRAGMA application_id={HISTORY_ID}')
                for table,columns in HISTORY_SCHEMA.items():db.execute(f'CREATE TABLE {table}({columns})')
                db.execute('INSERT INTO config VALUES(1,1,?,?,?,?)',
                    (value['store_id'],p['genesis_sha256'],content_id(p),encode(p)))
                for table,key in (('headers','headers'),('blocks','history')):
                    for row in value[key]:
                        height=row['height'] if table=='blocks' else int(row['signed_header']['header']['height'])
                        integer(height,1,4097);raw=encode(row)
                        need(len(raw)<=16*1024*1024,'history item exceeds quota')
                        db.execute(f'INSERT INTO {table} VALUES(?,?,?)',
                                   (height,hashlib.sha256(raw).hexdigest(),raw))
                for seq,cp in enumerate(value['checkpoints'],1):
                    raw=encode(cp);need(len(raw)<=4096,'checkpoint descriptor exceeds quota')
                    db.execute('INSERT INTO checkpoints VALUES(?,?,?,?,?)',
                        (seq,cp['id'],cp['height'],cp['checked_ns'],raw))
                db.execute('COMMIT')
            except BaseException:
                if db.in_transaction:db.execute('ROLLBACK')
                raise
        with P4IncrementalStore(path,bytes(genesis),p,read_only=True) as store:
            descriptors=store.checkpoint_descriptors()  # Full cryptographic/native/admin cold audit.
            yield store,descriptors,Path(folder)


class _WalletAudit:
    """Historical-only facade: no inherited approval, signer or journal mutation."""
    def __init__(self,db,path,genesis,policy,store):
        self.db,self.path,self.genesis=db,path,bytes(genesis)
        self.policy=policy_v2_checked(policy);self.policy_id=content_id(self.policy)
        self._policy_bytes=encode(self.policy);self.store=store;self.store_id=store.store_id
        g,_=p4_genesis(self.genesis,self.policy['genesis_sha256']);self.height_limit=max_height_for(g)
        self._active_checkpoint=None
    _catalog=P4AlphaWallet._catalog
    _origin_fresh=P4AlphaWallet._origin_fresh
    _transfer_review=P4AlphaWallet._transfer_review
    _rotation_review=P4AlphaWallet._rotation_review
    _decision_review=P4AlphaWallet._decision_review
    def load(self):return P4AlphaWallet._load(self,historical=True)


class _DeliveryAudit:
    """Only original configuration, selection and historical audit are available."""
    APPLICATION_ID=P4AlphaDelivery.APPLICATION_ID
    VERSION=2
    REVIEW_FORMAT=P4AlphaDelivery.REVIEW_FORMAT
    _config=P4Delivery._config
    _derive_review=P4Delivery._derive_review
    def __init__(self,db,path,wallet,wallet_id,store):
        self.db,self.path,self.wallet,self.wallet_id,self.store=db,path,wallet,wallet_id,store
        row=db.execute('SELECT * FROM config').fetchone()
        need(row is not None and len(row)==8,'delivery config missing')
        self.endpoint=row[6];endpoint_port(self.endpoint);self.config=self._config()
    def audit(self,decisions):return P4AlphaDelivery._audit(self,decisions)


def _validate(snapshot,genesis,policy):
    exact(snapshot,{'schema','format','captured_ns','history','wallet','delivery'},'complete alpha snapshot')
    integer(snapshot['schema'],1,1);need(snapshot['format']==SNAPSHOT_FORMAT,'unsupported alpha snapshot')
    captured=integer(snapshot['captured_ns'])
    p=policy_v2_checked(policy)
    need(captured<=time.time_ns()+p['max_clock_drift_seconds']*10**9,
         'snapshot capture claims a future host time')
    need(len(encode(snapshot))<=MAX_PLAINTEXT_BYTES,'snapshot plaintext quota exceeded')
    with _historical_store(snapshot['history'],genesis,p) as (store,descriptors,folder):
        with closing(_memory(snapshot['wallet'],WALLET_SCHEMA,WALLET_ID)) as wdb:
            with closing(_memory(snapshot['delivery'],DELIVERY_SCHEMA,P4AlphaDelivery.APPLICATION_ID)) as ddb:
                wallet=_WalletAudit(wdb,folder/'inert-wallet-audit',genesis,p,store)
                wid,context,report,decisions,last=wallet.load()
                delivery=_DeliveryAudit(ddb,folder/'inert-delivery-audit',wallet,wid,store)
                attempts,responses,receipts,delivery_last=delivery.audit(decisions)
                total=sum(len(v) for db,schema in ((wdb,WALLET_SCHEMA),(ddb,DELIVERY_SCHEMA))
                          for table in schema for row in db.execute(f'SELECT * FROM {table}')
                          for v in row if type(v) is bytes)
                need(total<=MAX_JOURNAL_BYTES,'complete financial journal quota exceeded')
                latest=max(last,delivery_last,*(cp['checked_ns'] for cp in descriptors.values()))
                need(latest<=captured,'snapshot capture predates retained original records')
                return {'wallet_id':wid,'delivery_id':delivery.config[2],'policy_id':wallet.policy_id,
                    'store_id':store.store_id,'report':report,'decisions':decisions,
                    'held':pending(report,decisions),'attempts':attempts,'responses':responses,
                    'receipts':receipts,'last_ns':latest}


def capture(delivery):
    need(type(delivery) is P4AlphaDelivery,'one existing bound alpha delivery required')
    wallet=delivery.wallet
    with wallet.atomic(write=False):
        with delivery.atomic(write=False):
            # Audit the live files before fixed-schema reconstruction can normalize
            # their application IDs or catalogs. Historical export grants no authority.
            _,_,_,decisions,_=wallet._load(historical=True)
            delivery._audit(decisions)
            # Fixed read transaction ordering: wallet, delivery, then store.
            history=load_json(delivery.store.export_history(),max_bytes=MAX_HISTORY_BYTES)
            snapshot={'schema':1,'format':SNAPSHOT_FORMAT,'captured_ns':time.time_ns(),
                      'history':history,'wallet':_rows(wallet.db,WALLET_SCHEMA),
                      'delivery':_rows(delivery.db,DELIVERY_SCHEMA)}
    _validate(snapshot,wallet.genesis,wallet.policy)
    return snapshot


def _seal(snapshot,password):
    _password(password)
    plaintext=encode(snapshot);need(len(plaintext)<=MAX_PLAINTEXT_BYTES,'alpha plaintext quota exceeded')
    salt,nonce=secrets.token_bytes(32),secrets.token_bytes(12)
    header={'schema':1,'format':BACKUP_FORMAT,'kdf':KDF.copy(),'cipher':'aes-256-gcm',
            'salt':salt.hex(),'nonce':nonce.hex()}
    key=Scrypt(salt=salt,length=32,n=32768,r=8,p=1).derive(password)
    ciphertext=AESGCM(key).encrypt(nonce,plaintext,MAGIC+encode(header))
    raw=MAGIC+encode({'header':header,'ciphertext':base64.b64encode(ciphertext).decode()})
    need(len(raw)<=MAX_BACKUP_BYTES,'encrypted alpha backup quota exceeded')
    return raw


def _unseal(raw,password):
    _password(password)
    need(type(raw) is bytes and len(raw)<=MAX_BACKUP_BYTES and raw.startswith(MAGIC),
         'explicit bounded alpha backup required')
    value=load_json(raw[len(MAGIC):],max_bytes=MAX_BACKUP_BYTES)
    exact(value,{'header','ciphertext'},'alpha encrypted envelope')
    need(MAGIC+encode(value)==raw,'noncanonical alpha encrypted envelope')
    h=value['header'];exact(h,{'schema','format','kdf','cipher','salt','nonce'},'alpha encryption header')
    integer(h['schema'],1,1)
    need(h['format']==BACKUP_FORMAT and h['cipher']=='aes-256-gcm' and encode(h['kdf'])==encode(KDF),
         'unsupported fixed alpha cryptographic parameters')
    for name,size in (('salt',32),('nonce',12)):
        text=h[name];need(type(text) is str and len(text)==size*2,'invalid encryption metadata')
        try:decoded=bytes.fromhex(text)
        except ValueError as exc:raise ValueError('invalid encryption metadata') from exc
        need(decoded.hex()==text,'noncanonical encryption metadata')
    text=value['ciphertext']
    need(type(text) is str and len(text)<=(MAX_PLAINTEXT_BYTES+18)//3*4,'ciphertext quota exceeded')
    try:ciphertext=base64.b64decode(text,validate=True)
    except ValueError as exc:raise ValueError('invalid ciphertext encoding') from exc
    need(16<=len(ciphertext)<=MAX_PLAINTEXT_BYTES+16 and
         base64.b64encode(ciphertext).decode()==text,'ciphertext size or encoding differs')
    key=Scrypt(salt=bytes.fromhex(h['salt']),length=32,n=32768,r=8,p=1).derive(password)
    try:plaintext=AESGCM(key).decrypt(bytes.fromhex(h['nonce']),ciphertext,MAGIC+encode(h))
    except InvalidTag as exc:raise ValueError('unable to authenticate alpha backup') from exc
    snapshot=load_json(plaintext,max_bytes=MAX_PLAINTEXT_BYTES)
    need(encode(snapshot)==plaintext,'noncanonical alpha plaintext')
    return snapshot


def backup(delivery,output,password):
    need(type(delivery) is P4AlphaDelivery,'explicit alpha backup source required')
    _,_,_,output=separate_paths(delivery.wallet.path,delivery.path,delivery.store.path,output)
    snapshot=capture(delivery);raw=_seal(snapshot,password)
    _publish_parts(output,(raw,),MAX_BACKUP_BYTES)
    return {'status':'complete-alpha-history-backup','snapshot_id':content_id(snapshot),
            'backup_sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw),
            'signing_enabled':False,'source_journals_modified':False,'private_keys_included':False}


def restore_backup(backup_path,output,genesis,policy,password):
    backup_path,output=separate_paths(backup_path,output)
    snapshot=_unseal(_read(backup_path,MAX_BACKUP_BYTES),password)
    _validate(snapshot,bytes(genesis),policy)
    value={'schema':1,'format':RECOVERY_FORMAT,'snapshot_id':content_id(snapshot),'snapshot':snapshot}
    raw=RECOVERY_MAGIC+encode(value)
    need(len(raw)<=MAX_ARCHIVE_BYTES,'inert archive quota exceeded')
    _publish_parts(output,(raw,),MAX_ARCHIVE_BYTES)
    return {'status':'restored-alpha-recovery-only','snapshot_id':value['snapshot_id'],
        'archive_sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw),
        'signing_enabled':False,'dispatch_enabled':False,'old_device_fenced':False,
        'latestness_established':False,'private_keys_restored':False,'trust_policy_renewed':False}


def _history_at(value,checkpoint_id):
    hash_text(checkpoint_id)
    matches=[(i,cp) for i,cp in enumerate(value['checkpoints']) if cp['id']==checkpoint_id]
    need(len(matches)==1,'original receipt checkpoint not retained')
    index,cp=matches[0];height=integer(cp['height'],1,4096)
    return {**value,'history':value['history'][:height],'headers':value['headers'][:height+1],
            'checkpoints':value['checkpoints'][:index+1]}


def _reference(decision,checkpoint_id,genesis,policy,store_id):
    body=decision['review']['body'];wire=bytes.fromhex(decision['wire_hex'])
    return {'schema':1,'format':REFERENCE_FORMAT,'genesis_sha256':hashlib.sha256(genesis).hexdigest(),
        'policy_id':content_id(policy),'store_id':store_id,'checkpoint_id':checkpoint_id,
        'wire_sha256':hashlib.sha256(wire).hexdigest(),'payer':body['sender'],'decision_id':decision['id']}


def receipt_reference(delivery,decision_id,*,payer,grant_id=''):
    need(type(delivery) is P4AlphaDelivery,'original alpha receipt source required')
    with delivery.wallet.atomic(write=False):
        _,_,_,ds,_=delivery.wallet._load(historical=True)
        d=P4Delivery._selected(ds,decision_id,payer,grant_id)
        with delivery.atomic(write=False):
            _,_,receipts,_=delivery._audit(ds)
            need(decision_id in receipts,'original positive receipt unavailable; no absence proof')
            return _reference(d,receipts[decision_id]['checkpoint_id'],
                delivery.wallet.genesis,delivery.wallet.policy,delivery.store.store_id)


def _capsule(history,reference,wire):
    return encode({'schema':1,'format':RECEIPT_FORMAT,'reference':reference,
                   'capsule_id':content_id(reference),'wire_hex':wire.hex(),'history':history})


def make_receipt(delivery,decision_id,*,payer,grant_id='',checkpoint_id=None):
    need(type(delivery) is P4AlphaDelivery,'original alpha receipt source required')
    with delivery.wallet.atomic(write=False):
        _,_,_,ds,_=delivery.wallet._load(historical=True)
        d=P4Delivery._selected(ds,decision_id,payer,grant_id)
        with delivery.atomic(write=False):
            _,_,receipts,_=delivery._audit(ds)
            need(decision_id in receipts,'original positive receipt unavailable; no absence proof')
            selected=receipts[decision_id]['checkpoint_id'] if checkpoint_id is None else hash_text(checkpoint_id)
            view=delivery.store.checkpoint_at(selected,historical=True)
            from p4_wallet import matched_receipt
            need(matched_receipt(view['report'],d) is not None,'selected checkpoint has no original positive receipt')
            history=load_json(delivery.store.export_history(),max_bytes=MAX_HISTORY_BYTES)
            prefix=_history_at(history,selected)
            ref=_reference(d,selected,delivery.wallet.genesis,delivery.wallet.policy,delivery.store.store_id)
            raw=_capsule(prefix,ref,bytes.fromhex(d['wire_hex']))
    need(len(raw)<=MAX_RECEIPT_BYTES,'complete portable receipt quota exceeded')
    return raw


def verify_receipt(raw,genesis,policy,*,payer,wire_sha256):
    need(type(raw) is bytes and 0<len(raw)<=MAX_RECEIPT_BYTES,'bounded alpha receipt required')
    value=load_json(raw,max_bytes=MAX_RECEIPT_BYTES)
    exact(value,{'schema','format','reference','capsule_id','wire_hex','history'},'alpha receipt capsule')
    integer(value['schema'],1,1);need(value['format']==RECEIPT_FORMAT and encode(value)==raw,
                                    'unsupported or noncanonical alpha receipt')
    ref=value['reference']
    exact(ref,{'schema','format','genesis_sha256','policy_id','store_id','checkpoint_id',
               'wire_sha256','payer','decision_id'},'original alpha receipt reference')
    integer(ref['schema'],1,1);need(ref['format']==REFERENCE_FORMAT,'unsupported receipt reference')
    p=policy_v2_checked(policy);hash_text(wire_sha256);hash_text(ref['decision_id'])
    for key in ('genesis_sha256','policy_id','store_id','checkpoint_id','wire_sha256'):hash_text(ref[key])
    need(ref['payer']==payer and ref['wire_sha256']==wire_sha256 and
         ref['genesis_sha256']==hashlib.sha256(bytes(genesis)).hexdigest() and
         ref['policy_id']==content_id(p) and value['capsule_id']==content_id(ref),
         'external payer/wire/genesis/policy or receipt identity differs')
    text=value['wire_hex'];need(type(text) is str and 0<len(text)<=32768,'bounded original wire required')
    try:wire=bytes.fromhex(text)
    except ValueError as exc:raise ValueError('invalid receipt wire') from exc
    need(wire.hex()==text and hashlib.sha256(wire).hexdigest()==wire_sha256,
         'original signed wire changed')
    with _historical_store(value['history'],bytes(genesis),p) as (store,descriptors,_):
        need(store.store_id==ref['store_id'] and value['history']['checkpoints'] and
             value['history']['checkpoints'][-1]['id']==ref['checkpoint_id'],
             'receipt prefix original identity differs')
        view=store.checkpoint_at(ref['checkpoint_id'],historical=True)
        need(view['checkpoint']['lookahead_time_ns']<=time.time_ns()+p['max_clock_drift_seconds']*10**9,
             'receipt claims a future signed checkpoint')
        found=_receipt_from_verified_report(view['report'],wire,payer)
        need(found['status']=='recorded','exact successful included receipt unavailable; no absence proof')
        return {'status':'verified-historical-alpha-receipt','capsule_id':content_id(ref),
            'packet_sha256':hashlib.sha256(raw).hexdigest(),'reference':copy.deepcopy(ref),
            'receipt':found['receipt'],'state_height':view['report']['state_height'],
            'header_hash':view['report']['header_hash'],'historical_only':True,
            'current_spending_authority':False,'latestness_established':False,
            'approval_journal_verified':False,'source_host_admission_times_authenticated':False,
            'old_device_fenced':False,'historical_absence_proven':False,
            'wallet_reservations_changed':False,'external_settlement_verified':False}


class RecoveryArchive:
    """Private inert record. No inherited wallet, delivery, signing or dispatch API."""
    def __init__(self,path,genesis,policy):
        self.path=private_path(path);self.genesis=bytes(genesis);self.policy=policy_v2_checked(policy)
        raw=_read(self.path,MAX_ARCHIVE_BYTES)
        need(raw.startswith(RECOVERY_MAGIC),'explicit alpha inert archive required')
        value=load_json(raw[len(RECOVERY_MAGIC):],max_bytes=MAX_ARCHIVE_BYTES)
        exact(value,{'schema','format','snapshot_id','snapshot'},'inert alpha archive')
        integer(value['schema'],1,1)
        need(value['format']==RECOVERY_FORMAT and RECOVERY_MAGIC+encode(value)==raw and
             value['snapshot_id']==content_id(value['snapshot']),'inert archive format or content differs')
        self._snapshot=encode(value['snapshot']);self.snapshot_id=value['snapshot_id']
        _validate(value['snapshot'],self.genesis,self.policy)
    def close(self):self._snapshot=None
    def __enter__(self):return self
    def __exit__(self,*_):self.close()
    def _audit(self):
        need(self._snapshot is not None,'inert recovery archive is closed')
        return _validate(load_json(self._snapshot,max_bytes=MAX_PLAINTEXT_BYTES),self.genesis,self.policy)
    def inspect(self):
        a=self._audit();held={d['id'] for d in a['held']};decisions=[]
        for d in a['decisions']:
            did=d['id']
            decisions.append({'id':did,'payer':d['review']['body']['sender'],
                'grant_id':d['review']['body']['grant_id'],'debit_units':d['review']['debit_units'],
                'pending':did in held,'attempt_recorded':did in a['attempts'],
                'transport_observation':a['responses'].get(did,{}).get('observation',
                    'unresolved' if did in a['attempts'] else 'not_attempted'),
                'wallet_receipt_status':'unavailable' if did in held else 'recorded',
                'delivery_receipt_status':'verified_historical_receipt' if did in a['receipts'] else 'unavailable',
                'wire_sha256':hashlib.sha256(bytes.fromhex(d['wire_hex'])).hexdigest(),'safe_to_resend':False})
        budgets=[{'id':b[0],'cap':str(b[3]),'spent':str(b[4]),
            'pending_debit_units':str(sum(int(d['review']['debit_units']) for d in a['held']
                                         if d['review']['budget_id']==b[0]))} for b in a['report']['budgets']]
        return {'status':'verified-historical-alpha-recovery-archive','snapshot_id':self.snapshot_id,
            'wallet_id':a['wallet_id'],'delivery_id':a['delivery_id'],'store_id':a['store_id'],
            'wallet_revision':revision(a['wallet_id'],a['policy_id'],a['report']['evidence_id'],a['decisions']),
            'state_height':a['report']['state_height'],'registry_epoch':a['report']['registry_epoch'],
            'historical_checked_at_ns':a['last_ns'],'budgets':budgets,'decisions':decisions,
            'pending_debit_units':str(sum(int(d['review']['debit_units']) for d in a['held'])),
            'latestness_established':False,'old_device_fenced':False,'current_spending_authority':False,
            'signing_enabled':False,'dispatch_enabled':False,'automatic_resend':False,
            'trust_policy_renewed':False,'private_keys_restored':False}
    def recover(self,decision_id,*,payer,grant_id=''):
        a=self._audit();d=P4Delivery._selected(a['decisions'],decision_id,payer,grant_id)
        return bytes.fromhex(d['wire_hex'])
    def export_receipt(self,decision_id,*,payer,grant_id=''):
        a=self._audit();d=P4Delivery._selected(a['decisions'],decision_id,payer,grant_id)
        need(decision_id in a['receipts'],'original exact receipt unavailable; outcome unknown')
        snapshot=load_json(self._snapshot,max_bytes=MAX_PLAINTEXT_BYTES)
        cid=a['receipts'][decision_id]['checkpoint_id']
        history=_history_at(snapshot['history'],cid)
        ref=_reference(d,cid,self.genesis,self.policy,a['store_id'])
        raw=_capsule(history,ref,bytes.fromhex(d['wire_hex']))
        need(len(raw)<=MAX_RECEIPT_BYTES,'portable receipt quota exceeded')
        return raw
