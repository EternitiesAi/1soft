"""Trusted-host local atomic treasury ledger. Not consensus or certified settlement."""
from __future__ import annotations
import copy,hashlib,json,os,sqlite3,stat,subprocess
from pathlib import Path

PROFILE='1soft/private-treasury-payment-lab/halo2-pasta/v1'
FIELD_MODULUS=0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001
ZERO='00'*32
SIZE=4008
MAX_U64=2**64-1

def canonical(value):return json.dumps(value,separators=(',',':'),sort_keys=True).encode()
def field(value):
    if type(value) is not str or len(value)!=64 or value.lower()!=value:
        raise ValueError('canonical field required')
    try:raw=bytes.fromhex(value)
    except ValueError:raise ValueError('canonical field required') from None
    if len(raw)!=32 or int.from_bytes(raw,'little')>=FIELD_MODULUS:raise ValueError('field range')
    return raw
def number(value):
    if type(value) is not int or not 0<=value<=MAX_U64:raise ValueError('u64 required')
    return value
def integer(f):
    value=int.from_bytes(field(f),'little');number(value);return value
def numfield(n):return number(n).to_bytes(32,'little').hex()
def parse(raw):
    if type(raw) is not bytes or len(raw)!=SIZE or raw[:8]!=b'1STPAY01':raise ValueError('exact local transaction required')
    p=[raw[8+i*32:8+(i+1)*32].hex() for i in range(25)]
    for f in p:field(f)
    if integer(p[0])!=1 or integer(p[15])>=integer(p[16]):raise ValueError('version or interval')
    for i in range(19):
        if p[i]==ZERO:raise ValueError('zero public field')
    for i in range(20,24):
        if p[i]==ZERO:raise ValueError('zero note field')
    if p[22]==p[23]:raise ValueError('identical outputs')
    for i in range(14,18):integer(p[i])
    return p
def txid(raw):parse(raw);return hashlib.sha256(b'1soft/private-treasury-payment-lab/transaction/v1\0'+raw).hexdigest()

class Bridge:
    """Exact-binary bounded subprocess calls; no mock or unavailable-proof fallback."""
    def __init__(self,binary:Path,expected_sha256:str):
        self.binary=Path(binary).resolve(strict=True);self.expected=expected_sha256
        self._check_binary()
    def _check_binary(self):
        if not self.binary.is_file() or hashlib.sha256(self.binary.read_bytes()).hexdigest()!=self.expected:
            raise ValueError('verifier binary identity differs')
    def call(self,operation,raw):
        self._check_binary()
        result=subprocess.run([str(self.binary),operation],input=raw,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=45)
        if result.returncode:raise ValueError('local cryptographic bridge refused')
        return result.stdout
    def verify(self,raw):
        parse(raw)
        if self.call('verify',raw)!=b'verified\n':raise ValueError('verifier response')
    def context_root(self,state):
        fields=[state[k] for k in ['genesis','asset','mission','parent_id']]+[numfield(state['epoch']),state['parent']]
        for pair in state['grants']:fields.extend(pair)
        root=self.call('context-root',b''.join(field(f) for f in fields))
        if len(root)!=32:raise ValueError('context response')
        return root.hex()
    def note_root(self,notes):
        root=self.call('note-root',b''.join(field(f) for f in notes))
        if len(root)!=32:raise ValueError('tree response')
        return root.hex()

def connection(path:Path):
    path=Path(path).absolute()
    if os.name!='posix':raise ValueError('POSIX trusted-host component')
    if path.parent.is_symlink() or not path.parent.is_dir() or stat.S_IMODE(path.parent.stat().st_mode)!=0o700:
        raise ValueError('private directory required')
    if path.is_symlink() or (path.exists() and (not path.is_file() or stat.S_IMODE(path.stat().st_mode)!=0o600)):
        raise ValueError('private regular database required')
    # Explicit file creation avoids process-global umask races between callers.
    fd=os.open(path,os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
    try:
        mode=os.fstat(fd)
        if not stat.S_ISREG(mode.st_mode) or stat.S_IMODE(mode.st_mode)!=0o600:
            raise ValueError('private regular database required')
    finally:os.close(fd)
    c=sqlite3.connect(path,timeout=60,isolation_level=None)
    try:
        c.execute('PRAGMA journal_mode=WAL');c.execute('PRAGMA synchronous=FULL');c.execute('PRAGMA foreign_keys=ON')
        return c
    except BaseException:
        c.close();raise

def validate_genesis(g):
    if type(g) is not dict or set(g)!={'genesis','asset','mission','parent_id','epoch','parent','grants','fee','notes'}:
        raise ValueError('genesis shape')
    for key in ['genesis','asset','mission','parent_id','parent']:
        field(g[key])
        if g[key]==ZERO:raise ValueError('zero genesis')
    if number(g['epoch'])==0 or number(g['fee'])==0:raise ValueError('epoch or fee')
    if type(g['grants']) is not list or len(g['grants'])!=2:raise ValueError('grant slots')
    for pair in g['grants']:
        if type(pair) is not list or len(pair)!=2:raise ValueError('grant shape')
        for value in pair:
            field(value)
            if value==ZERO:raise ValueError('zero genesis grant')
    if g['grants'][0][0]==g['grants'][1][0]:raise ValueError('duplicate grant')
    if type(g['notes']) is not list or not 1<=len(g['notes'])<=16 or len(set(g['notes']))!=len(g['notes']):raise ValueError('genesis note count')
    for value in g['notes']:
        field(value)
        if value==ZERO:raise ValueError('zero note')

class Ledger:
    def __init__(self,path:Path,genesis:dict,bridge:Bridge):
        validate_genesis(genesis);self.bridge=bridge;self.db=connection(path)
        self.genesis_id=hashlib.sha256(canonical({'profile':PROFILE,'genesis':genesis})).hexdigest()
        try:
            self.db.execute('BEGIN IMMEDIATE')
            self.db.execute('CREATE TABLE IF NOT EXISTS state (singleton INTEGER PRIMARY KEY CHECK(singleton=1), genesis_id TEXT NOT NULL, data BLOB NOT NULL)')
            self.db.execute('CREATE TABLE IF NOT EXISTS receipts (txid TEXT PRIMARY KEY, raw BLOB NOT NULL, height TEXT NOT NULL)')
            row=self.db.execute('SELECT genesis_id FROM state').fetchone()
            if row is None:
                state=copy.deepcopy(genesis);state.update(nullifiers=[],authority_nullifiers=[],fees=0,height=0)
                state['anchors']=[self.bridge.note_root(state['notes'])]
                self.db.execute('INSERT INTO state VALUES (1,?,?)',(self.genesis_id,canonical(state)))
            elif row[0]!=self.genesis_id:raise ValueError('different pinned genesis/profile')
            self._read();self.db.execute('COMMIT')
        except BaseException:
            try:
                if self.db.in_transaction:self.db.execute('ROLLBACK')
            finally:self.db.close()
            raise
    def close(self):self.db.close()
    def _read(self):
        row=self.db.execute('SELECT genesis_id,data FROM state WHERE singleton=1').fetchone()
        if row is None or row[0]!=self.genesis_id:raise ValueError('missing state identity')
        state=json.loads(row[1]);self._validate(state);return state
    def _validate(self,s):
        if set(s)!={'genesis','asset','mission','parent_id','epoch','parent','grants','fee','notes','anchors','nullifiers','authority_nullifiers','fees','height'}:
            raise ValueError('state shape')
        for k in ['genesis','asset','mission','parent_id','parent']:field(s[k])
        number(s['epoch']);number(s['fee']);number(s['fees']);number(s['height'])
        if len(s['grants'])!=2 or s['grants'][0][0]==s['grants'][1][0]:raise ValueError('grant identities')
        for pair in s['grants']:
            if len(pair)!=2:raise ValueError('grant shape')
            for f in pair:field(f)
        for key,bound in [('notes',16),('anchors',8),('nullifiers',7),('authority_nullifiers',14)]:
            values=s[key]
            if type(values) is not list or len(values)>bound or len(set(values))!=len(values):raise ValueError('bounded unique state')
            for v in values:
                field(v)
                if v==ZERO:raise ValueError('zero state member')
        if not s['anchors'] or self.bridge.note_root(s['notes'])!=s['anchors'][-1]:raise ValueError('state root differs')
    def snapshot(self):
        self.db.execute('BEGIN')
        try:
            state=self._read()
            state['receipts']={i:{'raw_sha256':hashlib.sha256(raw).hexdigest(),'height':int(h)} for i,raw,h in self.db.execute('SELECT txid,raw,height FROM receipts ORDER BY txid')}
            self.db.execute('COMMIT');return state
        except BaseException:
            if self.db.in_transaction:self.db.execute('ROLLBACK')
            raise
    def _check(self,s,p,height,ident):
        number(height)
        if height<s['height']:raise ValueError('backward execution height')
        if not integer(p[15])<=height<integer(p[16]):raise ValueError('execution height')
        for i,k in [(1,'genesis'),(2,'asset'),(3,'mission'),(5,'parent_id'),(7,'parent')]:
            if p[i]!=s[k]:raise ValueError('stale authority/domain')
        if p[4]!=self.bridge.context_root(s) or integer(p[14])!=s['epoch'] or integer(p[17])!=s['fee']:
            raise ValueError('exact current authority required')
        index=next((i for i,pair in enumerate(s['grants']) if pair==[p[6],p[8]] and pair[1]!=ZERO),None)
        if index is None:raise ValueError('stale or revoked grant')
        if p[20] not in s['anchors']:raise ValueError('unadmitted value anchor')
        if p[21] in s['nullifiers'] or any(p[i] in s['authority_nullifiers'] for i in [11,12]):raise ValueError('used nullifier')
        if p[11]==p[12] or len(s['notes'])+2>16 or any(p[i] in s['notes'] for i in [22,23]):raise ValueError('note cardinality/duplicate')
        if s['fees']+s['fee']>MAX_U64:raise ValueError('fee overflow')
        if self.db.execute('SELECT 1 FROM receipts WHERE txid=?',(ident,)).fetchone():raise ValueError('executed transaction')
        # The fixed request identity may execute once within this component genesis.
        for (raw,) in self.db.execute('SELECT raw FROM receipts'):
            if parse(raw)[18]==p[18]:raise ValueError('executed request')
        return index
    def apply(self,raw:bytes,height:int):
        p=parse(raw);ident=txid(raw);self.db.execute('BEGIN IMMEDIATE')
        try:
            s=self._read();index=self._check(s,p,height,ident);self.bridge.verify(raw)
            s['parent']=p[9];s['grants'][index][1]=p[10];s['notes'].extend([p[22],p[23]])
            s['nullifiers'].append(p[21]);s['authority_nullifiers'].extend([p[11],p[12]]);s['fees']+=s['fee'];s['height']=height
            s['anchors'].append(self.bridge.note_root(s['notes']));self._validate(s)
            self.db.execute('UPDATE state SET data=? WHERE singleton=1',(canonical(s),))
            self.db.execute('INSERT INTO receipts VALUES (?,?,?)',(ident,raw,str(height)))
            self.db.execute('COMMIT');return ident
        except BaseException:
            if self.db.in_transaction:self.db.execute('ROLLBACK')
            raise
    def revoke(self,grant_id:str):
        field(grant_id);self.db.execute('BEGIN IMMEDIATE')
        try:
            s=self._read();index=next((i for i,pair in enumerate(s['grants']) if pair[0]==grant_id),None)
            if index is None:raise ValueError('unknown grant')
            s['grants'][index][1]=ZERO;self.db.execute('UPDATE state SET data=? WHERE singleton=1',(canonical(s),))
            self.db.execute('COMMIT')
        except BaseException:
            if self.db.in_transaction:self.db.execute('ROLLBACK')
            raise
    def exact_local_receipt(self,ident,raw):
        row=self.db.execute('SELECT raw FROM receipts WHERE txid=?',(ident,)).fetchone()
        if row is None or bytes(row[0])!=raw or txid(raw)!=ident:raise ValueError('exact executed local receipt absent')

class Outbox:
    """Exact local obligation. No signing, retry, expiry-release or certificate claim."""
    def __init__(self,path):
        self.db=connection(path)
        self.db.execute("CREATE TABLE IF NOT EXISTS obligations (txid TEXT PRIMARY KEY, raw BLOB NOT NULL, nf TEXT NOT NULL, parent_old TEXT NOT NULL, grant_old TEXT NOT NULL, status TEXT NOT NULL CHECK(status IN ('retained','claimed','recorded-local')))")
        for name,key in [('input','nf'),('parent','parent_old'),('grant','grant_old')]:
            self.db.execute(f"CREATE UNIQUE INDEX IF NOT EXISTS live_{name} ON obligations ({key}) WHERE status != 'recorded-local'")
    def close(self):self.db.close()
    def retain(self,raw):
        p=parse(raw);ident=txid(raw);self.db.execute('BEGIN IMMEDIATE')
        try:
            self.db.execute("INSERT INTO obligations VALUES (?,?,?,?,?,'retained')",(ident,raw,p[21],p[7],p[8]));self.db.execute('COMMIT');return ident
        except sqlite3.IntegrityError:
            if self.db.in_transaction:self.db.execute('ROLLBACK')
            raise ValueError('existing exact obligation or held input/authority') from None
        except BaseException:
            if self.db.in_transaction:self.db.execute('ROLLBACK')
            raise
    def _row(self,ident):
        row=self.db.execute('SELECT raw,status FROM obligations WHERE txid=?',(ident,)).fetchone()
        if row is None or txid(bytes(row[0]))!=ident:raise ValueError('exact retained obligation missing')
        return bytes(row[0]),row[1]
    def export(self,ident):return self._row(ident)[0]
    def status(self,ident):return self._row(ident)[1]
    def claim(self,ident):
        self.db.execute('BEGIN IMMEDIATE')
        try:
            raw,status=self._row(ident)
            if status!='retained':raise ValueError('one attempt already claimed')
            self.db.execute("UPDATE obligations SET status='claimed' WHERE txid=?",(ident,));self.db.execute('COMMIT');return raw
        except BaseException:
            if self.db.in_transaction:self.db.execute('ROLLBACK')
            raise
    def record_local_receipt(self,ident,ledger:Ledger):
        self.db.execute('BEGIN IMMEDIATE')
        try:
            raw,status=self._row(ident);ledger.exact_local_receipt(ident,raw)
            self.db.execute("UPDATE obligations SET status='recorded-local' WHERE txid=?",(ident,));self.db.execute('COMMIT')
        except BaseException:
            if self.db.in_transaction:self.db.execute('ROLLBACK')
            raise
