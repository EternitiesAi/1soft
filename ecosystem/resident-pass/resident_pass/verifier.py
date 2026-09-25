"""Single-host credential checking with issuer status and one-use challenges.

The journal is not a public identity registry. Callers supply pinned issuer rules
and a trusted local clock. It cannot discover unobserved revocations or survive a
malicious issuer, malicious host, or rollback of the entire workspace. No network.
"""
from __future__ import annotations
from contextlib import contextmanager
import os
from pathlib import Path
import secrets
import sqlite3
import stat
import time

from .protocol import (IssuerRule,Refused,require,fields,number,token,hex64,canonical,decode,digest,
    card_body,status_body,challenge_body,verify_signature,CARD_DOMAIN,STATUS_DOMAIN,PRESENT_DOMAIN,PURPOSES)

class Verifier:
    def __init__(self,path,issuers,audience,trust_expires_at,*,clock=time.time):
        token(audience);number(trust_expires_at)
        require(type(issuers) in (tuple,list) and 1<=len(issuers)<=32,'pinned issuer list required')
        require(all(isinstance(x,IssuerRule) for x in issuers),'invalid issuer policy')
        self.issuers={x.issuer:x for x in issuers}
        require(len(self.issuers)==len(issuers),'duplicate issuer')
        self.audience=audience;self.trust_expires_at=trust_expires_at;self.clock=clock
        policy={'schema':1,'audience':audience,'trust_expires_at':trust_expires_at,
                'issuers':[{'issuer':x.issuer,'public_key':x.public_key,'kinds':list(x.kinds)}
                           for x in sorted(issuers,key=lambda x:x.issuer)]}
        self.policy=digest(policy)
        if str(path)!=':memory:':
            path=Path(os.path.abspath(path));parent=path.parent
            for p in (parent,*parent.parents):require(not p.is_symlink(),'journal parent symlink refused')
            info=parent.stat()
            require(stat.S_ISDIR(info.st_mode) and info.st_uid==os.geteuid() and
                    stat.S_IMODE(info.st_mode)&0o077==0,'private owned journal directory required')
            for candidate in [path,*(Path(str(path)+s) for s in ('-wal','-shm','-journal'))]:
                if candidate.exists() or candidate.is_symlink():
                    info=candidate.lstat()
                    require(stat.S_ISREG(info.st_mode) and info.st_nlink==1 and info.st_uid==os.geteuid()
                            and stat.S_IMODE(info.st_mode)&0o077==0,'private regular journal files required')
            try:
                fd=os.open(path,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600);os.close(fd)
            except FileExistsError:pass
        self.db=sqlite3.connect(path,isolation_level=None,timeout=5)
        self.db.row_factory=sqlite3.Row
        self.db.execute('PRAGMA journal_mode=WAL');self.db.execute('PRAGMA synchronous=FULL')
        self.db.executescript('''
        CREATE TABLE IF NOT EXISTS policy(id INTEGER PRIMARY KEY CHECK(id=1),hash TEXT NOT NULL,last_time INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS issuer_status(issuer TEXT PRIMARY KEY,sequence INTEGER NOT NULL,digest TEXT NOT NULL,document TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS subject_epochs(issuer TEXT NOT NULL,subject TEXT NOT NULL,epoch INTEGER NOT NULL,credential TEXT NOT NULL,key TEXT NOT NULL,revoked INTEGER NOT NULL,PRIMARY KEY(issuer,subject));
        CREATE TABLE IF NOT EXISTS challenges(nonce TEXT PRIMARY KEY,body TEXT NOT NULL,used INTEGER NOT NULL DEFAULT 0,receipt TEXT);
        CREATE TABLE IF NOT EXISTS native_checkpoints(chain TEXT PRIMARY KEY,height INTEGER NOT NULL,hash TEXT NOT NULL);
        ''')
        try:
            with self.atomic():
                row=self.db.execute('SELECT hash FROM policy WHERE id=1').fetchone()
                if row:require(row[0]==self.policy,'journal trust policy differs')
                else:self.db.execute('INSERT INTO policy VALUES (1,?,0)',(self.policy,))
        except BaseException:self.db.close();raise

    def close(self):self.db.close()
    def __enter__(self):return self
    def __exit__(self,*_):self.close()
    @contextmanager
    def atomic(self):
        self.db.execute('BEGIN IMMEDIATE')
        try:yield;self.db.execute('COMMIT')
        except BaseException:self.db.execute('ROLLBACK');raise

    def now(self):
        raw=self.clock()
        require(type(raw) in (int,float) and raw==raw and raw>=0,'invalid clock')
        try:now=int(raw)
        except (OverflowError,ValueError) as exc:raise Refused('invalid clock') from exc
        number(now)
        old=self.db.execute('SELECT last_time FROM policy WHERE id=1').fetchone()[0]
        require(now>=old,'clock rollback');require(now<self.trust_expires_at,'local trust policy expired')
        self.db.execute('UPDATE policy SET last_time=? WHERE id=1',(now,))
        return now

    def _issuer(self, issuer):
        token(issuer);require(issuer in self.issuers,'issuer is not locally trusted')
        return self.issuers[issuer]

    def _signed_status(self,document,now):
        fields(document,{'body','signature'});body=status_body(document['body'])
        rule=self._issuer(body['issuer'])
        verify_signature(rule.public_key,document['signature'],STATUS_DOMAIN,body)
        require(body['issued_at']<=now<body['expires_at'] and now-body['issued_at']<=120,'status is stale or not yet valid')
        return body

    def install_status(self,document):
        document=decode(canonical(document))
        with self.atomic():
            now=self.now();body=self._signed_status(document,now);key=body['issuer'];new_digest=digest(document)
            old=self.db.execute('SELECT * FROM issuer_status WHERE issuer=?',(key,)).fetchone()
            if old:
                require(body['sequence']>=old['sequence'],'issuer status rollback')
                if body['sequence']==old['sequence']:
                    require(new_digest==old['digest'],'conflicting issuer status sequence');return
                previous=decode(old['document'].encode())['body']
                require(body['issued_at']>=previous['issued_at'],'issuer status time rollback')
            active={entry['subject_id']:entry for entry in body['entries'] if entry['status']=='active'}
            for sub,entry in active.items():
                seen=self.db.execute('SELECT * FROM subject_epochs WHERE issuer=? AND subject=?',(key,sub)).fetchone()
                if seen:
                    require(entry['epoch']>=seen['epoch'],'subject epoch rollback')
                    if entry['epoch']==seen['epoch']:
                        require(not seen['revoked'] and entry['credential_id']==seen['credential'] and
                                entry['holder_key']==seen['key'],'key/card replacement requires a newer epoch')
                self.db.execute('INSERT OR REPLACE INTO subject_epochs VALUES (?,?,?,?,?,0)',
                                (key,sub,entry['epoch'],entry['credential_id'],entry['holder_key']))
            for entry in body['entries']:
                if entry['status']=='revoked':
                    # Old revoked credentials may coexist with a new active epoch.
                    seen=self.db.execute('SELECT * FROM subject_epochs WHERE issuer=? AND subject=?',
                                         (key,entry['subject_id'])).fetchone()
                    if not seen or entry['epoch']>seen['epoch']:
                        self.db.execute('INSERT OR REPLACE INTO subject_epochs VALUES (?,?,?,?,?,1)',
                            (key,entry['subject_id'],entry['epoch'],entry['credential_id'],entry['holder_key']))
                    elif entry['epoch']==seen['epoch']:
                        require(entry['credential_id']==seen['credential'] and entry['holder_key']==seen['key'],
                                'conflicting revoked subject record')
                        self.db.execute('UPDATE subject_epochs SET revoked=1 WHERE issuer=? AND subject=?',
                                        (key,entry['subject_id']))
            self.db.execute('INSERT OR REPLACE INTO issuer_status VALUES (?,?,?,?)',
                            (key,body['sequence'],new_digest,canonical(document).decode()))

    def _card(self,card,now):
        fields(card,{'body','signature'});body=card_body(card['body']);rule=self._issuer(body['issuer'])
        verify_signature(rule.public_key,card['signature'],CARD_DOMAIN,body)
        require(body['kind'] in rule.kinds,'issuer not trusted for this subject kind')
        require(body['audience']==self.audience,'card audience differs')
        require(body['issued_at']<=now<body['expires_at'],'card expired or not yet valid')
        status=self.db.execute('SELECT * FROM issuer_status WHERE issuer=?',(body['issuer'],)).fetchone()
        require(status is not None,'signed issuer status required')
        document=decode(status['document'].encode())
        require(digest(document)==status['digest'] and document['body']['sequence']==status['sequence'],'stored status differs')
        current=self._signed_status(document,now)
        matches=[e for e in current['entries'] if e['credential_id']==body['credential_id']]
        require(len(matches)==1,'card not in supplied current status')
        entry=matches[0]
        require(entry['status']=='active' and all(entry[k]==body[k] for k in ('subject_id','holder_key','epoch')),
                'card revoked or identity key changed')
        seen=self.db.execute('SELECT * FROM subject_epochs WHERE issuer=? AND subject=?',
                             (body['issuer'],body['subject_id'])).fetchone()
        require(seen is not None and not seen['revoked'] and seen['epoch']==body['epoch'] and
                seen['credential']==body['credential_id'] and seen['key']==body['holder_key'], 'subject status inconsistent')
        return body

    def begin(self,card,*,purpose='introduce',context_digest=None,ttl=60):
        require(purpose in PURPOSES,'unsupported purpose');number(ttl,low=1,high=120)
        context_digest=digest({}) if context_digest is None else hex64(context_digest)
        if purpose=='introduce':require(context_digest==digest({}),'introductions cannot carry hidden context')
        card=decode(canonical(card))
        with self.atomic():
            now=self.now();body=self._card(card,now)
            require(self.db.execute('SELECT count(*) FROM challenges').fetchone()[0]<10000,'prototype challenge capacity reached')
            expires=min(now+ttl,body['expires_at'],self.trust_expires_at)
            require(expires>now,'empty validity window')
            challenge={'schema':1,'nonce':secrets.token_hex(32),'audience':self.audience,'purpose':purpose,
                       'card_digest':digest(card),'context_digest':context_digest,'issued_at':now,'expires_at':expires}
            self.db.execute('INSERT INTO challenges(nonce,body) VALUES (?,?)',(challenge['nonce'],canonical(challenge).decode()))
            return challenge

    def _check(self,card,presentation,now,*,purpose,context_digest):
        fields(presentation,{'body','signature'});challenge=challenge_body(presentation['body'])
        row=self.db.execute('SELECT * FROM challenges WHERE nonce=?',(challenge['nonce'],)).fetchone()
        require(row is not None and not row['used'],'challenge unknown or already consumed')
        require(canonical(challenge).decode()==row['body'],'challenge altered')
        require(challenge['audience']==self.audience and challenge['purpose']==purpose and
                challenge['context_digest']==context_digest,'presentation purpose or context differs')
        require(challenge['issued_at']<=now<challenge['expires_at'],'challenge expired')
        body=self._card(card,now);require(challenge['card_digest']==digest(card),'different credential presented')
        verify_signature(body['holder_key'],presentation['signature'],PRESENT_DOMAIN,challenge)
        return body,challenge

    def _finish(self,body,challenge,extra=None):
        result={'status':'verified-presentation','issuer':body['issuer'],'subject_id':body['subject_id'],
                'display_name':body['display_name'],'kind':body['kind'],'holder_epoch':body['epoch'],
                'credential_digest':challenge['card_digest'],'audience':self.audience,
                'purpose':challenge['purpose'],'assertion_scope':'issuer claim and current holder-key proof',
                'financial_authority_created':False,'legal_identity_verified':False,
                'consciousness_assessed':False,'biographical_continuity_verified':False}
        if extra:result.update(extra)
        c=self.db.execute('UPDATE challenges SET used=1,receipt=? WHERE nonce=? AND used=0',
                         (canonical(result).decode(),challenge['nonce']))
        require(c.rowcount==1,'challenge concurrently consumed')
        return result

    def accept(self,card,presentation):
        card=decode(canonical(card));presentation=decode(canonical(presentation))
        with self.atomic():
            now=self.now();body,challenge=self._check(card,presentation,now,purpose='introduce',context_digest=digest({}))
            return self._finish(body,challenge)

    def receipt(self,nonce):
        """Historical local result recovery; not a new authentication/session grant."""
        hex64(nonce);row=self.db.execute('SELECT receipt FROM challenges WHERE nonce=? AND used=1',(nonce,)).fetchone()
        require(row is not None,'no completed local presentation')
        return {'historical_local_result':decode(row[0].encode()),'new_authentication':False}
