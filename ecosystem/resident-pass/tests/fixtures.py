"""Identity-free fixture subjects and publicly known test key seeds only."""
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from resident_pass.protocol import public,issue_card,issue_status,pairwise_subject,IssuerRule,present
NOW=1790251200

def key(n):return Ed25519PrivateKey.from_private_bytes(bytes([n])*32)
ISSUER=key(11);HOLDER=key(12);OTHER=key(13);FOREIGN=key(14)
AUDIENCE='marketplace.test'
RULE=IssuerRule('eternities-lab',public(ISSUER),('resident',))

def card(holder=HOLDER,epoch=0,kind='resident',issuer='eternities-lab',issuer_key=ISSUER,
         audience=AUDIENCE,credential='card-001',now=NOW,subject=None):
    return issue_card(issuer_key,{'schema':1,'issuer':issuer,'credential_id':credential,
        'subject_id':subject or pairwise_subject(bytes([77])*32,issuer,audience),
        'kind':kind,'audience':audience,'display_name':'Aster · specimen',
        'holder_key':public(holder),'epoch':epoch,'issued_at':now-1,'expires_at':now+3600})

def status(cards=None,sequence=1,revoked=(),now=NOW,issuer='eternities-lab',issuer_key=ISSUER):
    cards=[card()] if cards is None else cards
    return issue_status(issuer_key,{'schema':1,'issuer':issuer,'sequence':sequence,'issued_at':now-1,
        'expires_at':now+120,'entries':[{**{k:c['body'][k] for k in ('credential_id','subject_id','holder_key','epoch')},
                            'status':'revoked' if c['body']['credential_id'] in revoked else 'active'} for c in cards]})
