"""Actual failed-run public history; synthetic durable rows, no engine restart claim."""
import copy,json,os,sqlite3,unittest
from pathlib import Path
from unittest.mock import patch
from protocol7_application import Application,SCHEMA,encode_finalization,finalization_identity
from protocol7_treasury import canonical,digest,initial_state,_execute,replay,application_hash
from protocol7_worker import Worker
from protocol5_encoding import comet_validator_set

@unittest.skipUnless(os.environ.get('P7_RESTART_REPORT') and os.environ.get('P7_RESTART_WORKER'),'actual public history/worker not supplied')
class AuditTests(unittest.TestCase):
    def test_actual_history_linear_audit_and_corrupt_response_refusal(self):
        path=Path(os.environ['P7_RESTART_REPORT']);v=json.loads(path.read_bytes())
        directory=path.with_name(path.name+'.artifacts')
        w=Worker(Path(os.environ['P7_RESTART_WORKER']),v['inputs']['worker']['sha256'],(directory/'fixture-a.tx').read_bytes())
        g=v['genesis'];state=v['records']['active_revoke']['witness']['state']
        h=v['records']['active_revoke']['state_height'];replay(g,state,h,w)
        validators=comet_validator_set(g['validators'])
        db=sqlite3.connect(':memory:');db.execute(SCHEMA['blocks'])
        s=initial_state(g,w)
        for height,b in enumerate(state['blocks'],1):
            txs=[bytes.fromhex(raw) for raw in b['transactions']]
            s,results=_execute(g,s,txs,height,w)
            votes=[] if height==1 else [{'address':r.address.hex(),'power':r.power,'block_id_flag':2} for r in validators.validators]
            # Deliberately synthetic storage identities; actual native wire history.
            wire=canonical({'height':height,'synthetic_storage_fixture':True})
            block=digest(canonical(b));value={'height':height,'app_hash':application_hash(g,height,s),'tx_results':results,'last_commit_votes':votes,'validator_updates':[]}
            ident=finalization_identity(txs,height,bytes.fromhex(block),bytes.fromhex(validators.hash),votes,wire)
            db.execute('INSERT INTO blocks VALUES (?,?,?,?,?,?)',(height,block,ident,canonical(value),encode_finalization(value),wire))
        self.assertEqual(canonical(s),canonical(state))
        app=object.__new__(Application);app.g=g;app.worker=w;app.validators=validators;app.state=state;app.height=h;app.db=db
        calls=[];normal=w.verify
        def counted(raw):calls.append(digest(raw));return normal(raw)
        try:
            with patch('protocol7_application.execute_block',side_effect=AssertionError('audit must not replay already audited prefixes')),patch.object(w,'verify',side_effect=counted):
                app._audit_blocks()
            self.assertEqual(len(calls),3,'one native verification per actual payment in the audit pass')
            db.execute('UPDATE blocks SET response=? WHERE height=1',(b'corrupt-retained-response',))
            with self.assertRaisesRegex(ValueError,'P7 exact retained response differs'):app._audit_blocks()
        finally:db.close()
if __name__=='__main__':unittest.main()
