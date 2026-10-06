"""Receipt schema/tamper tests only. Fake proofs are never verified as native."""
import copy,json,unittest
from scripts import check_protocol8_recipient_report as c
from scripts.run_protocol8_recipient import CHECKS,CLAIMS
from src import protocol8_transfer as p
from tests import test_protocol8_transfer as boundary
class ReportTests(unittest.TestCase):
    def setUp(self):
        b=boundary.BoundaryTests();b.setUp();self.g=b.g;self.pin=p.sha(p.canonical(self.g));self.worker=b.w.identity['sha256']
        raw=b.raw;other=raw[:-1]+b'x'
        es=[e for e in json.loads((c.ROOT/'SOURCE_MANIFEST.json').read_bytes())['files']if e['path'].startswith(('src/','scripts/','tests/','tools/recipient-transfer/','tools/shielded-consensus/halo2/'))]
        row={'binary':'verifier','operation':'verify','pid':1,'start_ticks':'1','exit_code':0,'input_bytes':3592,'output_bytes':3,'binary_sha256':self.worker,'elapsed_seconds':0.1,'timed_out':False,'process_reaped':True,'resource_limits':{'cpu_seconds':45,'address_space_bytes':2*1024**3,'core_bytes':0}}
        self.r={'format':'1soft/P8-recipient-native-run/v1','status':'passed','scope':'native recipient proof and bounded public state only','source':{'commit':'aa'*20,'tree':'bb'*20,'clean':True,'runtime_files':es,'source_manifest_sha256':'cc'*32},'profile_sha256':p.PROFILE_SHA256,'profile':p.PROFILE,'binary_identities':{k:{'sha256':self.worker,'bytes':100}for k in ('prover','fixture','verifier')},'bootstrap_hex':'dd'*32,'genesis':b.g,'genesis_sha256':self.pin,'final_state':b.state,'state_sha256':p.state_hash(b.state),'public_wires':[v.hex()for v in (raw,raw,other)],'public_wire_sha256':[p.sha(v)for v in (raw,raw,other)],'checks':{v:'passed'for v in CHECKS},'details':{k:'refused'for k in ('spent_nullifier_refused','consumed_intent_refused','unknown_root_refused','wrong_fee_refused','wrong_height_refused','wrong_context_refused','forged_snapshot_refused','legacy_wire_refused','legacy_note_refused')},'processes':[dict(row,pid=i+1)for i in range(25)],'claims':copy.deepcopy(CLAIMS)}
        self.r['details']['private_request_refusals']=['magic','profile','parameters','verifying_key','bootstrap','wrong_recipient_key','truncated','trailing','u64_overflow']
    def test_shape_acceptance_is_not_proof_verification(self):
        self.assertEqual(len(c.validate_shape(self.r,self.pin,self.worker)),3)
    def test_early_tamper_refusals(self):
        cases=[]
        def case(change):
            r=copy.deepcopy(self.r);change(r);cases.append(r)
        case(lambda r:r.update(unexpected=1))
        case(lambda r:r['checks'].pop('first_native_proof'))
        case(lambda r:r['checks'].update(first_native_proof='skipped'))
        case(lambda r:r['claims'].update(consensus_qualified=True))
        case(lambda r:r['profile'].update(proof_bytes=3137))
        case(lambda r:r['source']['runtime_files'].pop())
        case(lambda r:r['source'].update(clean=False))
        case(lambda r:r['public_wires'].__setitem__(0,r['public_wires'][0][:-2]))
        case(lambda r:r['public_wire_sha256'].__setitem__(0,'00'*32))
        case(lambda r:r['processes'][0].update(process_reaped=False))
        case(lambda r:r['processes'][0].update(operation='private-dispatch'))
        case(lambda r:r['processes'][0].update(binary_sha256='00'*32))
        case(lambda r:r.update(genesis_sha256='00'*32))
        for i,r in enumerate(cases):
            with self.subTest(case=i):
                with self.assertRaises(p.Invalid):c.validate_shape(r,self.pin,self.worker)
    def test_external_pins_required(self):
        for g,w in [('00'*32,self.worker),(self.pin,'00'*32)]:
            with self.assertRaises(p.Invalid):c.validate_shape(self.r,g,w)
if __name__=='__main__':unittest.main()
