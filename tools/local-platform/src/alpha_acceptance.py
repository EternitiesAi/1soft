"""Actual finite alpha qualification on four owned local CometBFT validators.

Default qualification takes over one real hour. No scaled clock, chain reset,
new policy, journal migration, auto-resend, downloads or public deployment.
The original fixtures and generated vaults remain private outside the source.
"""
import hashlib
import json
import os
import signal
from pathlib import Path
import sys
import time
import traceback
import uuid
from block_application import encode
from commit_verifier import load_json
from local_devnet import (ROOT,PIN_SHA,initialize,LocalNetwork,private_new,read_private,verify_engine)
from development_profile import DURABLE_PROFILE
from p4_evidence import need,content_id
from payment_requests import new_request
from p4_alpha_custody import restore_backup,RecoveryArchive,verify_receipt

EXPECTED_CHECKS=(
 'exact_clean_source','pinned_engine','explicit_fresh_alpha_genesis','four_actual_owned_validators',
 'immutable_original_trust_policy','original_wallet_store_delivery_identity','first_original_signed_wire',
 'first_attempt_durable_once','first_exact_positive_execution','first_hold_retired_by_exact_receipt',
 'second_original_signature_fee_hold','receipt_reference_and_packet_retained','same_genesis_home_db_restart',
 'same_original_wires_after_restart','same_attempt_and_receipt_after_restart','hold_survives_restart',
 'actual_height_over64','actual_height_over512','actual_elapsed_over_one_hour','past_original_anchor_deadline',
 'continuous_checkpoint_lineage','over32_original_wallet_observations','original_policy_identity_unchanged',
 'original_account_role_nonce_and_budget_preserved','same_original_wires_after_one_hour','unobserved_hold_not_discarded',
 'original_receipt_packet_unchanged','post_hour_new_payment_signed','post_hour_exact_native_execution',
 'post_hour_positive_receipt_and_hold_reconciliation','original_attempt_not_resent',
 'complete_encrypted_history_and_inert_recovery','all_original_inert_wires_and_fee_hold',
 'historical_portable_receipt_verified','all_four_final_heights_consistent','source_engine_unchanged',
 'all_owned_processes_reaped','original_workspace_preserved')


def _birth(pid):
    try:return int(Path('/proc',str(pid),'stat').read_text().rsplit(') ',1)[1].split()[19])
    except (OSError,ValueError,IndexError):return None

def _files(root):
    return {name:{'device':p.stat().st_dev,'inode':p.stat().st_ino}
        for name in ('wallet.sqlite','delivery.sqlite','ledger.sqlite',*[f'app{i}/state.sqlite' for i in range(4)])
        if (p:=root/name).is_file()}


def stop_with_facts(network,rows):
    """Capture actual owned shutdown outcomes; reaping alone is not a pass."""
    before={p.pid:p.poll() for p in network.apps+network.engines}
    result=network.stop();valid=not result['warnings']
    for row in rows:
        if 'returncode' not in row:
            matches=[p for p in network.apps+network.engines if p.pid==row['pid']]
            if matches:
                p=matches[0];row.update(returncode=p.returncode,returncode_before_stop=before[p.pid],
                    reaped=p.poll() is not None,same_birth_still_present=_birth(row['pid'])==row['birth'])
                row['expected_stop_outcome']=before[p.pid] is None and p.returncode in (0,-signal.SIGTERM)
                valid=valid and row['expected_stop_outcome']
    return valid


def qualify_alpha(engine,output,*,duration_seconds=3660):
    need(type(duration_seconds) is int and 3600<duration_seconds<=7200,'qualification requires more than one real hour, at most two')
    sys.path.insert(0,str(ROOT/'tools/release'))
    import check_release as evidence
    source=evidence.source_identity(ROOT);binary=verify_engine(engine)
    output=Path(output).absolute();need(not output.is_relative_to(ROOT),'evidence must be outside source')
    from p4_read_store import private_path
    private_path(output)  # Refuse non-private/aliased parent before any new workspace or keys.
    output.mkdir(mode=0o700,exist_ok=False);private_new(output/'source.json',encode(source))
    workspace=Path.home()/('1sa-'+uuid.uuid4().hex[:12])
    secret=os.urandom(32).hex().encode();backup_secret=os.urandom(32).hex().encode()
    report={'schema':1,'format':'1soft/durable-alpha-real-acceptance/v1','status':'running',
        'source':{k:source[k] for k in ('commit','tree','source_id','tracked_files')},'engine_sha256':PIN_SHA,
        'workspace':str(workspace),'development_profile':DURABLE_PROFILE,'required_real_seconds':duration_seconds,
        'clock':'unscaled host time.time_ns plus monotonic elapsed; no injected clock',
        'expected_checks':list(EXPECTED_CHECKS),'checks':[],'phases':[],'owned_processes':[],
        'public_network':False,'real_funds':False,'independent_hosts':False,'production_qualified':False,
        'private_fixture_in_handoff':False,'unassessed':['host rollback and copied journal fencing','independent operators',
            'production custody/privacy/economics','load at resource ceilings','operation past the fixed 24-hour horizon']}
    net=None;start_ns=time.time_ns();started=time.monotonic();restart_done=False
    def save():evidence.store_json(output/'progress.json',report,replace=(output/'progress.json').exists())
    def check(name,value,**details):
        need(name in EXPECTED_CHECKS and name not in {c['name'] for c in report['checks']},'acceptance check membership differs')
        report['checks'].append({'name':name,'passed':bool(value),**details});save();need(value,'alpha qualification check failed: '+name)
    def owned(network):
        for kind,items in [('application',network.apps),('validator',network.engines)]:
            report['owned_processes'].extend({'kind':kind,'pid':p.pid,'birth':_birth(p.pid),'generation':1 if restart_done else 0} for p in items)
        save()
    def stop_owned(network):
        valid=stop_with_facts(network,report['owned_processes']);save()
        need(valid,'owned process exited unexpectedly or required forced stop; original fixture retained')
    def phase(svc,label):
        state=svc.state();cp=svc.store.current()['checkpoint']
        heights=[net.height(i) for i in range(4)]
        row={'index':len(report['phases'])+1,'label':label,'observed_ns':time.time_ns(),
            'elapsed_seconds':time.monotonic()-started,'node_heights':heights,'checkpoint':cp,
            'wallet_revision':state['wallet']['revision'],'wallet_observations':svc.wallet.db.execute('SELECT count(*) FROM observations').fetchone()[0],
            'pending_debit_units':state['wallet']['pending_debit_units'],'wallet_current':state['wallet_current'],
            'signing_ready':state['signing_ready'],'policy_id':content_id(net.policy())}
        private_new(output/f"phase-{row['index']:04}.json",encode(row));report['phases'].append(row);save()
        print(encode({'phase':label,'height':cp['height'],'observations':row['wallet_observations'],
            'elapsed_seconds':round(row['elapsed_seconds'],3),'pending_debit_units':row['pending_debit_units']}).decode(),flush=True)
        return row
    def advance(svc):
        tip=svc.store.current()['checkpoint'];deadline=time.monotonic()+30
        while net.height()<=tip['height'] and time.monotonic()<deadline:net.health();time.sleep(.25)
        need(net.height()>tip['height'],'new local checkpoint unavailable')
        saved=svc.refresh(expected_tip=tip['id']);svc.sync(expected_revision=svc.wallet.status()['revision'])
        return saved
    def sign_payment(svc,role,units):
        now=time.time_ns();rid=svc.add_request(new_request(net.config['genesis_sha256'],net.config['merchant'],str(units),
            created_ns=now,expires_ns=now+86400*10**9,note='Finite local alpha qualification'))['request_id']
        height=svc.wallet.status()['state_height'];q=svc.prepare(rid,role,valid_until=min(4096,height+32))
        result=svc.approve(rid,role,q['review'],q['confirmation'],password=secret)
        wire=svc.recover(rid);return rid,result['decision_id'],wire
    def send_and_settle(svc,rid,did):
        q=svc.submission_review(rid);svc.submit(rid,q['review'],q['confirmation'])
        deadline=time.monotonic()+60;body=svc.book.selected(rid)['review']['body']
        selection={'payer':body['sender'],'grant_id':body['grant_id']}
        while time.monotonic()<deadline:
            advance(svc)
            result=svc.delivery.import_receipt(did,svc.store.current()['checkpoint']['id'],**selection)
            if result['status']=='receipt_collected':
                svc.reconcile(rid,expected_revision=svc.wallet.status()['revision']);return result
            time.sleep(.25)
        raise ValueError('exact original local payment execution not observed before deadline')
    try:
        check('exact_clean_source',bool(source['files']))
        check('pinned_engine',hashlib.sha256(binary.read_bytes()).hexdigest()==PIN_SHA)
        config=initialize(workspace,binary,password=secret,profile=DURABLE_PROFILE)
        genesis=read_private(workspace/'engine-genesis.json');native=load_json(read_private(workspace/'app-genesis.json'))
        check('explicit_fresh_alpha_genesis',native['development_profile']==DURABLE_PROFILE and native['asset']=='DEV')
        net=LocalNetwork(workspace,binary);net.start();owned(net);net.bootstrap(password=secret)
        check('four_actual_owned_validators',len(net.apps)==len(net.engines)==4 and all(net.height(i)>=1 for i in range(4)))
        policy_bytes=read_private(workspace/'policy.json');policy=net.policy();policy_id=content_id(policy)
        check('immutable_original_trust_policy',policy['schema']==2 and policy['trust_period_seconds']==3600 and
              policy['absolute_not_after_ns']==__import__('validator_witness').nanos(policy['anchor_time'])+86400*10**9)
        with net.service() as svc:
            first_phase=phase(svc,'original-bootstrap')
            identities={'wallet_id':svc.wallet._catalog()[0],'delivery_id':svc.delivery.config[2],'store_id':svc.store.store_id}
            file_ids=_files(workspace)
            report.update(original_identities=identities,original_file_identities=file_ids,genesis_sha256=config['genesis_sha256'],policy_id=policy_id)
            check('original_wallet_store_delivery_identity',len(set(identities.values()))==3)
            rid1,did1,wire1=sign_payment(svc,'raven',5)
            check('first_original_signed_wire',svc.recover(rid1)==wire1 and svc.wallet.status()['pending_debit_units']=='7')
            first_receipt=send_and_settle(svc,rid1,did1)
            attempts=svc.delivery.db.execute('SELECT count(*) FROM attempts').fetchone()[0]
            check('first_attempt_durable_once',attempts==1)
            check('first_exact_positive_execution',first_receipt['status']=='receipt_collected')
            check('first_hold_retired_by_exact_receipt',svc.wallet.status()['pending_debit_units']=='0')
            ref=svc.retain_receipt(rid1);capsule_before=svc.capsule(rid1,ref['capsule_id'])
            private_new(output/'original-receipt.json',capsule_before)
            check('receipt_reference_and_packet_retained',ref['capsule_id']==load_json(capsule_before,max_bytes=64*1024*1024+65536)['capsule_id'])
            rid2,did2,wire2=sign_payment(svc,'atlas',11)
            check('second_original_signature_fee_hold',svc.wallet.status()['pending_debit_units']=='13')
            report['original_payments']=[{'request_id':rid1,'decision_id':did1,'wire_sha256':hashlib.sha256(wire1).hexdigest(),'role':'raven','units':'5','fee':'2'},
                {'request_id':rid2,'decision_id':did2,'wire_sha256':hashlib.sha256(wire2).hexdigest(),'role':'atlas','units':'11','fee':'2','never_dispatched':True}]
            phase(svc,'original-payment-and-held-signature')
        while time.monotonic()-started<duration_seconds or net.height()<=512:
            net.health()
            with net.service() as svc:
                tip=svc.store.current()['checkpoint']
                if net.height()>=tip['height']+16:
                    advance(svc);phase(svc,'continuous-original-history')
            if not restart_done and net.height()>512:
                stop_owned(net);restart_done=True
                net=LocalNetwork(workspace,binary);net.start();owned(net)
                need(net.ready() and net.bootstrap(password=secret)['status']=='original_workspace_retained','restart attempted new bootstrap')
                with net.service() as svc:
                    check('same_genesis_home_db_restart',read_private(workspace/'engine-genesis.json')==genesis and _files(workspace)==file_ids)
                    check('same_original_wires_after_restart',svc.recover(rid1)==wire1 and svc.recover(rid2)==wire2)
                    check('same_attempt_and_receipt_after_restart',svc.delivery.db.execute('SELECT count(*) FROM attempts').fetchone()[0]==1 and svc.capsule(rid1,ref['capsule_id'])==capsule_before)
                    check('hold_survives_restart',svc.wallet.status()['pending_debit_units']=='13')
                    phase(svc,'same-home-restart-after512')
            need(time.monotonic()-started<=duration_seconds+600,'actual duration gate exceeded its bounded time')
            time.sleep(4)
        with net.service() as svc:
            advance(svc);final_phase=phase(svc,'actual-hour-crossed')
            view=svc.store.current();height=view['checkpoint']['height'];elapsed=time.monotonic()-started
            check('actual_height_over64',height>64,height=height)
            check('actual_height_over512',height>512,height=height)
            check('actual_elapsed_over_one_hour',elapsed>=duration_seconds>3600,elapsed_seconds=elapsed,start_ns=start_ns,end_ns=time.time_ns())
            check('past_original_anchor_deadline',time.time_ns()>__import__('validator_witness').nanos(policy['anchor_time'])+3600*10**9)
            descriptors=svc.store.checkpoint_descriptors();ordered=list(descriptors.values());prior=None
            for cp in ordered:
                need(cp['parent_id']==(None if prior is None else prior['id']),'original checkpoint lineage broken')
                if prior is not None:need(cp['checked_ns']<prior['lookahead_time_ns']+3600*10**9,'an expired admission gap was renewed')
                prior=cp
            check('continuous_checkpoint_lineage',len(ordered)>32 and prior['height']==height,checkpoints=len(ordered))
            check('over32_original_wallet_observations',svc.wallet.db.execute('SELECT count(*) FROM observations').fetchone()[0]>32)
            check('original_policy_identity_unchanged',read_private(workspace/'policy.json')==policy_bytes and content_id(net.policy())==policy_id)
            recorded=svc.state()['ledger'];grants={g['id']:g for g in recorded['grants']};budgets={b['id']:b for b in recorded['budgets']}
            check('original_account_role_nonce_and_budget_preserved',svc.wallet._catalog()[0]==identities['wallet_id'] and svc.delivery.config[2]==identities['delivery_id'] and svc.store.store_id==identities['store_id'] and
                grants['raven']['nonce']=='1' and grants['raven']['spent']=='7' and grants['atlas']['nonce']=='0' and grants['atlas']['spent']=='0' and
                budgets['studio']['cap']=='100' and budgets['studio']['spent']=='7',grants=grants,budget=budgets['studio'])
            check('same_original_wires_after_one_hour',svc.recover(rid1)==wire1 and svc.recover(rid2)==wire2)
            check('unobserved_hold_not_discarded',svc.wallet.status()['pending_debit_units']=='13' and svc.delivery.db.execute('SELECT count(*) FROM attempts WHERE decision_id=?',(did2,)).fetchone()[0]==0)
            check('original_receipt_packet_unchanged',svc.capsule(rid1,ref['capsule_id'])==capsule_before)
            rid3,did3,wire3=sign_payment(svc,'raven',7)
            check('post_hour_new_payment_signed',svc.wallet.status()['pending_debit_units']=='22')
            last_receipt=send_and_settle(svc,rid3,did3)
            check('post_hour_exact_native_execution',last_receipt['status']=='receipt_collected')
            post=svc.state()['ledger'];post_grants={g['id']:g for g in post['grants']};post_budgets={b['id']:b for b in post['budgets']};post_accounts={a['id']:a for a in post['accounts']}
            check('post_hour_positive_receipt_and_hold_reconciliation',svc.wallet.status()['pending_debit_units']=='13' and
                post_grants['raven']['nonce']=='2' and post_grants['raven']['spent']=='16' and post_grants['atlas']['nonce']=='0' and
                post_budgets['studio']['spent']=='16' and post_accounts[config['roles']['owner']['payer']]['recorded_balance']=='978' and
                post_accounts[config['merchant']]['recorded_balance']=='12')
            check('original_attempt_not_resent',svc.delivery.db.execute('SELECT count(*) FROM attempts').fetchone()[0]==2 and svc.delivery.db.execute('SELECT count(*) FROM attempts WHERE decision_id=?',(did1,)).fetchone()[0]==1)
            report['post_hour_payment']={'request_id':rid3,'decision_id':did3,'wire_sha256':hashlib.sha256(wire3).hexdigest(),'role':'raven','units':'7','fee':'2'}
            backup_file=workspace/'qualified-history.p4alpha'
            with svc.backup_history(backup_secret) as item:
                with backup_file.open('xb') as target:
                    backup_file.chmod(0o600)
                    while raw:=item['source'].read(65536):target.write(raw)
                    target.flush();os.fsync(target.fileno())
                report['private_backup']={k:item[k] for k in ('size','sha256','format')}
            restored=restore_backup(backup_file,workspace/'inert-recovery.p4alpha',genesis,policy,backup_secret)
            with RecoveryArchive(workspace/'inert-recovery.p4alpha',genesis,policy) as archive:
                recovered=archive.inspect()
                check('complete_encrypted_history_and_inert_recovery',restored['status']=='restored-alpha-recovery-only' and not recovered['signing_enabled'] and not recovered['dispatch_enabled'])
                check('all_original_inert_wires_and_fee_hold',archive.recover(did1,payer=config['roles']['raven']['payer'],grant_id='raven')==wire1 and
                    archive.recover(did2,payer=config['roles']['atlas']['payer'],grant_id='atlas')==wire2 and archive.recover(did3,payer=config['roles']['raven']['payer'],grant_id='raven')==wire3 and recovered['pending_debit_units']=='13')
            checked=verify_receipt(capsule_before,genesis,policy,payer=config['roles']['raven']['payer'],wire_sha256=hashlib.sha256(wire1).hexdigest())
            check('historical_portable_receipt_verified',checked['status']=='verified-historical-alpha-receipt' and not checked['current_spending_authority'])
            private_new(output/'final-history.json',svc.store.export_history())
            private_new(output/'final-wallet-state.json',encode(svc.state()))
            final=phase(svc,'post-hour-payment-and-complete-recovery')
            heights=[net.height(i) for i in range(4)]
            check('all_four_final_heights_consistent',min(heights)>=height and max(heights)-min(heights)<=2,node_heights=heights)
        check('source_engine_unchanged',evidence.source_identity(ROOT)==source and verify_engine(binary)==binary)
        stop_owned(net)
        check('all_owned_processes_reaped',all(p.get('reaped') is True and p.get('same_birth_still_present') is False and p.get('expected_stop_outcome') is True for p in report['owned_processes']))
        check('original_workspace_preserved',_files(workspace)==file_ids and read_private(workspace/'engine-genesis.json')==genesis and read_private(workspace/'policy.json')==policy_bytes)
        need({c['name'] for c in report['checks']}==set(EXPECTED_CHECKS) and all(c['passed'] for c in report['checks']),'incomplete alpha gate')
        report.update(status='passed',elapsed_seconds=time.monotonic()-started,completed_ns=time.time_ns(),same_genesis_home_db=True)
    except BaseException as exc:
        report.update(status='failed',failure_type=type(exc).__name__,elapsed_seconds=time.monotonic()-started)
        traceback.print_exc()
    finally:
        if net is not None and not net.stopped:
            try:stop_owned(net)
            except BaseException as exc:report['cleanup_failure_type']=type(exc).__name__;report['status']='failed'
        secret=backup_secret=None
        save();private_new(output/'result.json',encode(report))
    return report
