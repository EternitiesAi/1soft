"""Read-only P4 display projection. Input authority remains the pinned verifier/store."""
import json,time
from p4_evidence import verify_evidence,p4_genesis,need
from p4_read_store import P4ReadStore


def project_report(report,genesis_bytes,policy):
    """Internal projection of an already verified report; never a proof ingestion API."""
    g,_=p4_genesis(genesis_bytes,policy['genesis_sha256'])
    checkpoint={k:str(report[k]) for k in ['state_height','header_height','registry_epoch','checked_at_ns','trust_expires_ns']}
    checkpoint.update({k:report[k] for k in ['app_hash','header_hash','evidence_id','policy_id','genesis_sha256']})
    accounts=[{**a,**{k:str(a[k]) for k in ['nonce','epoch','recorded_balance']}} for a in report['accounts']]
    budgets=[]
    for bid,owner,epoch,cap,spent,expires,recipients,revoked in report['budgets']:
        budgets.append({'id':bid,'owner':owner,'epoch':str(epoch),'cap':str(cap),'spent':str(spent),
            'recorded_remaining':str(cap-spent),'expires':str(expires),'recipients':json.loads(recipients),'revoked':bool(revoked)})
    links=dict(report['grant_budgets']);grants=[]
    for gid,owner,key,epoch,nonce,cap,spent,expires,recipients,revoked in report['grants']:
        grants.append({'id':gid,'owner':owner,'public_key':key,'epoch':str(epoch),'nonce':str(nonce),
            'cap':str(cap),'spent':str(spent),'recorded_remaining':str(cap-spent),'expires':str(expires),
            'recipients':json.loads(recipients),'revoked':bool(revoked),'budget_id':links.get(gid)})
    payments=[]
    for row in report['receipts']:
        rec=row['record'];body=rec['envelope']['body'];op=body['op']
        if op['type']!='transfer':continue
        payments.append({**{k:row[k] for k in ['native_txid','receipt_sha256','wire_sha256']},
            'height':str(row['height']),'index':str(row['index']),'payer':body['sender'],
            'recipient':op['to'],'units':str(op['units']),'fee_units':str(rec['fee_units']),
            'grant_id':body['grant_id'],'signer_public_key':rec['signer_public_key']})
    reg=report['registry'];pending=reg['pending']
    # Registry JSON has only public keys/hashes and bounded exact integer metadata.
    def strings(value):
        if type(value) is int:return str(value)
        if isinstance(value,list):return [strings(x) for x in value]
        if isinstance(value,dict):return {k:strings(v) for k,v in value.items()}
        return value
    registry={'active':strings(reg['active_validators']),'next':strings(reg['next_validators']),
        'active_hash':reg['active_hash'],'next_hash':reg['next_hash'],'pending':strings(pending),
        'last_activation_height':str(reg['last_activation_height']),
        'transitions':strings(report['validator_transitions'])}
    return {'schema':1,'status':'verified-p4-historical-state','chain_id':g['chain_id'],'asset':g['asset'],
        'checkpoint':checkpoint,'accounts':accounts,'budgets':budgets,'grants':grants,
        'payments':payments,'registry':registry,'recorded_supply_units':report['recorded_supply_units'],
        'latest_state_guaranteed':False,'pending_wallet_debits_included':False,'spending_authority':False,
        'independent_validator_hosts_verified':False,'external_settlement_verified':False}


def snapshot_view(evidence,genesis_bytes,policy,*,now_ns):
    return project_report(verify_evidence(evidence,genesis_bytes,policy,now_ns=now_ns),genesis_bytes,policy)


def current_view(store_path,genesis_bytes,policy,*,clock=time.time_ns):
    with P4ReadStore(store_path,genesis_bytes,policy,read_only=True,clock=clock) as store:
        report=store.current();need(report is not None,'no verified checkpoint available')
        return project_report(report,genesis_bytes,policy)
