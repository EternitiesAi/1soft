/* Exact decimal strings remain strings. Only bounded block heights become Numbers. */
'use strict';
const MAX_UNITS=9007199254740991n;
function atomic(value,{positive=false}={}){
  if(typeof value!=='string'||!(/^(0|[1-9][0-9]*)$/).test(value)||value.length>19)throw Error('Exact atomic units required.');
  const n=BigInt(value);if(n>MAX_UNITS||(positive&&n===0n))throw Error('Amount is outside the native limit.');return n;
}
function formatUnits(value){return atomic(value).toLocaleString('en-US')+' DEV';}
function shortId(value){return typeof value==='string'&&value.length>24?value.slice(0,12)+'…'+value.slice(-8):value;}
function deadline(value){const ms=BigInt(value)/1000000n;return new Date(Number(ms)).toLocaleString();}
const STAGES={request_open:'Unsigned request',review_bound_unsigned:'Original review retained; signature unrecorded',
  signed_reserved:'Signed · obligation retained',recorded:'Execution reconciled in wallet',recorded_historical:'Execution recorded historically'};
function paymentProgress(e,inspected,live){
  const signed=['signed_reserved','recorded','recorded_historical'].includes(e.stage),
    historical=e.stage==='recorded_historical',reconciled=e.stage==='recorded',
    receipt=e.delivery?.receipt_status==='verified_historical_receipt',
    attempted=!!e.delivery?.attempt_recorded,bound=e.stage==='review_bound_unsigned'||signed;
  let title,detail,next,tone='neutral';
  if(!inspected){title='Saved state needs inspection';tone='warning';
    detail='The latest local action is unresolved. This request is a retained snapshot; current balances and signing authority are unavailable.';
    next='Reload view to inspect the original decision. Do not repeat signing or submission.';
  }else if(historical){title='Historical execution';
    detail='Execution is recorded historically. Current spending authority is unavailable; this view does not establish a current hold balance.';
    next='Export the original signed payment for inspection. Do not resubmit it.';
  }else if(!live){title='Current authority unavailable';tone='warning';
    detail='The fixed trust deadline or retained evidence cannot authorize current actions. Original decisions remain retained.';
    next='Reload the retained view or export the original payment. Reloading does not renew trust.';
  }else if(reconciled){title='Execution reconciled';tone='complete';
    detail='The wallet matched exact execution and retired this decision’s hold. Other pending obligations remain separate.';
    next=receipt?(e.capsule_ids?.length?'Export the retained receipt. It discloses full public chain history.':'Keep a portable receipt. It discloses full public chain history.'):'Collect a delivery receipt if needed. Ledger reconciliation does not create one.';
  }else if(receipt){title='Receipt verified';
    detail='Exact execution evidence is retained. Its fee-inclusive obligation remains until wallet reconciliation.';
    next='Reconcile wallet explicitly to retire this decision’s hold.';
  }else if(attempted){title='Payment outcome unknown';tone='warning';
    detail='A submission attempt is recorded. Its response is not execution proof; missing evidence does not mean unpaid.';
    next='Collect receipt evidence for the original signed payment. Do not send it again.';
  }else if(signed){title='Signed and reserved';
    detail='The original signed payment and fee-inclusive obligation are retained. No verified execution receipt is displayed.';
    next='Review one submission of the original signed bytes before sending.';
  }else if(bound){title='Original review retained';
    detail='A review is bound to this request, but a signature is not recorded in the inspected wallet.';
    next='Inspect the original review and signing role. Approval must match its retained context.';
  }else{title=e.request_open?'Unsigned request':'Unsigned request expired';
    detail='This is payment intent. It authenticates neither a merchant nor payment execution.';
    next=e.request_open?'Review the signing role, recipient, amount and fee before unlocking.':'This expired unsigned request cannot be approved.';
  }
  const steps=[['Review',bound,'Retained','Required'],['Signature',signed,'Original retained','Unrecorded'],
    ['Submission',attempted,'Attempt recorded','Unattempted'],['Receipt',receipt,'Verified at collection','Not collected'],
    ['Wallet',reconciled&&live,'Reconciled',signed?(live?'Obligation retained':'Current hold unavailable'):'No signature recorded']]
    .map(([label,done,yes,no])=>({label,done:inspected&&done,status:inspected?(done?yes:no):'Needs inspection'}));
  return {title,detail,next,tone,steps};
}
if(typeof module!=='undefined')module.exports={atomic,formatUnits,shortId,deadline,STAGES,paymentProgress};

if(typeof document!=='undefined'){
  const $=id=>document.getElementById(id);
  let state=null,selected=null,payment=null,dispatch=null,csrf='',busy=false,viewAvailable=false,generation=0;
  function text(id,value){$(id).textContent=value;}
  function show(id,yes){$(id).hidden=!yes;}
  function tell(message,error=false){text('feedback',message);$('feedback').classList.toggle('error',error);}
  async function get(path){const r=await fetch(path,{cache:'no-store',credentials:'omit'});const q=await r.json();if(!r.ok)throw Error(q.message||'View unavailable.');return q;}
  async function post(name,body){const r=await fetch('/api/'+name,{method:'POST',credentials:'omit',cache:'no-store',
    headers:{'Content-Type':'application/json','X-1soft-CSRF':csrf},body:JSON.stringify(body)});const q=await r.json();
    if(!r.ok)throw Error(q.message||'Action unavailable.');return q;}
  async function run(work,{inspectOnFailure=true}={}){
    if(busy)return;busy=true;disable(true);tell('Working on this explicit action…');
    try{await work();}catch(e){
      viewAvailable=false;clearReviews();
      if(inspectOnFailure){
        try{await reload();tell('The action was refused or its return was unavailable. The retained wallet has been inspected. Follow the saved decision; the action was not repeated.',true);}
        catch{tell('The action and current local state could not be confirmed. Reload the retained wallet before signing or submitting. Original obligations remain unresolved.',true);}
      }else tell('The retained wallet could not be inspected. Reload before signing or submitting. Original decisions and obligations remain retained.',true);
      if(!viewAvailable&&state)render();
      text('network-status',viewAvailable?'Retained wallet inspected':'Local state needs inspection');
      $('indicator').classList.toggle('verified',viewAvailable&&!!state?.current_evidence_available);
    }finally{busy=false;disable(false);}
  }
  function disable(value){document.querySelectorAll('button,input,select,textarea').forEach(b=>b.disabled=value);if(!value)controls();}
  function capture(role=null){return {request_id:selected,role,generation};}
  function current(context){return context&&context.request_id===selected&&context.generation===generation&&
    (context.role===null||context.role===$('role').value);}
  function requireCurrent(context){if(!current(context))throw Error('The selection changed. Review the selected payment again.');}
  function facts(id,rows){const el=$(id);el.replaceChildren();for(const [name,value]of rows){const dt=document.createElement('dt'),dd=document.createElement('dd');dt.textContent=name;dd.textContent=value;el.append(dt,dd);}}
  function entry(){return state?.requests.find(r=>r.request_id===selected);}
  function controls(){const e=entry(),live=viewAvailable&&!!state?.current_evidence_available,signed=e&&['signed_reserved','recorded','recorded_historical'].includes(e.stage);
    if(busy)document.querySelectorAll('button,input,select,textarea').forEach(b=>b.disabled=true);
    $('request-form').querySelector('button').disabled=!viewAvailable||busy;$('import').disabled=!viewAvailable||busy;
    $('refresh').disabled=!live||busy;$('sync').disabled=!live||busy;
    $('prepare').disabled=!live||!e||!e.request_open||signed||busy;
    $('sign').disabled=!payment||!current(payment.context)||!$('sign-check').checked||$('password').value.length<16||!live||busy;
    $('submission-review').disabled=!signed||e.stage==='recorded'||e.stage==='recorded_historical'||!!e.delivery?.attempt_recorded||e.delivery?.receipt_status==='verified_historical_receipt'||!live||busy;
    $('send').disabled=!dispatch||!current(dispatch.context)||!$('send-check').checked||!live||busy;
    $('collect').disabled=!signed||!live||busy;
    $('reconcile').disabled=!signed||e?.delivery?.receipt_status!=='verified_historical_receipt'||e?.stage==='recorded'||!live||busy;
    $('retain').disabled=!signed||e?.delivery?.receipt_status!=='verified_historical_receipt'||!live||busy;
  }
  function clearReviews(){generation++;payment=null;dispatch=null;$('password').value='';$('sign-check').checked=false;$('send-check').checked=false;show('payment-review',false);show('dispatch-review',false);}
  async function reload(){const next=await get('/api/state');state=next;clearReviews();viewAvailable=true;render();}
  function render(){const live=viewAvailable&&state.current_evidence_available,w=live?state.wallet:null,l=live?state.ledger:null;
    $('indicator').classList.toggle('verified',live);text('network-status',live?'Verified retained observation':'Current evidence unavailable');
    text('checkpoint',live?`Wallet block ${w.state_height} · ledger block ${l?.checkpoint.state_height??'unavailable'}. Collection is explicit.`:'Trust expired, evidence unavailable, or local validation refused. Original decisions remain retained.');
    const roles=Object.keys(state.roles).sort((a,b)=>['owner','raven','atlas'].indexOf(a)-['owner','raven','atlas'].indexOf(b)),payer=state.roles[roles[0]].payer,a=w?.accounts.find(a=>a.id===payer);
    text('balance',a?formatUnits(a.recorded_balance):'Unavailable');text('pending',w?formatUnits(w.pending_debit_units):'Unavailable');
    text('available',a?formatUnits(a.uncommitted_units):'Unavailable');text('deficit',a&&a.reservation_deficit_units!=='0'?`Reservation deficit: ${formatUnits(a.reservation_deficit_units)}`:'Within this shared local wallet');
    const b=w?.budgets[0];text('budget-free',b?formatUnits(b.uncommitted_units)+' uncommitted':'Unavailable');
    text('budget-text',b?`${formatUnits(b.cap)} cap · ${formatUnits(b.spent)} recorded spent · ${formatUnits(b.pending_debit_units)} pending. All agent lanes share this journal.`:'Current budget observation unavailable.');
    if(!$('recipient').value&&l?.grants[0]?.recipients[0])$('recipient').value=l.grants[0].recipients[0];
    const oldRole=$('role').value;$('role').replaceChildren();for(const r of roles){const option=document.createElement('option');option.value=r;option.textContent=r==='owner'?'Owner · treasury':`${r[0].toUpperCase()+r.slice(1)} · agent grant`;$('role').append(option);}if(roles.includes(oldRole))$('role').value=oldRole;
    text('request-count',`${state.requests.length} requests`);const list=$('requests');list.replaceChildren();
    for(const e of [...state.requests].reverse()){const button=document.createElement('button');button.className='request-item';button.classList.toggle('selected',e.request_id===selected);
      const title=document.createElement('strong'),amount=document.createElement('b'),stage=document.createElement('span');title.textContent=e.request.note||'Payment request';amount.textContent=formatUnits(e.request.units);
      stage.textContent=STAGES[e.stage]+(!viewAvailable?' · retained snapshot':e.request_open?'':' · request expired');button.append(title,amount,stage);button.addEventListener('click',()=>{if(busy)return;selected=e.request_id;clearReviews();renderDetail();render();});list.append(button);}
    show('empty',state.requests.length===0);renderDetail();
    const table=$('payments');table.replaceChildren();for(const p of (l?.payments||[]).slice(-24).reverse()){const tr=document.createElement('tr');for(const value of [p.height,p.grant_id||'Owner',shortId(p.recipient),formatUnits(p.units),formatUnits(p.fee_units),shortId(p.native_txid)]){const td=document.createElement('td');td.textContent=value;tr.append(td);}tr.lastChild.title=p.native_txid;table.append(tr);}
    show('ledger-empty',!l?.payments.length);text('ledger-height',l?`Recorded through block ${l.checkpoint.state_height}`:'No current evidence');
    text('trust-deadline',l?`Original trust deadline: ${deadline(l.checkpoint.trust_expires_ns)}`:'No current trust-qualified view.');text('genesis','External genesis · '+state.genesis_sha256);
    const validators=$('validators');validators.replaceChildren();for(const [i,v]of(l?.registry.active||[]).entries()){const box=document.createElement('div');box.className='validator';const label=document.createElement('p'),key=document.createElement('strong'),power=document.createElement('p');label.textContent='Validator '+(i+1);key.textContent=shortId(v.public_key);power.textContent='Voting power '+v.power;box.append(label,key,power);validators.append(box);}controls();
  }
  function renderDetail(){const e=entry();show('detail',!!e);if(!e)return;const signed=['signed_reserved','recorded','recorded_historical'].includes(e.stage);
    text('request-note',e.request.note||'Payment request');text('request-id',e.request_id);$('request-download').href='/api/request/'+e.request_id;
    facts('request-facts',[['Recipient',e.request.recipient],['Requested',formatUnits(e.request.units)],['Request expires',deadline(String(e.request.expires_ns))],['Stage',STAGES[e.stage]],...(e.decision_id?[['Decision',e.decision_id]]:[])]);
    const progress=paymentProgress(e,viewAvailable,viewAvailable&&state.current_evidence_available);
    text('progress-title',progress.title);text('progress-detail',progress.detail);text('progress-next',progress.next);
    $('progress').dataset.tone=progress.tone;const steps=$('payment-progress');steps.replaceChildren();
    for(const step of progress.steps){const li=document.createElement('li'),label=document.createElement('strong'),status=document.createElement('span');
      li.classList.toggle('done',step.done);label.textContent=step.label;status.textContent=step.status;li.append(label,status);steps.append(li);}
    show('review-controls',!signed);show('signed-controls',signed);
    if(signed){const d=e.delivery,execution=['recorded','recorded_historical'].includes(e.stage),live=viewAvailable&&state.current_evidence_available;
      text('delivery-status',`Original signature: retained\nSubmission: ${d?.attempt_recorded?d.transport_observation:'no local attempt recorded'}\nReceipt: ${d?.receipt_status==='verified_historical_receipt'?'verified at collection':execution?'not collected; execution evidenced separately':'unavailable; outcome unknown'}\nWallet: ${!viewAvailable?'needs inspection; current hold unavailable':!live?'current hold unavailable':e.stage==='recorded'?'exact execution reconciled':'original obligation retained'}`);
      $('original-download').href='/api/original/'+e.request_id;const cid=e.capsule_ids[0];show('capsule-download',!!cid);if(cid)$('capsule-download').href='/api/capsule/'+e.request_id+'/'+cid;}
  }
  $('request-form').addEventListener('submit',event=>{event.preventDefault();run(async()=>{atomic($('units').value,{positive:true});const q=await post('create-request',{recipient:$('recipient').value,units:$('units').value,note:$('note').value,lifetime_seconds:600});selected=q.request_id;await reload();tell('Request retained. Choose a role and review before signing.');});});
  $('import').addEventListener('click',()=>run(async()=>{const q=await post('import-request',{request_json:$('import-text').value});selected=q.request_id;$('import-text').value='';await reload();tell('Imported request retained. Identity and payment remain unproven until independently checked.');}));
  $('reload').addEventListener('click',()=>run(async()=>{await reload();tell('Retained view reloaded. No network collection or submission performed.');},{inspectOnFailure:false}));
  $('refresh').addEventListener('click',()=>run(async()=>{await post('refresh',{expected_tip:state.ledger?.checkpoint.evidence_id??null});await reload();tell('Verified ledger collected. Wallet obligations are unchanged; choose Use ledger in wallet to reconcile that observation.');}));
  $('sync').addEventListener('click',()=>run(async()=>{await post('sync',{expected_revision:state.wallet?.revision??null});await reload();tell('Wallet reconciled against the selected verified ledger observation.');}));
  $('role').addEventListener('change',()=>{clearReviews();controls();});
  $('prepare').addEventListener('click',()=>run(async()=>{clearReviews();const context=capture($('role').value);
    const prepared=await post('prepare',{request_id:context.request_id,role:context.role,valid_until:Math.min(512,state.wallet.state_height+32)});
    requireCurrent(context);if(prepared.request_id!==context.request_id||prepared.role!==context.role)throw Error('Returned review belongs to another request or role.');
    payment={...prepared,context};const s=payment.summary;
    facts('payment-facts',[['Role',context.role==='owner'?'Owner · treasury':context.role[0].toUpperCase()+context.role.slice(1)+' · agent grant'],['Recipient',s.recipient],['Amount',formatUnits(s.units)],['Fee',formatUnits(s.fee_units)],['Total debit',formatUnits(s.debit_units)],['Valid through','Block '+s.valid_until],['Source','Wallet block '+s.state_height]]);text('payment-digest',payment.confirmation);show('payment-review',true);text('sign','Sign and reserve '+formatUnits(s.debit_units));tell('Review the exact payment. Signing will reserve the total debit without sending it.');}));
  $('sign-check').addEventListener('change',controls);$('password').addEventListener('input',controls);$('send-check').addEventListener('change',controls);
  $('sign').addEventListener('click',()=>run(async()=>{const p=payment;requireCurrent(p?.context);const password=$('password').value;$('password').value='';payment=null;show('payment-review',false);
    try{const q=await post('sign',{request_id:p.context.request_id,role:p.context.role,review_json:p.review_json,confirmation:p.confirmation,password});await reload();tell(`Original signed decision retained: ${q.decision_id}. Submission has not been attempted.`);}finally{$('password').value='';}}));
  $('submission-review').addEventListener('click',()=>run(async()=>{clearReviews();const context=capture();
    const prepared=await post('submission-review',{request_id:context.request_id});requireCurrent(context);
    if(prepared.request_id!==context.request_id)throw Error('Returned submission review belongs to another request.');
    dispatch={...prepared,context};const s=dispatch.summary;
    facts('dispatch-facts',[['Original decision',s.decision_id],['Total debit',formatUnits(s.debit_units)],['Role',s.grant_id||'Owner'],['Fixed endpoint',s.endpoint],['Original wire',s.wire_sha256],['Valid through','Block '+s.valid_until]]);text('dispatch-digest',dispatch.confirmation);$('send-check').checked=false;show('dispatch-review',true);tell('Review one submission of the original signed payment. Admission will not prove execution.');}));
  $('send').addEventListener('click',()=>run(async()=>{const p=dispatch;requireCurrent(p?.context);dispatch=null;show('dispatch-review',false);const q=await post('submit',{request_id:p.context.request_id,review_json:p.review_json,confirmation:p.confirmation});await reload();tell(`Submission attempt retained: ${q.transport_observation}. Collect evidence of exact execution; do not resend.`);}));
  $('collect').addEventListener('click',()=>run(async()=>{const q=await post('collect',{request_id:selected});await reload();tell(q.status==='unavailable'?paymentProgress(entry(),viewAvailable,viewAvailable&&state.current_evidence_available).detail:'Exact receipt collected. Collection does not change wallet holds.');}));
  $('reconcile').addEventListener('click',()=>run(async()=>{await post('reconcile',{request_id:selected,expected_revision:state.wallet.revision});await reload();tell('Exact verified execution reconciled in the wallet.');}));
  $('retain').addEventListener('click',()=>run(async()=>{await post('retain',{request_id:selected});await reload();tell('Verified capsule retained under the original trust deadline. It includes full chain history; review that scope before sharing.');}));
  run(async()=>{csrf=(await get('/api/session')).csrf;await reload();tell('Ready. Review each signature and each submission separately.');},{inspectOnFailure:false});
}
