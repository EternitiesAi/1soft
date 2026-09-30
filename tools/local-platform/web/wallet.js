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
if(typeof module!=='undefined')module.exports={atomic,formatUnits,shortId,deadline,STAGES};

if(typeof document!=='undefined'){
  const $=id=>document.getElementById(id);
  let state=null,selected=null,payment=null,dispatch=null,csrf='',busy=false;
  function text(id,value){$(id).textContent=value;}
  function show(id,yes){$(id).hidden=!yes;}
  function tell(message,error=false){text('feedback',message);$('feedback').classList.toggle('error',error);}
  async function get(path){const r=await fetch(path,{cache:'no-store',credentials:'omit'});const q=await r.json();if(!r.ok)throw Error(q.message||'View unavailable.');return q;}
  async function post(name,body){const r=await fetch('/api/'+name,{method:'POST',credentials:'omit',cache:'no-store',
    headers:{'Content-Type':'application/json','X-1soft-CSRF':csrf},body:JSON.stringify(body)});const q=await r.json();
    if(!r.ok)throw Error(q.message||'Action unavailable.');return q;}
  async function run(work){if(busy)return;busy=true;disable(true);tell('Working on this explicit action…');
    try{await work();}catch(e){tell(e.message,true);}finally{busy=false;disable(false);}}
  function disable(value){document.querySelectorAll('button').forEach(b=>b.disabled=value);if(!value)controls();}
  function facts(id,rows){const el=$(id);el.replaceChildren();for(const [name,value]of rows){const dt=document.createElement('dt'),dd=document.createElement('dd');dt.textContent=name;dd.textContent=value;el.append(dt,dd);}}
  function entry(){return state?.requests.find(r=>r.request_id===selected);}
  function controls(){const e=entry(),live=!!state?.current_evidence_available,signed=e&&['signed_reserved','recorded','recorded_historical'].includes(e.stage);
    $('refresh').disabled=!live||busy;$('sync').disabled=!live||busy;
    $('prepare').disabled=!live||!e||!e.request_open||signed||busy;
    $('sign').disabled=!payment||!$('sign-check').checked||$('password').value.length<16||!live||busy;
    $('submission-review').disabled=!signed||!!e.delivery?.attempt_recorded||e.delivery?.receipt_status==='verified_historical_receipt'||!live||busy;
    $('send').disabled=!dispatch||!$('send-check').checked||!live||busy;
    $('collect').disabled=!signed||!live||busy;
    $('reconcile').disabled=!signed||e?.delivery?.receipt_status!=='verified_historical_receipt'||e?.stage==='recorded'||!live||busy;
    $('retain').disabled=!signed||e?.delivery?.receipt_status!=='verified_historical_receipt'||!live||busy;
  }
  function clearReviews(){payment=null;dispatch=null;$('password').value='';$('sign-check').checked=false;$('send-check').checked=false;show('payment-review',false);show('dispatch-review',false);}
  async function reload(){state=await get('/api/state');clearReviews();render();}
  function render(){const w=state.wallet,l=state.ledger,live=state.current_evidence_available;
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
      stage.textContent=STAGES[e.stage]+(e.request_open?'':' · request expired');button.append(title,amount,stage);button.addEventListener('click',()=>{selected=e.request_id;clearReviews();renderDetail();render();});list.append(button);}
    show('empty',state.requests.length===0);renderDetail();
    const table=$('payments');table.replaceChildren();for(const p of (l?.payments||[]).slice(-24).reverse()){const tr=document.createElement('tr');for(const value of [p.height,p.grant_id||'Owner',shortId(p.recipient),formatUnits(p.units),formatUnits(p.fee_units),shortId(p.native_txid)]){const td=document.createElement('td');td.textContent=value;tr.append(td);}tr.lastChild.title=p.native_txid;table.append(tr);}
    show('ledger-empty',!l?.payments.length);text('ledger-height',l?`Recorded through block ${l.checkpoint.state_height}`:'No current evidence');
    text('trust-deadline',l?`Original trust deadline: ${deadline(l.checkpoint.trust_expires_ns)}`:'No current trust-qualified view.');text('genesis','External genesis · '+state.genesis_sha256);
    const validators=$('validators');validators.replaceChildren();for(const [i,v]of(l?.registry.active||[]).entries()){const box=document.createElement('div');box.className='validator';const label=document.createElement('p'),key=document.createElement('strong'),power=document.createElement('p');label.textContent='Validator '+(i+1);key.textContent=shortId(v.public_key);power.textContent='Voting power '+v.power;box.append(label,key,power);validators.append(box);}controls();
  }
  function renderDetail(){const e=entry();show('detail',!!e);if(!e)return;const signed=['signed_reserved','recorded','recorded_historical'].includes(e.stage);
    text('request-note',e.request.note||'Payment request');text('request-id',e.request_id);$('request-download').href='/api/request/'+e.request_id;
    facts('request-facts',[['Recipient',e.request.recipient],['Requested',formatUnits(e.request.units)],['Request expires',deadline(String(e.request.expires_ns))],['Stage',STAGES[e.stage]],...(e.decision_id?[['Decision',e.decision_id]]:[])]);
    show('review-controls',!signed);show('signed-controls',signed);
    if(signed){const d=e.delivery;text('delivery-status',`Original signature: retained\nSubmission: ${d.attempt_recorded?d.transport_observation:'not attempted'}\nReceipt: ${d.receipt_status==='verified_historical_receipt'?'verified at collection':'unavailable; outcome unknown'}\nWallet: ${e.stage==='recorded'?'exact execution reconciled':'original obligation retained'}`);
      $('original-download').href='/api/original/'+e.request_id;const cid=e.capsule_ids[0];show('capsule-download',!!cid);if(cid)$('capsule-download').href='/api/capsule/'+e.request_id+'/'+cid;}
  }
  $('request-form').addEventListener('submit',event=>{event.preventDefault();run(async()=>{atomic($('units').value,{positive:true});const q=await post('create-request',{recipient:$('recipient').value,units:$('units').value,note:$('note').value,lifetime_seconds:600});selected=q.request_id;await reload();tell('Request retained. Choose a role and review before signing.');});});
  $('import').addEventListener('click',()=>run(async()=>{const q=await post('import-request',{request_json:$('import-text').value});selected=q.request_id;$('import-text').value='';await reload();tell('Imported request retained. Identity and payment remain unproven until independently checked.');}));
  $('reload').addEventListener('click',()=>run(async()=>{await reload();tell('Retained view reloaded. No network collection or submission performed.');}));
  $('refresh').addEventListener('click',()=>run(async()=>{await post('refresh',{expected_tip:state.ledger?.checkpoint.evidence_id??null});await reload();tell('Verified ledger collected. Wallet obligations are unchanged; choose Use ledger in wallet to reconcile that observation.');}));
  $('sync').addEventListener('click',()=>run(async()=>{await post('sync',{expected_revision:state.wallet?.revision??null});await reload();tell('Wallet reconciled against the selected verified ledger observation.');}));
  $('role').addEventListener('change',()=>{clearReviews();controls();});
  $('prepare').addEventListener('click',()=>run(async()=>{clearReviews();payment=await post('prepare',{request_id:selected,role:$('role').value,valid_until:Math.min(512,state.wallet.state_height+32)});const s=payment.summary;
    facts('payment-facts',[['Role',$('role').selectedOptions[0].textContent],['Recipient',s.recipient],['Amount',formatUnits(s.units)],['Fee',formatUnits(s.fee_units)],['Total debit',formatUnits(s.debit_units)],['Valid through','Block '+s.valid_until],['Source','Wallet block '+s.state_height]]);text('payment-digest',payment.confirmation);show('payment-review',true);text('sign','Sign and reserve '+formatUnits(s.debit_units));tell('Review the exact payment. Signing will reserve the total debit without sending it.');}));
  $('sign-check').addEventListener('change',controls);$('password').addEventListener('input',controls);$('send-check').addEventListener('change',controls);
  $('sign').addEventListener('click',()=>run(async()=>{const p=payment;const password=$('password').value;$('password').value='';payment=null;show('payment-review',false);
    try{const q=await post('sign',{request_id:selected,role:$('role').value,review_json:p.review_json,confirmation:p.confirmation,password});await reload();tell(`Original signed decision retained: ${q.decision_id}. Submission has not been attempted.`);}finally{$('password').value='';}}));
  $('submission-review').addEventListener('click',()=>run(async()=>{dispatch=await post('submission-review',{request_id:selected});const s=dispatch.summary;
    facts('dispatch-facts',[['Original decision',s.decision_id],['Total debit',formatUnits(s.debit_units)],['Role',s.grant_id||'Owner'],['Fixed endpoint',s.endpoint],['Original wire',s.wire_sha256],['Valid through','Block '+s.valid_until]]);text('dispatch-digest',dispatch.confirmation);$('send-check').checked=false;show('dispatch-review',true);tell('Review one submission of the original signed payment. Admission will not prove execution.');}));
  $('send').addEventListener('click',()=>run(async()=>{const p=dispatch;dispatch=null;show('dispatch-review',false);const q=await post('submit',{request_id:selected,review_json:p.review_json,confirmation:p.confirmation});await reload();tell(`Submission attempt retained: ${q.transport_observation}. Collect evidence of exact execution; do not resend.`);}));
  $('collect').addEventListener('click',()=>run(async()=>{const q=await post('collect',{request_id:selected});await reload();tell(q.status==='unavailable'?'Exact receipt unavailable. Outcome remains unknown and the obligation is retained.':'Exact receipt collected. Wallet obligations remain unchanged until reconciliation.');}));
  $('reconcile').addEventListener('click',()=>run(async()=>{await post('reconcile',{request_id:selected,expected_revision:state.wallet.revision});await reload();tell('Exact verified execution reconciled in the wallet.');}));
  $('retain').addEventListener('click',()=>run(async()=>{await post('retain',{request_id:selected});await reload();tell('Verified capsule retained under the original trust deadline. It includes full chain history; review that scope before sharing.');}));
  run(async()=>{csrf=(await get('/api/session')).csrf;await reload();tell('Ready. Review each signature and each submission separately.');});
}
