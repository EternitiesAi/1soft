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
function prepareHeight(state){
  let ceiling=512;
  if(state.development_profile!==undefined){
    if(state.development_profile!=='durable-private-alpha-v1'||state.limits?.rpc_height!==4096||state.limits?.offline_height!==4096)throw Error('Unsupported development profile or height bounds.');
    ceiling=4096;
  }
  const height=state.wallet?.state_height;
  if(!Number.isSafeInteger(height)||height<1||height>ceiling)throw Error('Wallet height is outside the development profile.');
  return Math.min(ceiling,height+32);
}
const STAGES={request_open:'Unsigned request',review_bound_unsigned:'Original review retained; signature unrecorded',
  signed_reserved:'Signed · obligation retained',recorded:'Execution reconciled in wallet',recorded_historical:'Execution recorded historically'};
function paymentProgress(e,inspected,live,ready=live){
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
  }else if(!ready){title='Wallet needs current verification';tone='warning';
    detail='The read ledger is current. The saved wallet context is not ready to authorize signing or submission; original obligations remain retained.';
    next='Use ledger in wallet to verify its context. A refused verification does not renew authority or release holds.';
  }else if(reconciled){title='Execution reconciled';tone='complete';
    detail='The wallet matched exact execution and retired this decision’s hold. Other pending obligations remain separate.';
    next=receipt?(e.capsule_ids?.length?'Export the retained receipt. It discloses full public chain history.':'Keep a portable receipt. It discloses full public chain history.'):'Collect a delivery receipt if needed. Ledger reconciliation does not create one.';
  }else if(receipt){title='Receipt verified';
    detail='Exact execution evidence is retained. Its fee-inclusive obligation remains until wallet reconciliation.';
    next='Reconcile wallet explicitly to retire this decision’s hold.';
  }else if(attempted){title='Payment outcome unknown';tone='warning';
    detail='A submission attempt is recorded. Its response is not execution proof; missing evidence does not mean unpaid.';
    next='Collect receipt evidence for the original signed payment. Do not send it again.';
  }else if(signed&&e.invoice&&!e.request_open){title='Invoice expired';tone='warning';
    detail='The original signed payment and obligation remain retained. Quote expiry cannot establish that it is unpaid.';
    next='Recover the original payment or collect exact execution evidence. A new submission is unavailable.';
  }else if(signed){title='Signed and reserved';
    detail='The original signed payment and fee-inclusive obligation are retained. No verified execution receipt is displayed.';
    next='Review one submission of the original signed bytes before sending.';
  }else if(bound){title='Original review retained';
    detail='A review is bound to this request, but a signature is not recorded in the inspected wallet.';
    next='Inspect the original review and signing role. Approval must match its retained context.';
  }else{title=e.request_open?'Unsigned request':'Unsigned request expired';
    detail=e.invoice?'This is a retained merchant quote. Approving its terms and native payment is still required; execution and fulfillment are unproven.':'This is payment intent. It authenticates neither a merchant nor payment execution.';
    next=e.request_open?'Review the signing role, recipient, amount and fee before unlocking.':'This expired unsigned request cannot be approved.';
  }
  const steps=[['Review',bound,'Retained','Required'],['Signature',signed,'Original retained','Unrecorded'],
    ['Submission',attempted,'Attempt recorded','Unattempted'],['Receipt',receipt,'Verified at collection','Not collected'],
    ['Wallet',reconciled&&live,'Reconciled',signed?(live?'Obligation retained':'Current hold unavailable'):'No signature recorded']]
    .map(([label,done,yes,no])=>({label,done:inspected&&done,status:inspected?(done?yes:no):'Needs inspection'}));
  return {title,detail,next,tone,steps};
}
function backupInputs(passphrase,repeat,scope){
  const valid=value=>typeof value==='string'&&value.length<=1024&&![...value].some(c=>{const n=c.codePointAt(0);return n>=0xd800&&n<=0xdfff;})&&
    new TextEncoder().encode(value).length>=16&&new TextEncoder().encode(value).length<=1024;
  if(!valid(passphrase)||!valid(repeat))throw Error('Use a backup passphrase of 16–1024 UTF-8 bytes in both fields.');
  if(passphrase!==repeat)throw Error('The backup passphrases differ. Enter both again.');
  if(scope!==true)throw Error('Confirm the complete shared-history scope before downloading.');
  return {passphrase,repeat_passphrase:repeat,scope_confirmed:true};
}
function historyProfile(response){
  const format=response.headers.get('X-1Soft-Backup-Format');
  if(format===null)return {limit:16*1024*1024,magic:'1SOFTP4B3\n',filename:'1soft-recovery-history.p4b3'};
  if(format==='alpha-v1')return {limit:180*1024*1024,magic:'1SOFTP4A1\n',filename:'1soft-recovery-history.p4alpha'};
  throw Error('History download format header is unsupported.');
}
async function historyBlob(response){
  if(!response.ok){await response.body?.cancel();throw Error('History backup was refused or unavailable. The original journals are retained.');}
  let profile;
  try{profile=historyProfile(response);}catch(e){await response.body?.cancel();throw e;}
  const {limit,magic}=profile,declared=response.headers.get('Content-Length');
  if(response.headers.get('Content-Type')!=='application/octet-stream'||!declared||!(/^[1-9][0-9]{0,8}$/).test(declared)||Number(declared)>limit){
    await response.body?.cancel();throw Error('History download headers exceed the supported bound.');
  }
  const reader=response.body?.getReader();if(!reader)throw Error('History download body unavailable.');
  const parts=[];let size=0,complete=false;
  try{
    while(true){const {value,done}=await reader.read();if(done)break;
      if(!(value instanceof Uint8Array)||!value.length||size+value.length>Number(declared)||size+value.length>limit)throw Error('History download exceeded its declared bound.');
      size+=value.length;parts.push(value);
    }
    if(size!==Number(declared))throw Error('History download was incomplete.');
    const blob=new Blob(parts,{type:'application/octet-stream'});
    const prefix=new Uint8Array(await blob.slice(0,10).arrayBuffer());
    if(blob.size!==size||prefix.length!==10||prefix.some((b,i)=>b!==magic.charCodeAt(i)))throw Error('History download format differs.');
    complete=true;return blob;
  }finally{if(!complete)await reader.cancel().catch(()=>{});reader.releaseLock();}
}
async function merchantBlob(response,pin,{proof=false}={}){
  let reader=null,complete=false;
  try{
  if(!response.ok||response.status!==200||response.headers.get('Content-Type')!=='application/octet-stream'||
     response.headers.get('Content-Encoding')!==null||response.headers.get('Transfer-Encoding')!==null)throw Error('Purchase response is unavailable or has another encoding.');
  const length=response.headers.get('Content-Length'),limit=proof?90*1024*1024:65536;
  if(!/^[1-9][0-9]{0,8}$/.test(length||'')||Number(length)>limit)throw Error('Purchase response exceeds its declared bound.');
  for(const key of ['request_id','quote_sha256','resource_sha256','wire_sha256','capsule_sha256','native_txid']){
    if(!/^[0-9a-f]{64}$/.test(pin?.[key]||'')||response.headers.get('X-1soft-'+key.replaceAll('_','-'))!==pin[key])throw Error('Purchase response belongs to another invoice or original payment.');
  }
  const fulfilled=response.headers.get('X-1soft-Fulfilled-Ns');
  if(!/^[1-9][0-9]{0,18}$/.test(fulfilled||'')||BigInt(fulfilled)>9223372036854775807n||
     (pin.fulfilled_ns!==null&&pin.fulfilled_ns!==undefined&&fulfilled!==pin.fulfilled_ns))throw Error('Original fulfillment time differs.');
  const digest=proof?response.headers.get('X-1soft-Proof-Sha256'):pin.resource_sha256;
  if(!/^[0-9a-f]{64}$/.test(digest||'')||(proof&&response.headers.get('X-1soft-Proof-Format')!=='alpha-v1'))throw Error('Purchase proof format or digest differs.');
  reader=response.body?.getReader();if(!reader)throw Error('Purchase bytes are unavailable.');
  const chunks=[];let total=0;
    while(true){const item=await reader.read();if(item.done)break;total+=item.value.byteLength;
      if(total>Number(length)||chunks.length>=32768)throw Error('Purchase byte stream exceeds its bound.');chunks.push(item.value);}
    if(total!==Number(length))throw Error('Purchase byte stream was truncated.');
    const blob=new Blob(chunks,{type:'application/octet-stream'});
    const actual=Array.from(new Uint8Array(await globalThis.crypto.subtle.digest('SHA-256',await blob.arrayBuffer())),b=>b.toString(16).padStart(2,'0')).join('');
    if(actual!==digest)throw Error('Purchase bytes do not match the retained digest.');
    complete=true;return {blob,fulfilled_ns:fulfilled};
  }finally{if(!complete){if(reader)await reader.cancel().catch(()=>{});else await response.body?.cancel().catch(()=>{});}reader?.releaseLock();}
}
const resourceBlob=(response,pin)=>merchantBlob(response,pin);
const merchantProofBlob=(response,pin)=>merchantBlob(response,pin,{proof:true});
async function checkedMerchantReview(prepared){
  if(typeof prepared?.review_json!=='string'||!/^[0-9a-f]{64}$/.test(prepared.confirmation||''))throw Error('Retrieval review text or confirmation is missing.');
  const review=JSON.parse(prepared.review_json),summary=prepared.summary;
  if(!review||Array.isArray(review)||!summary||Array.isArray(summary)||
     review.format!=='1soft/alpha-browser-resource-review/v1'||review.full_public_ledger_disclosed!==true||review.signing_or_submission_performed!==false||
     Object.keys(review).length!==Object.keys(summary).length||Object.keys(review).some(k=>
       !Object.hasOwn(summary,k)||review[k]!==summary[k]||(review[k]!==null&&!['string','boolean'].includes(typeof review[k]))))throw Error('Displayed retrieval facts differ from the original review.');
  const digest=Array.from(new Uint8Array(await globalThis.crypto.subtle.digest('SHA-256',new TextEncoder().encode(prepared.review_json))),b=>b.toString(16).padStart(2,'0')).join('');
  if(digest!==prepared.confirmation)throw Error('Retrieval confirmation differs from the exact review text.');
  return review;
}
if(typeof module!=='undefined')module.exports={atomic,formatUnits,shortId,deadline,STAGES,paymentProgress,backupInputs,historyProfile,historyBlob,resourceBlob,merchantProofBlob,checkedMerchantReview};

if(typeof document!=='undefined'){
  const $=id=>document.getElementById(id);
  let state=null,selected=null,payment=null,dispatch=null,purchase=null,csrf='',busy=false,viewAvailable=false,generation=0;
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
  function controls(){const e=entry(),live=viewAvailable&&!!state?.current_evidence_available,ready=live&&(state?.signing_ready??live),signed=e&&['signed_reserved','recorded','recorded_historical'].includes(e.stage);
    if(busy)document.querySelectorAll('button,input,select,textarea').forEach(b=>b.disabled=true);
    $('request-form').querySelector('button').disabled=!viewAvailable||busy;$('import').disabled=!viewAvailable||busy;
    $('refresh').disabled=!live||busy;$('sync').disabled=!live||busy;
    $('prepare').disabled=!ready||!e||!e.request_open||signed||busy;
    $('sign').disabled=!payment||!current(payment.context)||!$('sign-check').checked||(!!e?.invoice&&(!$('terms-check').checked||!payment?.terms_json||!e.request_open))||$('password').value.length<16||!ready||busy;
    $('submission-review').disabled=!signed||e.stage==='recorded'||e.stage==='recorded_historical'||!!e.delivery?.attempt_recorded||e.delivery?.receipt_status==='verified_historical_receipt'||(!!e.invoice&&!e.request_open)||!ready||busy;
    $('send').disabled=!dispatch||!current(dispatch.context)||!$('send-check').checked||(!!e?.invoice&&!e.request_open)||!ready||busy;
    $('collect').disabled=!signed||!live||busy;
    $('reconcile').disabled=!signed||e?.delivery?.receipt_status!=='verified_historical_receipt'||e?.stage==='recorded'||!live||busy;
    $('retain').disabled=!signed||e?.delivery?.receipt_status!=='verified_historical_receipt'||!live||busy;
    $('backup-download').disabled=!viewAvailable||!$('backup-scope').checked||busy;
    $('purchase-review').disabled=!viewAvailable||!e?.merchant_delivery?.retrieval_available||busy;
    $('purchase-retrieve').disabled=!purchase||!current(purchase.context)||!$('purchase-share').checked||!viewAvailable||busy;
    $('purchase-proof').disabled=!purchase||!current(purchase.context)||!$('purchase-share').checked||!e?.merchant_delivery?.consumption_retained||!viewAvailable||busy;
  }
  function clearReviews(){generation++;payment=null;dispatch=null;purchase=null;$('password').value='';$('sign-check').checked=false;$('terms-check').checked=false;$('terms-facts').replaceChildren();text('terms-digest','');show('merchant-terms-review',false);$('send-check').checked=false;show('payment-review',false);show('dispatch-review',false);$('purchase-share').checked=false;show('purchase-confirmation',false);}
  async function reload(){const next=await get('/api/state');state=next;clearReviews();viewAvailable=true;render();}
  function render(){const live=viewAvailable&&state.current_evidence_available,ready=live&&(state.signing_ready??live),walletCurrent=live&&(state.wallet_current??live),
      w=viewAvailable&&(live||state.wallet_current!==undefined)?state.wallet:null,l=live?state.ledger:null;
    $('indicator').classList.toggle('verified',live);text('network-status',live?(ready?'Verified retained observation':'Read current · wallet needs verification'):'Current evidence unavailable');
    text('checkpoint',w?`Wallet block ${w.state_height}${walletCurrent?'':' (saved historical context)'} · ledger block ${l?.checkpoint.state_height??'unavailable'}. Collection and wallet verification are explicit.`:'Trust expired, evidence unavailable, or local validation refused. Original decisions remain retained.');
    const roles=Object.keys(state.roles).sort((a,b)=>['owner','raven','atlas'].indexOf(a)-['owner','raven','atlas'].indexOf(b)),payer=state.roles[roles[0]].payer,a=w?.accounts.find(a=>a.id===payer);
    text('balance',a?formatUnits(a.recorded_balance)+(walletCurrent?'':' · saved'):'Unavailable');text('pending',w?formatUnits(w.pending_debit_units)+(walletCurrent?'':' · saved obligations'):'Unavailable');
    text('available',a&&ready?formatUnits(a.uncommitted_units):'Unavailable');text('deficit',a&&a.reservation_deficit_units!=='0'?`Reservation deficit: ${formatUnits(a.reservation_deficit_units)}`:ready?'Within this shared local wallet':'Saved obligations retained; current spending authority unavailable');
    const b=w?.budgets[0];text('budget-free',b&&ready?formatUnits(b.uncommitted_units)+' uncommitted':'Unavailable');
    text('budget-text',b?`${formatUnits(b.cap)} cap · ${formatUnits(b.spent)} recorded spent · ${formatUnits(b.pending_debit_units)} pending${walletCurrent?'':' at the saved wallet context'}. All agent lanes share this journal.`:'Current budget observation unavailable.');
    if(!$('recipient').value&&l?.grants[0]?.recipients[0])$('recipient').value=l.grants[0].recipients[0];
    const oldRole=$('role').value;$('role').replaceChildren();for(const r of roles){const option=document.createElement('option');option.value=r;option.textContent=r==='owner'?'Owner · treasury':`${r[0].toUpperCase()+r.slice(1)} · agent grant`;$('role').append(option);}if(roles.includes(oldRole))$('role').value=oldRole;
    const merchantMode=state.payment_mode==='committed_merchant_invoices';show('unsigned-compose',!merchantMode);show('merchant-inbox-info',merchantMode);
    text('hidden-requests',state.hidden_generic_request_count?`${state.hidden_generic_request_count} generic requests are outside this invoice view. Treasury and budget totals include every obligation in the shared wallet.`:'Treasury and budget totals include every obligation in the shared wallet.');
    text('request-count',`${state.requests.length} ${merchantMode?'invoices':'requests'}`);const list=$('requests');list.replaceChildren();
    for(const e of [...state.requests].reverse()){const button=document.createElement('button');button.className='request-item';button.classList.toggle('selected',e.request_id===selected);
      const title=document.createElement('strong'),amount=document.createElement('b'),stage=document.createElement('span');title.textContent=e.invoice?'Merchant invoice':e.request.note||'Payment request';amount.textContent=formatUnits(e.request.units);
      stage.textContent=STAGES[e.stage]+(!viewAvailable?' · retained snapshot':e.request_open?'':' · request expired');button.append(title,amount,stage);button.addEventListener('click',()=>{if(busy)return;selected=e.request_id;clearReviews();renderDetail();render();});list.append(button);}
    show('empty',state.requests.length===0);renderDetail();
    const table=$('payments');table.replaceChildren();for(const p of (l?.payments||[]).slice(-24).reverse()){const tr=document.createElement('tr');for(const value of [p.height,p.grant_id||'Owner',shortId(p.recipient),formatUnits(p.units),formatUnits(p.fee_units),shortId(p.native_txid)]){const td=document.createElement('td');td.textContent=value;tr.append(td);}tr.lastChild.title=p.native_txid;table.append(tr);}
    show('ledger-empty',!l?.payments.length);text('ledger-height',l?`Recorded through block ${l.checkpoint.state_height}`:'No current evidence');
    text('trust-deadline',l?(state.limits?.absolute_not_after_ns?`Checkpoint trust deadline: ${deadline(l.checkpoint.trust_expires_ns)} · Fixed alpha horizon: ${deadline(String(state.limits.absolute_not_after_ns))}`:`Original trust deadline: ${deadline(l.checkpoint.trust_expires_ns)}`):'No current trust-qualified view.');text('genesis','External genesis · '+state.genesis_sha256);
    const validators=$('validators');validators.replaceChildren();for(const [i,v]of(l?.registry.active||[]).entries()){const box=document.createElement('div');box.className='validator';const label=document.createElement('p'),key=document.createElement('strong'),power=document.createElement('p');label.textContent='Validator '+(i+1);key.textContent=shortId(v.public_key);power.textContent='Voting power '+v.power;box.append(label,key,power);validators.append(box);}controls();
  }
  function renderDetail(){const e=entry();show('detail',!!e);if(!e)return;const signed=['signed_reserved','recorded','recorded_historical'].includes(e.stage);
    text('request-note',e.invoice?'Merchant invoice':e.request.note||'Payment request');
    show('invoice-detail',!!e.invoice);if(e.invoice)facts('invoice-facts',[['Merchant origin',e.invoice.merchant_origin],['Resource',e.invoice.resource_url],['Public resource digest',e.invoice.resource_sha256],['Native invoice commitment',e.invoice.invoice_commitment],['Quote expires',deadline(e.invoice.expires_ns)]]);text('request-id',e.request_id);$('request-download').href='/api/request/'+e.request_id;
    facts('request-facts',[['Recipient',e.request.recipient],['Requested',formatUnits(e.request.units)],['Request expires',deadline(String(e.request.expires_ns))],['Stage',STAGES[e.stage]],...(e.decision_id?[['Decision',e.decision_id]]:[])]);
    const progress=paymentProgress(e,viewAvailable,viewAvailable&&state.current_evidence_available,viewAvailable&&state.current_evidence_available&&(state.signing_ready??state.current_evidence_available));
    text('progress-title',progress.title);text('progress-detail',progress.detail);text('progress-next',progress.next);
    $('progress').dataset.tone=progress.tone;const steps=$('payment-progress');steps.replaceChildren();
    for(const step of progress.steps){const li=document.createElement('li'),label=document.createElement('strong'),status=document.createElement('span');
      li.classList.toggle('done',step.done);label.textContent=step.label;status.textContent=step.status;li.append(label,status);steps.append(li);}
    show('review-controls',!signed);show('signed-controls',signed);
    show('purchase-section',!!e.invoice&&!!state.merchant_fulfillment_available);
    if(e.merchant_delivery){const d=e.merchant_delivery;
      text('purchase-status',d.consumption_retained?'The merchant retains the original consumption. Resource receipt in this browser is still unconfirmed; explicitly retrieve and verify it.':d.enrolled?'The merchant enrolled the original paid receipt. Resource consumption has not been confirmed.':'The merchant operator must separately enroll the original paid receipt before retrieval.');
      text('purchase-review',d.consumption_retained?'Review retrieval again':'Review purchase retrieval');}
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
    const prepared=await post('prepare',{request_id:context.request_id,role:context.role,valid_until:prepareHeight(state)});
    requireCurrent(context);if(prepared.request_id!==context.request_id||prepared.role!==context.role)throw Error('Returned review belongs to another request or role.');
    const e=entry();if(e.invoice){const t=prepared.terms_summary;
      if(typeof prepared.terms_json!=='string'||!prepared.terms_json||typeof prepared.terms_confirmation!=='string'||!t||t.request_id!==context.request_id||t.role!==context.role||t.native_confirmation!==prepared.confirmation||t.quote_sha256!==e.invoice.quote_sha256||t.invoice_commitment!==e.invoice.invoice_commitment||t.resource_sha256!==e.invoice.resource_sha256)throw Error('Returned merchant terms differ from the selected invoice.');
      facts('terms-facts',[['Merchant origin',t.merchant_origin],['Resource',t.resource_url],['Recipient',t.recipient],['Invoice amount',formatUnits(t.amount_units)],['Public resource digest',t.resource_sha256],['Native invoice commitment',t.invoice_commitment],['Quote expires',deadline(t.expires_ns)]]);text('terms-digest',prepared.terms_confirmation);show('merchant-terms-review',true);
    }else if(prepared.terms_json)throw Error('Merchant consent returned for a generic request.');
    payment={...prepared,context};const s=payment.summary;
    facts('payment-facts',[['Role',context.role==='owner'?'Owner · treasury':context.role[0].toUpperCase()+context.role.slice(1)+' · agent grant'],['Recipient',s.recipient],['Amount',formatUnits(s.units)],['Fee',formatUnits(s.fee_units)],['Total debit',formatUnits(s.debit_units)],['Valid through','Block '+s.valid_until],['Source','Wallet block '+s.state_height]]);text('payment-digest',payment.confirmation);show('payment-review',true);text('sign','Sign and reserve '+formatUnits(s.debit_units));tell('Review the exact payment. Signing will reserve the total debit without sending it.');}));
  $('sign-check').addEventListener('change',controls);$('terms-check').addEventListener('change',controls);$('password').addEventListener('input',controls);$('send-check').addEventListener('change',controls);
  $('sign').addEventListener('click',()=>run(async()=>{const p=payment;requireCurrent(p?.context);const password=$('password').value;$('password').value='';payment=null;show('payment-review',false);
    try{const body={request_id:p.context.request_id,role:p.context.role,review_json:p.review_json,confirmation:p.confirmation,password};
      if(p.terms_json){if(!$('terms-check').checked)throw Error('Explicit merchant terms consent is required.');body.terms_json=p.terms_json;body.terms_confirmation=p.terms_confirmation;}
      const q=await post(p.terms_json?'sign-invoice':'sign',body);await reload();tell(`Original signed decision retained: ${q.decision_id}. Submission has not been attempted.`);}finally{$('password').value='';}}));
  $('submission-review').addEventListener('click',()=>run(async()=>{clearReviews();const context=capture();
    const prepared=await post('submission-review',{request_id:context.request_id});requireCurrent(context);
    if(prepared.request_id!==context.request_id)throw Error('Returned submission review belongs to another request.');
    dispatch={...prepared,context};const s=dispatch.summary;
    facts('dispatch-facts',[['Original decision',s.decision_id],['Total debit',formatUnits(s.debit_units)],['Role',s.grant_id||'Owner'],['Fixed endpoint',s.endpoint],['Original wire',s.wire_sha256],['Valid through','Block '+s.valid_until]]);text('dispatch-digest',dispatch.confirmation);$('send-check').checked=false;show('dispatch-review',true);tell('Review one submission of the original signed payment. Admission will not prove execution.');}));
  $('send').addEventListener('click',()=>run(async()=>{const p=dispatch;requireCurrent(p?.context);dispatch=null;show('dispatch-review',false);const q=await post('submit',{request_id:p.context.request_id,review_json:p.review_json,confirmation:p.confirmation});await reload();tell(`Submission attempt retained: ${q.transport_observation}. Collect evidence of exact execution; do not resend.`);}));
  $('collect').addEventListener('click',()=>run(async()=>{const q=await post('collect',{request_id:selected});await reload();tell(q.status==='unavailable'?paymentProgress(entry(),viewAvailable,viewAvailable&&state.current_evidence_available).detail:'Exact receipt collected. Collection does not change wallet holds.');}));
  $('reconcile').addEventListener('click',()=>run(async()=>{await post('reconcile',{request_id:selected,expected_revision:state.wallet.revision});await reload();tell('Exact verified execution reconciled in the wallet.');}));
  $('retain').addEventListener('click',()=>run(async()=>{await post('retain',{request_id:selected});await reload();tell('Verified capsule retained under the original trust deadline. It includes full chain history; review that scope before sharing.');}));
  $('purchase-review').addEventListener('click',()=>run(async()=>{
    clearReviews();const context=capture();const prepared=await post('merchant-review',{request_id:context.request_id});requireCurrent(context);
    const s=await checkedMerchantReview(prepared);requireCurrent(context);const e=entry();
    if(prepared.request_id!==context.request_id||!s||s.request_id!==context.request_id||s.decision_id!==e.decision_id||
       s.quote_sha256!==e.invoice.quote_sha256||s.resource_sha256!==e.invoice.resource_sha256||
       s.resource_url!==e.invoice.resource_url||s.merchant_origin!==e.invoice.merchant_origin||
       ['wire_sha256','capsule_sha256','native_txid'].some(k=>s[k]!==e.merchant_delivery[k])||
       typeof prepared.review_json!=='string'||!/^[0-9a-f]{64}$/.test(prepared.confirmation||''))throw Error('Returned retrieval review differs from the selected original invoice.');
    purchase={...prepared,summary:s,context};facts('purchase-facts',[['Merchant endpoint',s.merchant_origin],['Resource',s.resource_url],['Public resource digest',s.resource_sha256],
      ['Original payment',s.native_txid],['Receipt packet digest',s.capsule_sha256],['Original role',s.grant_id||'Owner'],['Retained fulfillment',s.fulfilled_ns?deadline(s.fulfilled_ns):'Not yet consumed']]);
    show('purchase-confirmation',true);tell('Review sharing the original public receipt. Retrieval does not sign, submit or reconcile the wallet.');
  }));
  $('purchase-share').addEventListener('change',controls);
  function downloadBlob(blob,filename){const url=URL.createObjectURL(blob),a=document.createElement('a');
    try{a.href=url;a.download=filename;document.body.append(a);a.click();}finally{a.remove();setTimeout(()=>URL.revokeObjectURL(url),1000);}}
  async function purchaseFetch(path,options,p,proof=false){
    const controller=new AbortController(),timer=setTimeout(()=>controller.abort(),150000);
    try{const response=await fetch(path,{...options,signal:controller.signal,credentials:'omit',cache:'no-store',redirect:'error'});
      const result=await (proof?merchantProofBlob:resourceBlob)(response,p.summary);requireCurrent(p.context);return result;
    }finally{clearTimeout(timer);}}
  $('purchase-retrieve').addEventListener('click',()=>run(async()=>{
    const p=purchase;requireCurrent(p?.context);if(!$('purchase-share').checked)throw Error('Public receipt disclosure consent is required.');
    purchase=null;show('purchase-confirmation',false);
    const result=await purchaseFetch('/api/merchant-retrieve',{method:'POST',headers:{'Content-Type':'application/json','X-1soft-CSRF':csrf},
      body:JSON.stringify({request_id:p.context.request_id,review_json:p.review_json,confirmation:p.confirmation})},p);
    downloadBlob(result.blob,'1soft-purchase-'+p.context.request_id+'.bin');await reload();
    if(selected!==p.context.request_id)throw Error('The selected invoice changed while refreshing purchase state.');
    text('purchase-status','Original purchase bytes received and digest-verified in this browser. The download was offered; saving it is your browser’s decision.');
    tell('Purchase bytes verified and download offered. No payment was repeated.');
  }));
  $('purchase-proof').addEventListener('click',()=>run(async()=>{
    const p=purchase;requireCurrent(p?.context);if(!$('purchase-share').checked)throw Error('Public receipt disclosure consent is required.');
    const result=await purchaseFetch('/api/merchant-proof/'+p.context.request_id,{method:'GET'},p,true);
    downloadBlob(result.blob,'1soft-merchant-proof-'+p.context.request_id+'.json');
    tell('Merchant proof download offered. It includes full public history; independent genesis, policy and invoice pins are needed for offline verification.');
  }));
  $('backup-scope').addEventListener('change',controls);
  $('backup-form').addEventListener('submit',async event=>{
    event.preventDefault();let passphrase=$('backup-passphrase').value,repeat=$('backup-repeat').value;
    $('backup-passphrase').value='';$('backup-repeat').value='';
    if(busy){passphrase=repeat='';return;}
    busy=true;disable(true);text('backup-feedback','Capturing and encrypting the complete retained shared history…');
    $('backup-feedback').classList.remove('error');let url=null,anchor=null,body=null;
    try{
      body=backupInputs(passphrase,repeat,$('backup-scope').checked);passphrase=repeat='';
      const response=await fetch('/api/backup-history',{method:'POST',credentials:'omit',cache:'no-store',
        headers:{'Content-Type':'application/json','X-1soft-CSRF':csrf},body:JSON.stringify(body)});
      body=null;const blob=await historyBlob(response);url=URL.createObjectURL(blob);
      anchor=document.createElement('a');anchor.href=url;anchor.download=historyProfile(response).filename;
      anchor.hidden=true;document.body.append(anchor);anchor.click();
      text('backup-feedback','Encrypted history download requested. Keep the file, passphrase and original genesis/policy pins privately. This does not restore an active account or renew spending authority.');
    }catch{
      text('backup-feedback','History download was refused, incomplete or unavailable. No payment was signed or submitted. Enter both passphrases again to retry explicitly; legacy downloads have an 8 MiB history / 16 MiB file limit; explicit alpha downloads have a 64 MiB history / 180 MiB file limit. Nothing is evicted to fit.');
      $('backup-feedback').classList.add('error');
    }finally{
      passphrase=repeat='';body=null;$('backup-passphrase').value='';$('backup-repeat').value='';$('backup-scope').checked=false;
      anchor?.remove();if(url)URL.revokeObjectURL(url);busy=false;disable(false);
    }
  });
  run(async()=>{csrf=(await get('/api/session')).csrf;await reload();tell('Ready. Review each signature and each submission separately.');},{inspectOnFailure:false});
}
