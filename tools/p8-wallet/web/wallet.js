'use strict';
const $=(id)=>document.getElementById(id);
const token=document.querySelector('meta[name="1soft-session"]').content;
let busy=false,reviewed=null,lastView=null,demoOutputs=null;
function notice(text,error=false){$('notice').textContent=text;$('notice').classList.toggle('error',error);}
function page(name){
  for(const el of document.querySelectorAll('.page'))el.hidden=el.id!==name;
  for(const el of document.querySelectorAll('nav button')){if(el.dataset.page===name)el.setAttribute('aria-current','page');else el.removeAttribute('aria-current');}
  if(name!=='recovery'){$('private-review').textContent='';$('review-panel').hidden=true;reviewed=null;}
  $('result-panel').hidden=true;
}
function nonce(){return Array.from(crypto.getRandomValues(new Uint8Array(24)),v=>v.toString(16).padStart(2,'0')).join('');}
function fields(form){return Object.fromEntries(new FormData(form));}
function button(text,fn){const el=document.createElement('button');el.className='quiet';el.textContent=text;el.addEventListener('click',fn);return el;}
function row(identifier,detail,action){const el=document.createElement('div');el.className='row';const text=document.createElement('div');const id=document.createElement('div');id.className='identifier';id.textContent=identifier;const small=document.createElement('small');small.textContent=detail;text.append(id,small);el.append(text,action);return el;}
function renderGuide(v){
  lastView=v;$('wallet-id').textContent=v.wallet_id;$('observed').textContent=v.as_of_height===null?'No signed state recorded':'AS-OF height '+v.as_of_height;$('connection').textContent='Authenticated local wallet';$('note-count').textContent=v.notes.length+' recorded';
  $('notes').replaceChildren();$('payments').replaceChildren();$('commitment').replaceChildren(new Option('Select an authenticated note',''));
  for(const id of v.notes){$('commitment').add(new Option(id,id));$('notes').append(row(id,'Recorded note commitment',button('Prepare',()=>{page('payment');$('commitment').value=id;prepareInstruction();})));}
  if(!v.notes.length){const p=document.createElement('p');p.className='empty';p.textContent='No notes recorded. Receive and authenticate a note to begin.';$('notes').append(p);}
  for(const item of v.obligations){const id=item.txid;const flags='Recorded attempts: '+item.attempts+' | Wallet completion flag: '+String(item.completed);$('payments').append(row(id||'Proof pending; no retained wire',flags,button('Review',()=>{if(id){page('recovery');$('txid').value=id;}})));}
  if(!v.obligations.length){const p=document.createElement('p');p.className='empty';p.textContent='No retained payments yet. Prepared originals will appear here.';$('payments').append(p);}
}
function result(v){
  $('result-panel').hidden=false;$('result-heading').textContent=v.state.replaceAll('-',' ');$('result-message').textContent=v.message||'';$('result-details').replaceChildren();
  for(const [key,label] of [['txid','Transaction'],['commitment','Note commitment'],['attempts','Recorded attempts'],['as_of_height','Signed AS-OF height'],['output_sha256','Local file SHA256'],['output_bytes','Local file bytes']])if(v[key]!==undefined){const el=document.createElement('div');const dt=document.createElement('dt');dt.textContent=label;const dd=document.createElement('dd');dd.textContent=String(v[key]);el.append(dt,dd);$('result-details').append(el);}
}
async function action(command,data={},confirmation=''){
  if(busy)return null;
  busy=true;for(const b of document.querySelectorAll('button'))b.disabled=true;
  notice('Working on '+command.replaceAll('-',' ')+'. Keep this window open; the original payment is retained.');
  try{
    const response=await fetch('/api/action',{method:'POST',headers:{'Content-Type':'application/json','X-1soft-Session':token},credentials:'omit',cache:'no-store',referrerPolicy:'no-referrer',body:JSON.stringify({command,fields:data,confirmation,nonce:nonce()})});
    const value=await response.json();
    if(!response.ok)throw new Error(value.message||'Local action refused.');
    const v=value.console_receipt.view;
    if(command==='guide'&&value.status!=='refused')renderGuide(v);else result(v);
    notice(v.message||'Local command completed.',value.status==='refused');
    return value;
  }catch(e){
    reviewed=null;$('review-panel').hidden=true;
    notice(command==='submit'?'The send response was lost or refused. Do not send again. Check status and reconcile the original payment.':(e.message||'Local response unavailable. Check the original state before another action.'),true);
    return null;
  }finally{
    busy=false;for(const b of document.querySelectorAll('button'))b.disabled=false;$('send').disabled=!(reviewed&&reviewed.can_submit);
  }
}
function prepareInstruction(){$('prepare-instruction').textContent=$('commitment').value?'Type PREPARE '+$('commitment').value+' to retain this exact payment locally.':'Select a note to view its exact confirmation.';}
for(const el of document.querySelectorAll('nav button'))el.addEventListener('click',()=>page(el.dataset.page));
$('refresh').addEventListener('click',()=>action('guide'));
const demo=$('demo-inputs');
if(demo)demo.addEventListener('click',async()=>{
  if(busy)return;
  try{
    const response=await fetch('/api/context',{method:'POST',headers:{'Content-Type':'application/json','X-1soft-Session':token},credentials:'omit',cache:'no-store',body:'{}'});
    if(!response.ok)throw new Error('Synthetic inputs unavailable.');
    const v=await response.json();
    demoOutputs=v.output_paths;
    for(const [form,values] of Object.entries(v.forms))for(const [name,value] of Object.entries(values))$(form).elements[name].value=value;
    notice(v.message); // Only paths/public fixture values. No action, proof or confirmation starts here.
  }catch(e){notice(e.message,true);}
});
$('output-form').elements.kind.addEventListener('change',e=>{if(demoOutputs)$('output-form').elements.output.value=demoOutputs[e.target.value];});
$('commitment').addEventListener('change',prepareInstruction);
$('txid').addEventListener('input',()=>{reviewed=null;$('review-panel').hidden=true;$('send').disabled=true;});
$('observe-form').addEventListener('submit',async e=>{e.preventDefault();await action('observe',fields(e.target));});
$('import-form').elements.source.addEventListener('change',e=>{$('wire-label').hidden=e.target.value==='genesis';if(e.target.value==='genesis')$('import-form').elements.wire.value='';});
$('import-form').addEventListener('submit',async e=>{e.preventDefault();await action('import-note',fields(e.target));});
$('prepare-form').addEventListener('submit',async e=>{e.preventDefault();const v=fields(e.target),confirmation=v.confirmation;delete v.confirmation;const answer=await action('prepare',v,confirmation);e.target.elements.confirmation.value='';if(answer&&answer.console_receipt.view.txid){$('txid').value=answer.console_receipt.view.txid;}});
$('review-form').addEventListener('submit',async e=>{e.preventDefault();reviewed=null;const answer=await action('review',fields(e.target));if(answer&&answer.status!=='refused'){reviewed={...answer.console_receipt.view,txid:$('txid').value};$('review-panel').hidden=false;$('private-review').textContent=answer.private_display;$('submit-instruction').textContent='Type SUBMIT '+reviewed.txid+' '+reviewed.review.wire_sha256+' to send this original once.';$('send').disabled=!reviewed.can_submit;}});
$('status').addEventListener('click',async()=>{reviewed=null;$('review-panel').hidden=true;await action('status',{txid:$('txid').value});});
$('submit-form').addEventListener('submit',async e=>{e.preventDefault();if(!reviewed||!reviewed.can_submit)return;const txid=reviewed.txid;const confirmation=fields(e.target).confirmation;reviewed=null;$('review-panel').hidden=true;await action('submit',{txid},confirmation);e.target.elements.confirmation.value='';$('private-review').textContent='';});
$('recover-form').addEventListener('submit',async e=>{e.preventDefault();reviewed=null;await action('reconcile',{txid:$('txid').value,...fields(e.target)});});
$('output-form').addEventListener('submit',async e=>{e.preventDefault();const v=fields(e.target),command=v.kind;delete v.kind;if(command==='export')delete v.output_index;await action(command,{txid:$('txid').value,...v});});
// Authentication starts only on an explicit operator action. No background
// refresh, stored private fields, command replay or automatic submission.
