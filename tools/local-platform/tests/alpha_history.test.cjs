const test=require('node:test');const assert=require('node:assert/strict');
const fs=require('node:fs');const vm=require('node:vm');const path=require('node:path');
const wallet=require('../web/wallet.js');
const legacy=Buffer.from('1SOFTP4B3\npublic test ciphertext');
const alpha=Buffer.from('1SOFTP4A1\npublic test ciphertext');
function response(raw,format,declared=raw.length){
  const headers={'Content-Type':'application/octet-stream','Content-Length':String(declared)};
  if(format!==undefined)headers['X-1Soft-Backup-Format']=format;
  return new Response(raw,{headers});
}
test('alpha history has its explicit cap, magic and filename while legacy stays fixed',async()=>{
  assert.equal((await wallet.historyBlob(response(alpha,'alpha-v1'))).size,alpha.length);
  assert.equal(wallet.historyProfile(response(alpha,'alpha-v1')).filename,'1soft-recovery-history.p4alpha');
  assert.equal(wallet.historyProfile(response(alpha,'alpha-v1')).limit,180*1024*1024);
  assert.equal(wallet.historyProfile(response(legacy)).filename,'1soft-recovery-history.p4b3');
  assert.equal(wallet.historyProfile(response(legacy)).limit,16*1024*1024);
});
test('unknown/duplicate/empty formats and mixed magics are refused',async()=>{
  for(const [raw,format] of [[alpha,undefined],[legacy,'alpha-v1'],[alpha,'alpha-v2'],
      [alpha,'alpha-v1, alpha-v1'],[alpha,''],[alpha,'legacy-v3']]){
    await assert.rejects(wallet.historyBlob(response(raw,format)));
  }
});
test('alpha alone permits a complete file beyond legacy cap without accepting alpha overflow',async()=>{
  const raw=Buffer.alloc(16*1024*1024+1);alpha.copy(raw,0);
  assert.equal((await wallet.historyBlob(response(raw,'alpha-v1'))).size,raw.length);
  await assert.rejects(wallet.historyBlob(response(raw)));
  for(const declared of [180*1024*1024+1,'0188743680','1887436800']){
    await assert.rejects(wallet.historyBlob(response(alpha,'alpha-v1',declared)));
  }
});
test('alpha oversized and incomplete streams are cancelled without completed downloads',async()=>{
  for(const mode of ['oversized','incomplete']){
    let cancelled=false;
    const stream=new ReadableStream({start(c){c.enqueue(mode==='oversized'?new Uint8Array(11):alpha.subarray(0,9));},
      cancel(){cancelled=true;}});
    // The incomplete stream errors after its initial chunk; no result is downloadable.
    if(mode==='incomplete'){
      const short=new Response(alpha.subarray(0,9),{headers:{'Content-Type':'application/octet-stream',
        'Content-Length':String(alpha.length),'X-1Soft-Backup-Format':'alpha-v1'}});
      await assert.rejects(wallet.historyBlob(short),/incomplete/);
    }else{
      await assert.rejects(wallet.historyBlob(new Response(stream,{headers:{'Content-Type':'application/octet-stream',
        'Content-Length':'10','X-1Soft-Backup-Format':'alpha-v1'}})),/bound/);
      assert.equal(cancelled,true);
    }
  }
});

function state({ready=false,signed=false}={}){
  const payer='lab_'+'1'.repeat(64);
  return {current_evidence_available:true,wallet_current:ready,signing_ready:ready,
    wallet:{revision:7,state_height:4,pending_debit_units:'60',
      accounts:[{id:payer,recorded_balance:'994',uncommitted_units:'934',reservation_deficit_units:'0'}],
      budgets:[{cap:'100',spent:'0',pending_debit_units:'60',uncommitted_units:'40'}]},
    ledger:{checkpoint:{state_height:9,evidence_id:'e'.repeat(64),trust_expires_ns:'4102444800000000000'},
      grants:[],payments:[],registry:{active:[]}},roles:{owner:{payer}},genesis_sha256:'b'.repeat(64),
    requests:[{request_id:'a'.repeat(64),request:{recipient:payer,units:'58',note:'public control fixture',
      expires_ns:'4102444800000000000'},request_open:true,stage:signed?'signed_reserved':'request_open',
      decision_id:signed?'d'.repeat(64):null,capsule_ids:[],
      delivery:signed?{attempt_recorded:false,receipt_status:'unavailable'}:null}]};
}
async function page(snapshot){
  class Element{
    constructor(id=''){this.id=id;this.disabled=false;this.hidden=false;this.value='';this.checked=false;
      this.children=[];this.listeners={};this.dataset={};this.classList={toggle(){},add(){},remove(){}};}
    addEventListener(name,fn){this.listeners[name]=fn;}
    replaceChildren(...items){this.children=items;}
    append(...items){this.children.push(...items);}
    querySelector(){return this.button??(this.button=new Element());}
    remove(){}
  }
  const elements=new Map();const document={getElementById(id){
    if(!elements.has(id))elements.set(id,new Element(id));return elements.get(id);
  },querySelectorAll(){return [...elements.values()];},createElement(){return new Element();},body:new Element()};
  const calls=[];const context={document,TextEncoder,Blob,Uint8Array,URL,console,
    fetch:async(url,options={})=>{calls.push({url,method:options.method??'GET',...(options.body?{body:JSON.parse(options.body)}:{})});
      return {ok:true,json:async()=>{
        if(url==='/api/session')return {csrf:'key-free-fixture'};
        if(url==='/api/prepare'){
          const q=JSON.parse(options.body);return {request_id:q.request_id,role:q.role,
            confirmation:'c'.repeat(64),review_json:'public key-free review fixture',
            summary:{recipient:snapshot.requests[0].request.recipient,units:'58',fee_units:'2',
              debit_units:'60',valid_until:q.valid_until,state_height:snapshot.wallet.state_height}};
        }
        return snapshot;
      }};}};
  vm.runInNewContext(fs.readFileSync(path.join(__dirname,'../web/wallet.js'),'utf8'),context);
  await new Promise(resolve=>setImmediate(resolve));await new Promise(resolve=>setImmediate(resolve));
  elements.get('requests').children[0].listeners.click();
  elements.get('role').value='owner'; // Browser selects a valid role; the minimal DOM has no HTML select default.
  return {elements,calls};
}
test('actual alpha controls disable signing and dispatch on an older wallet while allowing explicit read refresh/sync',async()=>{
  for(const signed of [false,true]){
    const {elements,calls}=await page(state({ready:false,signed}));
    assert.equal(elements.get('refresh').disabled,false);
    assert.equal(elements.get('sync').disabled,false);
    for(const id of ['prepare','sign','submission-review','send'])assert.equal(elements.get(id).disabled,true,id);
    assert.deepEqual(calls,[{url:'/api/session',method:'GET'},{url:'/api/state',method:'GET'}]);
  }
});
test('actual controls preserve legacy readiness fallback and ready alpha preparation',async()=>{
  for(const legacyMode of [false,true]){
    const snapshot=state({ready:true});
    if(legacyMode){delete snapshot.wallet_current;delete snapshot.signing_ready;}
    const {elements}=await page(snapshot);
    assert.equal(elements.get('prepare').disabled,false);
    assert.equal(elements.get('refresh').disabled,false);
    assert.equal(elements.get('sync').disabled,false);
  }
});

test('actual historical render keeps saved balances and fee holds while hiding current spendable units',async()=>{
  for(const current of [false,true]){
    const snapshot=state({ready:false});snapshot.current_evidence_available=current;
    const {elements}=await page(snapshot);
    assert.match(elements.get('balance').textContent,/994 DEV.*saved/);
    assert.match(elements.get('pending').textContent,/60 DEV.*saved obligations/);
    assert.equal(elements.get('available').textContent,'Unavailable');
    assert.equal(elements.get('budget-free').textContent,'Unavailable');
    assert.match(elements.get('checkpoint').textContent,/saved historical context/);
    assert.equal(elements.get('sync').disabled,!current);
    assert.equal(elements.get('refresh').disabled,!current);
    if(current)assert.match(elements.get('progress-title').textContent,/current verification/);
  }
});
test('alpha deadline render distinguishes checkpoint interval from the immutable horizon',async()=>{
  const snapshot=state({ready:true});snapshot.limits={absolute_not_after_ns:'4102444800000000000'};
  const {elements}=await page(snapshot);
  assert.match(elements.get('trust-deadline').textContent,/Checkpoint trust deadline:.*Fixed alpha horizon:/);
});


test('actual prepare sends a future alpha height above512 using the advertised4096 profile',async()=>{
  const snapshot=state({ready:true});snapshot.wallet.state_height=513;
  snapshot.development_profile='durable-private-alpha-v1';snapshot.limits={rpc_height:4096,offline_height:4096};
  const {elements,calls}=await page(snapshot);await elements.get('prepare').listeners.click();
  const posted=calls.find(x=>x.url==='/api/prepare');assert.ok(posted);
  assert.equal(posted.body.valid_until,545);
  assert.match(elements.get('payment-facts').children.map(x=>x.textContent??x.children.map(y=>y.textContent).join(' ')).join(' '),/545/);
});
test('actual legacy prepare keeps its512 ceiling without an alpha profile',async()=>{
  const snapshot=state({ready:true});snapshot.wallet.state_height=500;
  const {elements,calls}=await page(snapshot);await elements.get('prepare').listeners.click();
  assert.equal(calls.find(x=>x.url==='/api/prepare').body.valid_until,512);
});
test('actual alpha prepare caps near its advertised4096 boundary',async()=>{
  const snapshot=state({ready:true});snapshot.wallet.state_height=4090;
  snapshot.development_profile='durable-private-alpha-v1';snapshot.limits={rpc_height:4096,offline_height:4096};
  const {elements,calls}=await page(snapshot);await elements.get('prepare').listeners.click();
  assert.equal(calls.find(x=>x.url==='/api/prepare').body.valid_until,4096);
});
test('unknown profile or incoherent alpha bounds refuse before prepare POST',async()=>{
  for(const [profile,limits] of [['other-alpha',{rpc_height:4096,offline_height:4096}],
    ['durable-private-alpha-v1',{rpc_height:8192,offline_height:4096}],
    ['durable-private-alpha-v1',{rpc_height:4096,offline_height:'4096'}],
    ['durable-private-alpha-v1',{}]]){
    const snapshot=state({ready:true});snapshot.development_profile=profile;snapshot.limits=limits;
    const {elements,calls}=await page(snapshot);await elements.get('prepare').listeners.click();
    assert.equal(calls.filter(x=>x.url==='/api/prepare').length,0);
  }
});
test('invalid or out-of-profile wallet heights refuse before prepare POST',async()=>{
  for(const height of [0,-1,1.5,'513',NaN,Infinity,4097]){
    const snapshot=state({ready:true});snapshot.wallet.state_height=height;
    snapshot.development_profile='durable-private-alpha-v1';snapshot.limits={rpc_height:4096,offline_height:4096};
    const {elements,calls}=await page(snapshot);await elements.get('prepare').listeners.click();
    assert.equal(calls.filter(x=>x.url==='/api/prepare').length,0);
  }
});
