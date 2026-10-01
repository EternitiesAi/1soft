/* Real Chromium events with a controlled, key-free HTTP API fixture.
 * This tests the interface, not signatures, consensus, custody or real funds.
 * Supply an existing playwright-core directory and browser executable; no installs.
 */
const test=require('node:test');const assert=require('node:assert/strict');
const http=require('node:http');const fs=require('node:fs');const path=require('node:path');
const {chromium}=require(process.env.ONE_BROWSER_TEST_DRIVER||'playwright-core');
const RID='a'.repeat(64),DID='d'.repeat(64),PAYER='lab_'+'1'.repeat(64),RECIPIENT='lab_'+'2'.repeat(64);
// Lose the application return after HTTP headers, not before any reply bytes.
// Chromium can transparently retry a reused connection that closes before headers.
// That separate transport behavior is not a JavaScript retry or a new signature.
function loseReturn(res){res.writeHead(200,{'Content-Type':'application/json','Content-Length':'1000','Connection':'close'});
  res.flushHeaders();res.write('{"incomplete":');setImmediate(()=>res.destroy());}
function initial(){return {schema:1,format:'1soft/local-platform-state/v1',asset:'DEV',
  current_evidence_available:true,wallet:{revision:1,state_height:4,pending_debit_units:'0',
    accounts:[{id:PAYER,recorded_balance:'994',uncommitted_units:'994',reservation_deficit_units:'0'}],
    budgets:[{cap:'100',spent:'0',pending_debit_units:'0',uncommitted_units:'100'}],decisions:[]},
  ledger:{checkpoint:{state_height:4,evidence_id:'e'.repeat(64),trust_expires_ns:'4102444800000000000'},
    grants:[{recipients:[RECIPIENT]}],payments:[],registry:{active:[]}},
  requests:[{request_id:RID,request:{schema:1,format:'1soft/payment-request/v1',genesis_sha256:'b'.repeat(64),
    recipient:RECIPIENT,units:'7',note:'Browser event fixture',created_ns:1700000000000000000,
    expires_ns:4102444800000000000},decision_id:null,stage:'request_open',request_open:true,
    delivery:null,capsule_ids:[],current_spending_authority:false}],
  roles:{owner:{payer:PAYER,grant_id:''},raven:{payer:PAYER,grant_id:'raven'},atlas:{payer:PAYER,grant_id:'atlas'}},
  genesis_sha256:'b'.repeat(64),policy_id:'c'.repeat(64),
  limits:{rpc_height:64,offline_height:512,wallet_observations:32,wallet_decisions:256,requests:64,receipt_capsules:32,trust_renewal:false},
  real_funds_supported:false,automatic_resend:false,public_deployment:false};}
function invoiceState(){const s=initial();s.payment_mode='committed_merchant_invoices';s.hidden_generic_request_count=2;
  s.requests[0].request.created_ns='1700000000000000001';s.requests[0].request.expires_ns='4102444800000000001';
  s.requests[0].invoice={merchant_origin:'https://merchant.example',resource_url:'https://merchant.example/premium',
    resource_sha256:'7'.repeat(64),invoice_commitment:'8'.repeat(64),quote_sha256:'6'.repeat(64),
    created_ns:'1700000000000000001',expires_ns:'4102444800000000001',onchain_privacy:false};return s;}
function invoicePrepared(q){const p=prepared(q);p.terms_json='{"request_id":"'+q.request_id+'","role":"'+q.role+'","expires_ns":4102444800000000001}';
  p.terms_confirmation='5'.repeat(64);p.terms_summary={...invoiceState().requests[0].invoice,
    request_id:q.request_id,role:q.role,native_confirmation:p.confirmation,amount_units:'7',recipient:RECIPIENT};return p;}
function signed(state){state.requests[0].decision_id=DID;state.requests[0].stage='signed_reserved';
  state.requests[0].delivery={attempt_recorded:false,transport_observation:'not_attempted',receipt_status:'unavailable'};
  state.wallet.pending_debit_units='9';state.wallet.accounts[0].uncommitted_units='985';}
function prepared(q){const review={schema:1,format:'1soft/p4-transfer-review/v1',body:{sender:PAYER,grant_id:q.role==='owner'?'':q.role,
  op:{type:'transfer',to:RECIPIENT,units:7},max_fee:2,valid_until:36,nonce:1},debit_units:'9',state_height:4};
  return {request_id:q.request_id,role:q.role,confirmation:'f'.repeat(64),review_json:JSON.stringify(review),
    summary:{payer:PAYER,recipient:RECIPIENT,units:'7',fee_units:'2',debit_units:'9',grant_id:review.body.grant_id,
      valid_until:'36',nonce:'1',state_height:'4'}};}
async function fixture(t,{state=initial(),delayPrepare=false,lostSign=false,lostSubmit=false,failInspection=false}={}){
  const calls=[];let releasePrepare=null,prepareReceived=null;const prepareSeen=new Promise(r=>prepareReceived=r);
  const web=path.resolve(__dirname,'../web');
  const server=http.createServer(async(req,res)=>{try{
    const respond=(code,value,type='application/json')=>{res.writeHead(code,{'Content-Type':type,'Cache-Control':'no-store'});res.end(typeof value==='string'?value:JSON.stringify(value));};
    if(req.url==='/'||req.url==='/wallet.js'||req.url==='/wallet.css'){
      const name=req.url==='/'?'index.html':req.url.slice(1);respond(200,fs.readFileSync(path.join(web,name),'utf8'),name.endsWith('.html')?'text/html':name.endsWith('.js')?'text/javascript':'text/css');return;}
    if(req.url==='/api/session'){respond(200,{csrf:'key-free-fixture',development_only:true});return;}
    if(req.url==='/api/state'){
      calls.push({path:req.url,method:req.method});
      if(failInspection&&calls.some(c=>['/api/sign','/api/sign-invoice'].includes(c.path)))respond(503,{message:'Fixture inspection unavailable.'});else respond(200,state);return;}
    if(req.method!=='POST'){respond(404,{message:'Fixture route unavailable.'});return;}
    let raw='';for await(const part of req)raw+=part;const q=JSON.parse(raw);calls.push({path:req.url,method:req.method,body:q});
    if(req.url==='/api/prepare'){
      const value=state.payment_mode?invoicePrepared(q):prepared(q);if(delayPrepare){releasePrepare=()=>respond(200,value);prepareReceived();}else respond(200,value);return;}
    if(req.url==='/api/sign'||req.url==='/api/sign-invoice'){
      if(state.payment_mode){assert.equal(req.url,'/api/sign-invoice');assert.equal(q.terms_json,invoicePrepared(q).terms_json);assert.equal(q.terms_confirmation,'5'.repeat(64));}
      assert.equal(q.request_id,RID);assert.equal(q.role,'owner');assert.equal(q.review_json,JSON.stringify(JSON.parse(q.review_json)));
      signed(state);if(lostSign)loseReturn(res);else respond(200,{decision_id:DID,broadcast:false});return;}
    if(req.url==='/api/submission-review'){
      respond(200,{request_id:RID,confirmation:'f'.repeat(64),review_json:'{"decision_id":"'+DID+'"}',
        summary:{decision_id:DID,payer:PAYER,grant_id:'',wire_sha256:'9'.repeat(64),endpoint:'http://127.0.0.1:1',
          valid_until:'36',debit_units:'9',state_height:'4',registry_epoch:'0'}});return;}
    if(req.url==='/api/submit'){
      state.requests[0].delivery.attempt_recorded=true;state.requests[0].delivery.transport_observation='transport_unavailable';
      if(lostSubmit)loseReturn(res);else respond(200,{transport_observation:'transport_unavailable'});return;}
    respond(400,{message:'Fixture action refused.'});
  }catch{res.destroy();}});
  let browser=null,context=null;
  t.after(async()=>{
    if(releasePrepare){releasePrepare();releasePrepare=null;}
    const closed=await Promise.allSettled([context?.close(),browser?.close()]);
    server.closeAllConnections();if(server.listening)await new Promise(r=>server.close(r));
    for(const result of closed)assert.equal(result.status,'fulfilled');
    t.diagnostic('owned browser contexts and loopback server closed');
  });
  await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(0,'127.0.0.1',resolve);});
  browser=await chromium.launch({headless:true,executablePath:process.env.ONE_BROWSER_TEST_EXECUTABLE});
  context=await browser.newContext({viewport:{width:1280,height:900}});const page=await context.newPage();page.setDefaultTimeout(4000);
  t.diagnostic('Chromium '+browser.version()+'; playwright-core '+require(path.join(process.env.ONE_BROWSER_TEST_DRIVER||'playwright-core','package.json')).version);
  const errors=[];page.on('pageerror',e=>errors.push(e.message));
  await page.goto(`http://127.0.0.1:${server.address().port}/`);await page.waitForFunction(()=>document.querySelector('#feedback').textContent.startsWith('Ready.'));
  await page.locator('.request-item').click();
  return {page,calls,state,errors,prepareSeen,allowInspection:()=>{failInspection=false;},release:()=>{assert.ok(releasePrepare);releasePrepare();releasePrepare=null;}};
}
async function sign(page){await page.locator('#prepare').click();await page.locator('#payment-review').waitFor({state:'visible'});
  await page.locator('#sign-check').check();await page.locator('#password').fill('fixture-password-only');await page.locator('#sign').click();}
test('pending review locks the role and every editable payment field',async t=>{
  const f=await fixture(t,{delayPrepare:true});await f.page.locator('#prepare').click();await f.prepareSeen;
  for(const id of ['role','password','sign-check','send-check','recipient','units','note','import-text'])
    assert.equal(await f.page.locator('#'+id).isDisabled(),true,id+' stays editable during pending review');
  f.release();await f.page.locator('#payment-review').waitFor({state:'visible'});assert.deepEqual(f.errors,[]);
});
test('late review cannot reappear after its signing role changed',async t=>{
  const f=await fixture(t,{delayPrepare:true});await f.page.locator('#prepare').click();await f.prepareSeen;
  await f.page.evaluate(()=>{const role=document.querySelector('#role');role.value='raven';role.dispatchEvent(new Event('change'));});
  f.release();await f.page.waitForFunction(()=>!document.querySelector('#feedback').textContent.startsWith('Working'));
  assert.equal(await f.page.locator('#payment-review').isVisible(),false);
  assert.equal(await f.page.locator('#sign').isDisabled(),true);assert.deepEqual(f.errors,[]);
});
test('lost signing return inspects original retained decision without another signature',async t=>{
  const f=await fixture(t,{lostSign:true});await sign(f.page);
  await f.page.waitForFunction(()=>!document.querySelector('#feedback').textContent.startsWith('Working'));
  assert.equal(f.calls.filter(c=>c.path==='/api/sign').length,1);
  assert.deepEqual(f.calls.filter(c=>c.method==='POST').map(c=>c.path),['/api/prepare','/api/sign']);
  assert.equal(f.calls.find(c=>c.path==='/api/sign').body.review_json,prepared({request_id:RID,role:'owner'}).review_json);
  assert.equal(f.calls.find(c=>c.path==='/api/sign').body.confirmation,'f'.repeat(64));
  assert.equal(f.state.requests[0].delivery.attempt_recorded,false);
  assert.equal(f.calls.filter(c=>c.path==='/api/state').length,2);
  assert.equal(await f.page.locator('#signed-controls').isVisible(),true);
  assert.match(await f.page.locator('#pending').textContent(),/9 DEV/);
  assert.equal(await f.page.locator('#password').inputValue(),'');assert.deepEqual(f.errors,[]);
});
test('failed inspection after a lost signature makes new signing unavailable until reload',async t=>{
  const f=await fixture(t,{lostSign:true,failInspection:true});await sign(f.page);
  await f.page.waitForFunction(()=>!document.querySelector('#feedback').textContent.startsWith('Working'));
  assert.equal(f.calls.filter(c=>c.path==='/api/sign').length,1);
  assert.deepEqual(f.calls.filter(c=>c.method==='POST').map(c=>c.path),['/api/prepare','/api/sign']);
  assert.equal(f.calls.find(c=>c.path==='/api/sign').body.review_json,prepared({request_id:RID,role:'owner'}).review_json);
  assert.equal(f.calls.find(c=>c.path==='/api/sign').body.confirmation,'f'.repeat(64));
  assert.equal(f.state.requests[0].delivery.attempt_recorded,false);
  assert.equal(await f.page.locator('#prepare').isDisabled(),true);
  assert.equal(await f.page.locator('#reload').isDisabled(),false);
  assert.equal(await f.page.locator('#pending').textContent(),'Unavailable');
  assert.equal(await f.page.locator('#available').textContent(),'Unavailable');
  assert.match(await f.page.locator('#feedback').textContent(),/reload|inspection|inspect/i);
  assert.equal(await f.page.locator('#password').inputValue(),'');
  f.allowInspection();await f.page.locator('#reload').click();
  await f.page.waitForFunction(()=>document.querySelector('#feedback').textContent.startsWith('Retained view reloaded.'));
  assert.match(await f.page.locator('#pending').textContent(),/9 DEV/);
  assert.equal(await f.page.locator('#signed-controls').isVisible(),true);
  assert.deepEqual(f.calls.filter(c=>c.method==='POST').map(c=>c.path),['/api/prepare','/api/sign']);
  assert.deepEqual(f.errors,[]);
});
test('lost submission return inspects saved attempt and keeps resend unavailable',async t=>{
  const state=initial();signed(state);const f=await fixture(t,{state,lostSubmit:true});
  await f.page.locator('#submission-review').click();await f.page.locator('#dispatch-review').waitFor({state:'visible'});
  await f.page.locator('#send-check').check();await f.page.locator('#send').click();
  await f.page.waitForFunction(()=>!document.querySelector('#feedback').textContent.startsWith('Working'));
  assert.equal(f.calls.filter(c=>c.path==='/api/submit').length,1);
  assert.deepEqual(f.calls.filter(c=>c.method==='POST').map(c=>c.path),['/api/submission-review','/api/submit']);
  assert.deepEqual(f.calls.find(c=>c.path==='/api/submit').body,{request_id:RID,review_json:'{"decision_id":"'+DID+'"}',confirmation:'f'.repeat(64)});
  assert.equal(f.calls.filter(c=>c.path==='/api/state').length,2);
  assert.equal(await f.page.locator('#submission-review').isDisabled(),true);
  assert.equal(await f.page.locator('#send').isDisabled(),true);
  assert.match(await f.page.locator('#pending').textContent(),/9 DEV/);assert.deepEqual(f.errors,[]);
});

test('recorded attempt with unknown outcome explains collection without claiming payment',async t=>{
  const state=initial();signed(state);state.requests[0].delivery.attempt_recorded=true;
  state.requests[0].delivery.transport_observation='transport_unavailable';
  const f=await fixture(t,{state});
  assert.match(await f.page.locator('#progress-title').textContent(),/outcome.*unknown/i);
  assert.match(await f.page.locator('#progress-next').textContent(),/collect.*evidence/i);
  assert.equal(await f.page.locator('#submission-review').isDisabled(),true);
  assert.equal(await f.page.locator('#collect').isDisabled(),false);
  assert.match(await f.page.locator('#pending').textContent(),/9 DEV/);assert.deepEqual(f.errors,[]);
});
test('verified receipt awaits explicit wallet reconciliation',async t=>{
  const state=initial();signed(state);state.requests[0].delivery.attempt_recorded=true;
  state.requests[0].delivery.receipt_status='verified_historical_receipt';const f=await fixture(t,{state});
  assert.match(await f.page.locator('#progress-title').textContent(),/receipt.*verified/i);
  assert.match(await f.page.locator('#progress-next').textContent(),/reconcile/i);
  assert.equal(await f.page.locator('#reconcile').isDisabled(),false);
  assert.match(await f.page.locator('#pending').textContent(),/9 DEV/);assert.deepEqual(f.errors,[]);
});
test('history and unknown outcomes remain distinct when current trust is unavailable',async t=>{
  const state=initial();signed(state);state.current_evidence_available=false;state.wallet=null;state.ledger=null;
  state.requests[0].stage='recorded_historical';const f=await fixture(t,{state});
  assert.match(await f.page.locator('#progress-title').textContent(),/historical.*execution/i);
  assert.match(await f.page.locator('#progress-detail').textContent(),/current.*(authority|trust)/i);
  assert.equal(await f.page.locator('#prepare').isDisabled(),true);
  assert.equal(await f.page.locator('#submission-review').isDisabled(),true);
  assert.equal(await f.page.locator('#original-download').getAttribute('href'),'/api/original/'+RID);
  assert.match(await f.page.locator('#payment-progress li').nth(4).textContent(),/current.*(unavailable|unknown)/i);
  assert.match(await f.page.locator('#delivery-status').textContent(),/current.*(unavailable|unknown)/i);
  assert.doesNotMatch(await f.page.locator('#delivery-status').textContent(),/outcome unknown|original obligation retained/i);
  assert.deepEqual(f.errors,[]);
});
test('recovery progress renders on desktop and mobile without horizontal page overflow',async t=>{
  const state=initial();signed(state);state.requests[0].delivery.attempt_recorded=true;
  state.requests[0].delivery.transport_observation='transport_unavailable';const f=await fixture(t,{state});
  assert.equal(await f.page.locator('#payment-progress li').count(),5);
  for(const [name,width,height]of [['desktop',1280,900],['mobile',390,844]]){
    await f.page.setViewportSize({width,height});
    assert.equal(await f.page.evaluate(()=>document.documentElement.scrollWidth<=window.innerWidth),true);
    assert.equal(await f.page.locator('#progress-next').isVisible(),true);
    if(process.env.ONE_BROWSER_TEST_ARTIFACTS){const destination=path.join(process.env.ONE_BROWSER_TEST_ARTIFACTS,name+'-recovery.png');
      fs.mkdirSync(path.dirname(destination),{recursive:true});assert.equal(fs.existsSync(destination),false);
      await f.page.screenshot({path:destination,fullPage:true});}
  }
  assert.deepEqual(f.errors,[]);
});

test('ledger-reconciled execution does not invent a collected delivery receipt',async t=>{
  const state=initial();signed(state);state.requests[0].stage='recorded';
  state.wallet.pending_debit_units='0';state.requests[0].delivery.attempt_recorded=false;
  const f=await fixture(t,{state});
  assert.match(await f.page.locator('#progress-title').textContent(),/execution.*reconciled/i);
  assert.doesNotMatch(await f.page.locator('#payment-progress li').nth(3).textContent(),/verified at collection/i);
  assert.match(await f.page.locator('#progress-next').textContent(),/collect.*receipt/i);
  assert.equal(await f.page.locator('#retain').isDisabled(),true);
  assert.equal(await f.page.locator('#collect').isDisabled(),false);
  assert.equal(await f.page.locator('#submission-review').isDisabled(),true);
  assert.doesNotMatch(await f.page.locator('#delivery-status').textContent(),/outcome unknown/i);
  assert.deepEqual(f.errors,[]);
});


test('merchant invoice requires both terms and native debit consent',async t=>{
  const f=await fixture(t,{state:invoiceState()});
  assert.equal(await f.page.locator('#request-form').isVisible(),false);
  assert.match(await f.page.locator('#invoice-facts').textContent(),/https:\/\/merchant.example\/premium/);
  await f.page.locator('#prepare').click();await f.page.locator('#payment-review').waitFor({state:'visible'});
  assert.match(await f.page.locator('#terms-facts').textContent(),/https:\/\/merchant.example\/premium/);
  await f.page.locator('#sign-check').check();await f.page.locator('#password').fill('fixture-password-only');
  assert.equal(await f.page.locator('#sign').isDisabled(),true);
  await f.page.locator('#terms-check').check();assert.equal(await f.page.locator('#sign').isDisabled(),false);
  await f.page.locator('#sign').click();await f.page.waitForFunction(()=>document.querySelector('#feedback').textContent.startsWith('Original signed decision'));
  const sign=f.calls.find(c=>c.path==='/api/sign-invoice');assert.ok(sign);
  assert.equal(sign.body.terms_json,invoicePrepared({request_id:RID,role:'owner'}).terms_json);
  assert.equal(f.calls.filter(c=>c.path==='/api/sign').length,0);assert.deepEqual(f.errors,[]);
});
test('changing the signing role clears both merchant consent and native consent',async t=>{
  const f=await fixture(t,{state:invoiceState()});await f.page.locator('#prepare').click();
  await f.page.locator('#payment-review').waitFor({state:'visible'});
  await f.page.locator('#sign-check').check();await f.page.locator('#terms-check').check();
  await f.page.locator('#password').fill('fixture-password-only');await f.page.locator('#role').selectOption('raven');
  assert.equal(await f.page.locator('#terms-check').isChecked(),false);
  assert.equal(await f.page.locator('#sign-check').isChecked(),false);
  assert.equal(await f.page.locator('#password').inputValue(),'');assert.equal(await f.page.locator('#sign').isDisabled(),true);
  assert.equal(await f.page.locator('#payment-review').isVisible(),false);assert.deepEqual(f.errors,[]);
});
test('lost merchant signature return inspects once and never repeats either approval',async t=>{
  const f=await fixture(t,{state:invoiceState(),lostSign:true});await f.page.locator('#prepare').click();
  await f.page.locator('#payment-review').waitFor({state:'visible'});
  await f.page.locator('#sign-check').check();await f.page.locator('#terms-check').check();
  await f.page.locator('#password').fill('fixture-password-only');await f.page.locator('#sign').click();
  await f.page.waitForFunction(()=>!document.querySelector('#feedback').textContent.startsWith('Working'));
  assert.deepEqual(f.calls.filter(c=>c.method==='POST').map(c=>c.path),['/api/prepare','/api/sign-invoice']);
  assert.equal(f.calls.filter(c=>c.path==='/api/state').length,2);
  assert.equal(await f.page.locator('#password').inputValue(),'');
  assert.equal(await f.page.locator('#terms-check').isChecked(),false);
  assert.match(await f.page.locator('#pending').textContent(),/9 DEV/);assert.deepEqual(f.errors,[]);
});
test('unavailable inspection after merchant signing locks both consents',async t=>{
  const f=await fixture(t,{state:invoiceState(),lostSign:true,failInspection:true});
  await f.page.locator('#prepare').click();await f.page.locator('#payment-review').waitFor({state:'visible'});
  await f.page.locator('#sign-check').check();await f.page.locator('#terms-check').check();
  await f.page.locator('#password').fill('fixture-password-only');await f.page.locator('#sign').click();
  await f.page.waitForFunction(()=>!document.querySelector('#feedback').textContent.startsWith('Working'));
  assert.equal(await f.page.locator('#prepare').isDisabled(),true);assert.equal(await f.page.locator('#sign').isDisabled(),true);
  assert.equal(await f.page.locator('#terms-check').isChecked(),false);assert.equal(await f.page.locator('#pending').textContent(),'Unavailable');
  assert.equal(f.calls.filter(c=>c.path==='/api/sign-invoice').length,1);assert.deepEqual(f.errors,[]);
});
test('a late merchant review cannot restore consents after a role change',async t=>{
  const f=await fixture(t,{state:invoiceState(),delayPrepare:true});await f.page.locator('#prepare').click();await f.prepareSeen;
  assert.equal(await f.page.locator('#terms-check').isDisabled(),true);
  await f.page.evaluate(()=>{const role=document.querySelector('#role');role.value='raven';role.dispatchEvent(new Event('change'));});
  f.release();await f.page.waitForFunction(()=>!document.querySelector('#feedback').textContent.startsWith('Working'));
  assert.equal(await f.page.locator('#payment-review').isVisible(),false);assert.equal(await f.page.locator('#sign').isDisabled(),true);
  assert.deepEqual(f.errors,[]);
});
test('expired merchant invoice keeps recovery and collection but refuses new submission',async t=>{
  const state=invoiceState();signed(state);state.requests[0].request_open=false;
  const f=await fixture(t,{state});assert.equal(await f.page.locator('#submission-review').isDisabled(),true);
  assert.equal(await f.page.locator('#collect').isDisabled(),false);
  assert.equal(await f.page.locator('#original-download').getAttribute('href'),'/api/original/'+RID);
  assert.match(await f.page.locator('#progress-next').textContent(),/expired|original|evidence/i);assert.deepEqual(f.errors,[]);
});
