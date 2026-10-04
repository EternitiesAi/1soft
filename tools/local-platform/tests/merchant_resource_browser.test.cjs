/* Actual Chromium with key-free controlled HTTP replies. No consensus/custody claim. */
const test=require('node:test'),assert=require('node:assert/strict'),http=require('node:http');
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const {chromium}=require(process.env.ONE_BROWSER_TEST_DRIVER||'playwright-core');
const H=n=>String(n).repeat(64),RID=H(1),PAYER='lab_'+H(8),RECIPIENT='lab_'+H(9),bytes=Buffer.from('Public original purchase\n');
const sha=x=>crypto.createHash('sha256').update(x).digest('hex');
function state(){return {schema:1,asset:'DEV',current_evidence_available:true,wallet_current:false,signing_ready:false,
  payment_mode:'committed_merchant_invoices',merchant_fulfillment_available:true,
  wallet:{revision:1,state_height:4,pending_debit_units:'9',accounts:[{id:PAYER,recorded_balance:'994',uncommitted_units:'985',reservation_deficit_units:'0'}],
    budgets:[{cap:'100',spent:'0',pending_debit_units:'9',uncommitted_units:'91'}],decisions:[]},
  ledger:{checkpoint:{state_height:5,evidence_id:H(8),trust_expires_ns:'4102444800000000000'},grants:[{recipients:[RECIPIENT]}],payments:[],registry:{active:[]}},
  requests:[{request_id:RID,request:{recipient:RECIPIENT,units:'7',created_ns:'1700000000000000001',expires_ns:'4102444800000000000'},
    decision_id:H(2),stage:'signed_reserved',request_open:true,capsule_ids:[H(6)],
    delivery:{attempt_recorded:true,transport_observation:'accepted',receipt_status:'verified_historical_receipt'},
    invoice:{merchant_origin:'http://127.0.0.1:1',resource_url:'http://127.0.0.1:1/premium',resource_sha256:sha(bytes),
      invoice_commitment:H(7),quote_sha256:H(3),created_ns:'1700000000000000001',expires_ns:'4102444800000000000'},
    merchant_delivery:{configured:true,enrolled:true,consumption_retained:false,retrieval_available:true,resource_received_by_browser:false,
      fulfilled_ns:null,quote_sha256:H(3),resource_sha256:sha(bytes),wire_sha256:H(4),capsule_sha256:H(5),native_txid:H(7),reference_id:H(6)}}],
  roles:{owner:{payer:PAYER,grant_id:''},raven:{payer:PAYER,grant_id:'raven'},atlas:{payer:PAYER,grant_id:'atlas'}},
  genesis_sha256:H(8),policy_id:H(9),limits:{rpc_height:64,offline_height:512}};}
function review(s){const e=s.requests[0],d=e.merchant_delivery;
  const summary={format:'1soft/alpha-browser-resource-review/v1',request_id:RID,decision_id:e.decision_id,
    quote_sha256:e.invoice.quote_sha256,merchant_origin:e.invoice.merchant_origin,resource_url:e.invoice.resource_url,
    resource_sha256:e.invoice.resource_sha256,payer:PAYER,grant_id:'',wire_sha256:d.wire_sha256,capsule_sha256:d.capsule_sha256,
    reference_id:d.reference_id,native_txid:d.native_txid,genesis_sha256:s.genesis_sha256,policy_id:s.policy_id,
    session_context_sha256:H(1),fulfilled_ns:d.fulfilled_ns,full_public_ledger_disclosed:true,signing_or_submission_performed:false};
  const review_json=JSON.stringify(Object.fromEntries(Object.keys(summary).sort().map(k=>[k,summary[k]])));
  return {request_id:RID,summary,review_json,confirmation:sha(review_json)};}
async function fixture(t,{mutate=null,lost=false,corrupt=false,delay=false,delayReply=false,failInspection=false,proofFormat='alpha-v1'}={}){
  const s=state(),calls=[],downloads=[],errors=[];let release=null,seenResolve;const seen=new Promise(r=>seenResolve=r);
  const server=http.createServer(async(req,res)=>{try{
    const json=(status,q)=>{res.writeHead(status,{'Content-Type':'application/json','Cache-Control':'no-store'});res.end(JSON.stringify(q));};
    if(['/','/wallet.js','/wallet.css'].includes(req.url)){
      const name=req.url==='/'?'index.html':req.url.slice(1);res.writeHead(200,{'Content-Type':name.endsWith('.html')?'text/html':name.endsWith('.js')?'text/javascript':'text/css'});
      res.end(fs.readFileSync(path.join(__dirname,'../web',name)));return;}
    if(req.url==='/api/session'){json(200,{csrf:'key-free-fixture'});return;}
    if(req.url==='/api/state'){calls.push(req.url);if(failInspection&&calls.includes('/api/merchant-retrieve'))json(503,{message:'Unavailable'});else json(200,s);return;}
    if(req.url==='/api/merchant-review'){
      calls.push(req.url);const q=review(s);if(mutate)mutate(q);if(delay){release=()=>json(200,q);seenResolve();}else json(200,q);return;}
    if(req.url==='/api/merchant-retrieve'||req.url==='/api/merchant-proof/'+RID){
      const proof=req.method==='GET';calls.push(req.url);
      if(!proof){let raw='';for await(const chunk of req)raw+=chunk;const q=JSON.parse(raw),expected=review(s);
        assert.deepEqual(q,{request_id:RID,review_json:expected.review_json,confirmation:expected.confirmation});
        s.requests[0].merchant_delivery.consumption_retained=true;s.requests[0].merchant_delivery.fulfilled_ns='1700000000000000001';}
      let body=proof?Buffer.from('{"public":"key-free proof fixture"}'):bytes;
      const headers={'Content-Type':'application/octet-stream','Content-Length':String(body.length),'X-1soft-Fulfilled-Ns':'1700000000000000001'};
      for(const key of ['request_id','quote_sha256','resource_sha256','wire_sha256','capsule_sha256','native_txid'])headers['X-1soft-'+key.replaceAll('_','-')]=key==='request_id'?RID:s.requests[0].merchant_delivery[key];
      if(proof){headers['X-1soft-Proof-Format']=proofFormat;headers['X-1soft-Proof-Sha256']=sha(body);}
      if(!proof&&lost){lost=false;headers['Content-Length']='1000';res.writeHead(200,headers);res.flushHeaders();res.write(bytes);setImmediate(()=>res.destroy());return;}
      if(!proof&&corrupt)body=Buffer.alloc(body.length,88);
      const finish=()=>{res.writeHead(200,headers);res.end(body);};
      if(delayReply){release=finish;seenResolve();}else finish();return;
    }
    json(404,{message:'Unavailable'});
  }catch{res.destroy();}});
  let browser,context;
  t.after(async()=>{if(release){release();release=null;}await context?.close();await browser?.close();server.closeAllConnections();if(server.listening)await new Promise(r=>server.close(r));assert.deepEqual(errors,[]);});
  await new Promise(r=>server.listen(0,'127.0.0.1',r));
  browser=await chromium.launch({headless:true,executablePath:process.env.ONE_BROWSER_TEST_EXECUTABLE});
  context=await browser.newContext({viewport:{width:1280,height:900},acceptDownloads:true});const page=await context.newPage();page.setDefaultTimeout(8000);
  page.on('pageerror',e=>errors.push(e.message));page.on('download',d=>downloads.push(d));
  await page.goto('http://127.0.0.1:'+server.address().port+'/');await page.waitForFunction(()=>document.querySelector('#feedback').textContent.startsWith('Ready.'));
  await page.locator('.request-item').click();
  return {page,s,calls,downloads,seen,release:()=>{assert.ok(release);release();release=null;}};
}
async function consent(page){await page.locator('#purchase-review').click();await page.locator('#purchase-confirmation').waitFor({state:'visible'});
  assert.equal(await page.locator('#purchase-retrieve').isDisabled(),true);await page.locator('#purchase-share').check();}
async function settled(page){await page.waitForFunction(()=>!document.querySelector('#feedback').textContent.startsWith('Working'));}
test('explicit receipt consent yields verified bytes and a separately reviewed proof download',async t=>{
  const f=await fixture(t);await consent(f.page);const resource=f.page.waitForEvent('download');await f.page.locator('#purchase-retrieve').click();
  const d=await resource;assert.equal(await d.failure(),null);assert.equal(fs.readFileSync(await d.path()).toString(),bytes.toString());await settled(f.page);
  assert.match(await f.page.locator('#purchase-status').textContent(),/digest-verified/);assert.equal(f.s.wallet.pending_debit_units,'9');
  await consent(f.page);const proof=f.page.waitForEvent('download');await f.page.locator('#purchase-proof').click();assert.equal(await (await proof).failure(),null);
  for(const width of [1280,390]){await f.page.setViewportSize({width,height:844});assert.equal(await f.page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true);}
});
test('lost return retains consumption and requires one explicit reviewed retry',async t=>{
  const f=await fixture(t,{lost:true});await consent(f.page);await f.page.locator('#purchase-retrieve').click();await settled(f.page);
  assert.equal(f.downloads.length,0);assert.equal(f.calls.filter(x=>x==='/api/merchant-retrieve').length,1);
  assert.match(await f.page.locator('#purchase-status').textContent(),/retains the original consumption/);
  await consent(f.page);const downloaded=f.page.waitForEvent('download');await f.page.locator('#purchase-retrieve').click();await downloaded;
  assert.equal(f.calls.filter(x=>x==='/api/merchant-retrieve').length,2);assert.equal(f.s.wallet.pending_debit_units,'9');
});
for(const key of ['grant_id','payer','reference_id'])test('mismatched displayed '+key+' cannot enable retrieval',async t=>{
  const f=await fixture(t,{mutate:q=>{q.summary[key]='different';}});await f.page.locator('#purchase-review').click();await settled(f.page);
  assert.equal(await f.page.locator('#purchase-confirmation').isVisible(),false);assert.equal(f.calls.includes('/api/merchant-retrieve'),false);
});
test('a changed exact review with old confirmation is refused',async t=>{
  const f=await fixture(t,{mutate:q=>{q.summary.grant_id='changed';q.review_json=JSON.stringify(q.summary);}});
  await f.page.locator('#purchase-review').click();await settled(f.page);assert.equal(await f.page.locator('#purchase-confirmation').isVisible(),false);
});
test('late review cannot survive a role change',async t=>{
  const f=await fixture(t,{delay:true});await f.page.locator('#purchase-review').click();await f.seen;
  await f.page.evaluate(()=>{const e=document.querySelector('#role');e.value='raven';e.dispatchEvent(new Event('change'));});f.release();await settled(f.page);
  assert.equal(await f.page.locator('#purchase-confirmation').isVisible(),false);assert.equal(f.calls.includes('/api/merchant-retrieve'),false);
});
test('corrupted resource bytes offer no download',async t=>{
  const f=await fixture(t,{corrupt:true});await consent(f.page);await f.page.locator('#purchase-retrieve').click();await settled(f.page);
  assert.equal(f.downloads.length,0);assert.equal(f.s.requests[0].merchant_delivery.consumption_retained,true);
});
test('failed inspection after a lost return disables further retrieval',async t=>{
  const f=await fixture(t,{lost:true,failInspection:true});await consent(f.page);await f.page.locator('#purchase-retrieve').click();await settled(f.page);
  assert.equal(await f.page.locator('#purchase-review').isDisabled(),true);assert.equal(f.downloads.length,0);
});
test('unsupported proof format offers no download',async t=>{
  const f=await fixture(t,{proofFormat:'another-format'});f.s.requests[0].merchant_delivery.consumption_retained=true;
  f.s.requests[0].merchant_delivery.fulfilled_ns='1700000000000000001';await f.page.locator('#reload').click();await settled(f.page);
  await consent(f.page);await f.page.locator('#purchase-proof').click();await settled(f.page);assert.equal(f.downloads.length,0);
});
for(const kind of ['resource','proof'])test('late '+kind+' reply offers no download after role change',async t=>{
  const f=await fixture(t,{delayReply:true});
  if(kind==='proof'){f.s.requests[0].merchant_delivery.consumption_retained=true;f.s.requests[0].merchant_delivery.fulfilled_ns='1700000000000000001';await f.page.locator('#reload').click();await settled(f.page);}
  await consent(f.page);await f.page.locator(kind==='proof'?'#purchase-proof':'#purchase-retrieve').click();await f.seen;
  await f.page.evaluate(()=>{const e=document.querySelector('#role');e.value='raven';e.dispatchEvent(new Event('change'));});f.release();await settled(f.page);
  assert.equal(f.downloads.length,0);assert.equal(await f.page.locator('#purchase-confirmation').isVisible(),false);
});
