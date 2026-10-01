/* Chromium -> actual guarded private-wallet launcher -> four local CometBFT validators.
 * Only newly generated DEV workspaces. Existing pinned runtime and browser required.
 * Lost returns are injected AFTER route.fetch has completed the actual API action.
 */
const test=require('node:test'),assert=require('node:assert/strict');
const {spawn}=require('node:child_process'),readline=require('node:readline');
const crypto=require('node:crypto'),fs=require('node:fs'),path=require('node:path');
const {chromium}=require(process.env.ONE_BROWSER_TEST_DRIVER||'playwright-core');
const PASSWORD='fixture passphrase not for funds';
async function waitForLoopback(origin){const http=require('node:http'),limit=Date.now()+10000;
  while(true){try{const status=await new Promise((resolve,reject)=>{const r=http.get(origin+'/',response=>{response.resume();response.once('end',()=>resolve(response.statusCode));});r.once('error',reject);r.setTimeout(1000,()=>r.destroy(Error('readiness timeout')));});assert.equal(status,200);return;
  }catch(e){if(e.code!=='ECONNREFUSED'||Date.now()>=limit)throw e;await new Promise(r=>setTimeout(r,100));}}}

test('three merchant browser payments execute once on four actual local validators',async t=>{
  const root=process.env.ONE_BROWSER_SERVICE_ROOT,python=process.env.ONE_BROWSER_SERVICE_PYTHON,
    engine=process.env.ONE_MERCHANT_BROWSER_ENGINE,output=process.env.ONE_MERCHANT_BROWSER_OUTPUT,
    artifacts=process.env.ONE_BROWSER_TEST_ARTIFACTS;
  assert.ok(root&&python&&engine&&output&&artifacts,'explicit owned evidence and installed runtime paths required');
  assert.equal(fs.existsSync(artifacts),false);fs.mkdirSync(artifacts,{recursive:false});
  const child=spawn('wsl.exe',['--distribution','Ubuntu','--user','xnuonux','--cd',root,'--exec',python,
    '-B','tools/private-payments/tests/browser_comet_fixture.py',engine,output],{stdio:['pipe','pipe','pipe']});
  let exit=null,readyResolve,browser=null,context=null,workflowComplete=false;
  const ready=new Promise(r=>readyResolve=r),lines=[],stderr=[],calls=[];
  const closed=new Promise((resolve,reject)=>{child.once('error',reject);child.once('exit',code=>{exit=code;});child.once('close',code=>resolve(code));});
  child.stderr.on('data',x=>stderr.push(x.toString()));
  const stream=readline.createInterface({input:child.stdout});
  stream.on('line',x=>{const q=JSON.parse(x);lines.push(q);if(q.origin)readyResolve(q);});
  t.after(async()=>{
    const stopped=await Promise.allSettled([context?.close(),browser?.close()]);
    if(exit===null)child.stdin.end('stop\n');
    let timer;const code=await Promise.race([closed,new Promise((_,reject)=>timer=setTimeout(()=>reject(Error('owned validator cleanup timeout')),30000))]).finally(()=>clearTimeout(timer));
    const cleanupPassed=stopped.every(r=>r.status==='fulfilled')&&code===0&&stderr.join('')==='';
    const final=lines.at(-1),fixturePassed=final?.status==='passed'&&final?.payments===3&&final?.owned_processes_after_cleanup===0&&final?.source_unchanged===true;
    fs.writeFileSync(path.join(artifacts,'browser-result.json'),JSON.stringify({schema:1,
      passed:workflowComplete&&fixturePassed&&cleanupPassed,workflow_complete:workflowComplete,
      fixture_passed:fixturePassed,cleanup_passed:cleanupPassed,calls,fixture_return:final,
      scope:'actual guarded API, three DEV invoices and four local validators; two deliberate lost application returns; no public network/real funds'},null,2)+'\n');
    assert.equal(workflowComplete,true,'browser assertions did not complete');
    assert.equal(cleanupPassed,true,stderr.join(''));assert.equal(fixturePassed,true);
    t.diagnostic('owned browser, HTTP listener and all eight app/validator processes closed; three original payments replayed');
  });
  let timer;const fixture=await Promise.race([ready,closed.then(code=>{throw Error('fixture exited before ready: '+code+' '+stderr.join(''));}),new Promise((_,reject)=>timer=setTimeout(()=>reject(Error('owned native startup timeout')),90000))]).finally(()=>clearTimeout(timer));
  await waitForLoopback(fixture.origin);
  browser=await chromium.launch({headless:true,executablePath:process.env.ONE_BROWSER_TEST_EXECUTABLE});
  t.diagnostic('Chromium '+browser.version()+'; playwright-core '+require(path.join(process.env.ONE_BROWSER_TEST_DRIVER||'playwright-core','package.json')).version);
  context=await browser.newContext({viewport:{width:1280,height:900}});const page=await context.newPage();page.setDefaultTimeout(10000);
  const errors=[];page.on('pageerror',e=>errors.push(e.message));
  let lostSign=false,lostSubmit=false;
  await page.route('**/api/sign-invoice',async route=>{calls.push({path:'/api/sign-invoice',request_id:route.request().postDataJSON().request_id});
    if(!lostSign){lostSign=true;const response=await route.fetch({maxRetries:0,maxRedirects:0});assert.equal(response.status(),200);await route.abort('failed');}
    else await route.continue();});
  await page.route('**/api/submit',async route=>{const rid=route.request().postDataJSON().request_id;calls.push({path:'/api/submit',request_id:rid});
    if(rid===fixture.invoices[1].request_id&&!lostSubmit){lostSubmit=true;const response=await route.fetch({maxRetries:0,maxRedirects:0});assert.equal(response.status(),200);await route.abort('failed');}
    else await route.continue();});
  const response=await page.goto(fixture.origin+'/');assert.match(response.headers()['content-security-policy'],/default-src 'none'/);
  await page.waitForFunction(()=>document.querySelector('#feedback').textContent.startsWith('Ready.'));
  assert.equal(await page.locator('#request-form').isVisible(),false);
  for(const [i,invoice] of fixture.invoices.entries()){
    await page.locator('.request-item').filter({has:page.locator('b').filter({hasText:new RegExp('^'+invoice.amount+' DEV$')})}).click();
    assert.equal(await page.locator('#request-id').textContent(),invoice.request_id);
    await page.locator('#role').selectOption(invoice.role);await page.locator('#prepare').click();
    await page.locator('#payment-review').waitFor({state:'visible'});
    assert.match(await page.locator('#terms-facts').textContent(),new RegExp(invoice.resource_sha256));
    if(i===0){
      await page.screenshot({path:path.join(artifacts,'merchant-review-desktop.png'),fullPage:true});
      await page.setViewportSize({width:390,height:844});
      assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true);
      await page.screenshot({path:path.join(artifacts,'merchant-review-mobile.png'),fullPage:true});
      await page.setViewportSize({width:1280,height:900});
    }
    await page.locator('#password').fill(PASSWORD);await page.locator('#sign-check').check();
    assert.equal(await page.locator('#sign').isDisabled(),true);await page.locator('#terms-check').check();
    await page.locator('#sign').click();
    await page.waitForFunction(()=>document.querySelector('#progress-title').textContent==='Signed and reserved');
    assert.equal(await page.locator('#password').inputValue(),'');
    const original=await context.request.get(fixture.origin+'/api/original/'+invoice.request_id);assert.equal(original.status(),200);
    const wire=await original.body();assert.equal(crypto.createHash('sha256').update(wire).digest('hex').length,64);
    assert.match(JSON.parse(wire).body.op.invoice_commitment,/^[0-9a-f]{64}$/);
    await page.locator('#submission-review').click();await page.locator('#dispatch-review').waitFor({state:'visible'});
    await page.locator('#send-check').check();await page.locator('#send').click();
    await page.waitForFunction(()=>document.querySelector('#progress-title').textContent==='Payment outcome unknown');
    assert.equal(await page.locator('#submission-review').isDisabled(),true);
    for(let n=0;n<10;n++){
      await page.locator('#collect').click();await page.waitForFunction(()=>!document.querySelector('#feedback').textContent.startsWith('Working'));
      if(await page.locator('#progress-title').textContent()==='Receipt verified')break;
      await new Promise(r=>setTimeout(r,1000));
    }
    assert.equal(await page.locator('#progress-title').textContent(),'Receipt verified');
    assert.equal(await page.locator('#pending').textContent(),String(Number(invoice.amount)+2)+' DEV');
    await page.locator('#reconcile').click();await page.waitForFunction(()=>document.querySelector('#progress-title').textContent==='Execution reconciled');
    assert.equal(await page.locator('#pending').textContent(),'0 DEV');
    await page.locator('#retain').click();await page.waitForFunction(()=>document.querySelector('#feedback').textContent.startsWith('Verified capsule retained'));
    const capsule=await context.request.get(fixture.origin+await page.locator('#capsule-download').getAttribute('href'));
    assert.equal(capsule.status(),200);assert.ok((await capsule.body()).length>100);
    assert.equal(await page.locator('#submission-review').isDisabled(),true);
    const recovered=await context.request.get(fixture.origin+'/api/original/'+invoice.request_id);assert.deepEqual(await recovered.body(),wire);
  }
  assert.equal(await page.locator('#balance').textContent(),'957 DEV');
  assert.equal(calls.filter(c=>c.path==='/api/sign-invoice').length,3);
  assert.equal(calls.filter(c=>c.path==='/api/submit').length,3);
  assert.equal(lostSign&&lostSubmit,true);assert.deepEqual(errors,[]);workflowComplete=true;
});
