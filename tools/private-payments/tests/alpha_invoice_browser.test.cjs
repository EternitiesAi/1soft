/* Chromium -> original durable alpha after a real hour -> four local CometBFT validators.
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

async function downloadHistory(page,fixture,child,awaitAudit,stage){
  assert.equal(await page.locator('#backup-download').isDisabled(),true);
  await page.locator('#backup-passphrase').fill('fixture passphrase not for funds');
  await page.locator('#backup-repeat').fill('fixture passphrase not for funds');
  await page.locator('#backup-scope').check();
  const completed=page.waitForEvent('download');
  await page.locator('#backup-download').click();
  const download=await completed;
  assert.equal(await download.failure(),null);
  assert.match(download.suggestedFilename(),/^1soft-/);
  assert.equal(path.basename(download.suggestedFilename()),download.suggestedFilename());
  const filename=stage+'.backup';
  await download.saveAs(path.join(fixture.download_dir_windows,filename));
  assert.equal(await page.locator('#backup-passphrase').inputValue(),'');
  assert.equal(await page.locator('#backup-repeat').inputValue(),'');
  const audited=awaitAudit(stage);
  child.stdin.write(JSON.stringify({operation:'audit-backup',filename,stage})+'\n');
  const result=await audited;
  assert.equal(result.passed,true);assert.equal(result.backup_format_version,1);
  assert.equal(result.all_seven_tables_exact,true);assert.equal(result.source_logical_rows_unchanged,true);
  assert.equal(result.spending_authority,false);assert.equal(result.keys_unlocked,false);
  assert.equal(result.signing_or_submission_performed,false);
  if(stage==='signed-pending')assert.ok(BigInt(result.pending_debit_units)>0n);
  else assert.equal(result.pending_debit_units,'0');
  return result;
}

test('durable payer invoices execute once after a real hour on four original local validators',async t=>{
  const root=process.env.ONE_BROWSER_SERVICE_ROOT,python=process.env.ONE_BROWSER_SERVICE_PYTHON,
    engine=process.env.ONE_MERCHANT_BROWSER_ENGINE,output=process.env.ONE_MERCHANT_BROWSER_OUTPUT,
    artifacts=process.env.ONE_BROWSER_TEST_ARTIFACTS;
  assert.ok(root&&python&&engine&&output&&artifacts,'explicit owned evidence and installed runtime paths required');
  assert.equal(fs.existsSync(artifacts),false);fs.mkdirSync(artifacts,{recursive:false});
  const child=spawn('wsl.exe',['--distribution','Ubuntu','--user','xnuonux','--cd',root,'--exec',python,
    '-B','tools/private-payments/tests/alpha_invoice_browser_fixture.py',engine,output],{stdio:['pipe','pipe','pipe']});
  let exit=null,readyResolve,browser=null,context=null,workflowComplete=false;
  const backupAudits=[],capsuleAudits=[],auditWaiters=new Map();
  function awaitAudit(stage){return new Promise((resolve,reject)=>{const timer=setTimeout(()=>reject(Error('owned download audit timed out')),120000);auditWaiters.set(stage,v=>{clearTimeout(timer);resolve(v);});});}
  const ready=new Promise(r=>readyResolve=r),lines=[],stderr=[],calls=[];
  const closed=new Promise((resolve,reject)=>{child.once('error',reject);child.once('exit',code=>{exit=code;});child.once('close',code=>resolve(code));});
  child.stderr.on('data',x=>stderr.push(x.toString()));
  const stream=readline.createInterface({input:child.stdout});
  stream.on('line',x=>{const q=JSON.parse(x);lines.push(q);if(q.origin)readyResolve(q);if(q.backup_audit||q.capsule_audit){const a=q.backup_audit||q.capsule_audit;(q.backup_audit?backupAudits:capsuleAudits).push(a);const receive=auditWaiters.get(a.stage);assert.ok(receive);auditWaiters.delete(a.stage);receive(a);}});
  t.after(async()=>{
    const stopped=await Promise.allSettled([context?.close(),browser?.close()]);
    if(exit===null)child.stdin.end('stop\n');
    let timer;const code=await Promise.race([closed,new Promise((_,reject)=>timer=setTimeout(()=>reject(Error('owned validator cleanup timeout')),30000))]).finally(()=>clearTimeout(timer));
    const cleanupPassed=stopped.every(r=>r.status==='fulfilled')&&code===0&&stderr.join('')==='';
    const final=lines.at(-1),fixturePassed=final?.status==='passed'&&final?.payments===3&&final?.owned_processes_after_cleanup===0&&final?.source_unchanged===true;
    fs.writeFileSync(path.join(artifacts,'browser-result.json'),JSON.stringify({schema:1,
      passed:workflowComplete&&fixturePassed&&cleanupPassed,workflow_complete:workflowComplete,
      fixture_passed:fixturePassed,cleanup_passed:cleanupPassed,calls,backup_audits:backupAudits,capsule_audits:capsuleAudits,fixture_return:final,
      scope:'one original real-hour alpha, actual guarded API, three DEV invoices and four local validators; two deliberate lost returns; payer-only, no merchant fulfillment'},null,2)+'\n');
    assert.equal(workflowComplete,true,'browser assertions did not complete');
    assert.equal(cleanupPassed,true,stderr.join(''));assert.equal(fixturePassed,true);
    t.diagnostic('owned browser, HTTP listener and all eight app/validator processes closed; three original payments replayed');
  });
  let timer;const fixture=await Promise.race([ready,closed.then(code=>{throw Error('fixture exited before ready: '+code+' '+stderr.join(''));}),new Promise((_,reject)=>timer=setTimeout(()=>reject(Error('owned native startup timeout')),4500000))]).finally(()=>clearTimeout(timer));
  await waitForLoopback(fixture.origin);
  browser=await chromium.launch({headless:true,executablePath:process.env.ONE_BROWSER_TEST_EXECUTABLE});
  t.diagnostic('Chromium '+browser.version()+'; playwright-core '+require(path.join(process.env.ONE_BROWSER_TEST_DRIVER||'playwright-core','package.json')).version);
  context=await browser.newContext({viewport:{width:1280,height:900},acceptDownloads:true});const page=await context.newPage();page.setDefaultTimeout(10000);
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
    if(i===0)await downloadHistory(page,fixture,child,awaitAudit,'signed-pending');
    assert.equal(await page.locator('#submission-review').isDisabled(),true);
    let collectedEntry=null,collectedState=null;
    for(let n=0;n<10;n++){
      await page.locator('#collect').click();await page.waitForFunction(()=>!document.querySelector('#feedback').textContent.startsWith('Working'));
      const response=await context.request.get(fixture.origin+'/api/state');assert.equal(response.status(),200);
      collectedState=await response.json();collectedEntry=collectedState.requests.find(e=>e.request_id===invoice.request_id);
      if(collectedEntry?.delivery?.receipt_status==='verified_historical_receipt')break;
      await new Promise(r=>setTimeout(r,1000));
    }
    assert.equal(collectedEntry.delivery.receipt_status,'verified_historical_receipt');
    assert.equal(collectedState.current_evidence_available,true);
    assert.equal(collectedState.wallet_current,false);assert.equal(collectedState.signing_ready,false);
    assert.equal(await page.locator('#progress-title').textContent(),'Wallet needs current verification');
    assert.equal(await page.locator('#reconcile').isEnabled(),true);
    assert.equal(collectedState.wallet.pending_debit_units,String(BigInt(invoice.amount)+2n));
    assert.equal(await page.locator('#pending').textContent(),collectedState.wallet.pending_debit_units+' DEV · saved obligations');
    await page.locator('#reconcile').click();await page.waitForFunction(()=>document.querySelector('#progress-title').textContent==='Execution reconciled');
    const reconciled=await (await context.request.get(fixture.origin+'/api/state')).json();
    assert.equal(reconciled.wallet_current,true);assert.equal(reconciled.signing_ready,true);
    assert.equal(reconciled.wallet.pending_debit_units,'0');
    assert.equal(await page.locator('#pending').textContent(),'0 DEV');
    await page.locator('#retain').click();await page.waitForFunction(()=>document.querySelector('#feedback').textContent.startsWith('Verified capsule retained'));
    const capsule=await context.request.get(fixture.origin+await page.locator('#capsule-download').getAttribute('href'));
    assert.equal(capsule.status(),200);const capsuleBytes=await capsule.body();assert.ok(capsuleBytes.length>100);
    const filename=invoice.role+'.capsule';fs.writeFileSync(path.join(fixture.download_dir_windows,filename),capsuleBytes,{flag:'wx'});
    const audited=awaitAudit('capsule-'+invoice.role);
    child.stdin.write(JSON.stringify({operation:'audit-capsule',filename,request_id:invoice.request_id})+'\n');
    const audit=await audited;assert.equal(audit.passed,true);assert.equal(audit.retained_packet_exact,true);
    assert.equal(audit.native_execution_reverified,true);assert.equal(audit.current_spending_authority,false);
    assert.equal(audit.packet_sha256,crypto.createHash('sha256').update(capsuleBytes).digest('hex'));
    assert.equal(audit.wire_sha256,crypto.createHash('sha256').update(wire).digest('hex'));
    assert.equal(audit.resource_sha256,invoice.resource_sha256);
    assert.equal(await page.locator('#submission-review').isDisabled(),true);
    const recovered=await context.request.get(fixture.origin+'/api/original/'+invoice.request_id);assert.deepEqual(await recovered.body(),wire);
  }
  await downloadHistory(page,fixture,child,awaitAudit,'receipt-complete');
  assert.equal(capsuleAudits.length,3);assert.equal(backupAudits.at(-1).recovered_originals.length,3);assert.equal(backupAudits.at(-1).retained_delivery_receipts,3);
  for(const [name,width,height]of [['desktop',1280,900],['mobile',390,844]]){await page.setViewportSize({width,height});assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true);await page.screenshot({path:path.join(artifacts,'history-'+name+'.png'),fullPage:true});}
  await page.setViewportSize({width:1280,height:900});
  assert.equal(await page.locator('#balance').textContent(),'957 DEV');
  assert.equal(calls.filter(c=>c.path==='/api/sign-invoice').length,3);
  assert.equal(calls.filter(c=>c.path==='/api/submit').length,3);
  assert.equal(lostSign&&lostSubmit,true);assert.deepEqual(errors,[]);
  child.stdin.write('stop\n');
  assert.deepEqual(errors,[]);workflowComplete=true;
});
