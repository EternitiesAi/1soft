/* Actual Chromium -> guarded wallet bridge -> actual merchant HTTP, four validators.
 * Fresh local DEV home only; existing cached runtimes. No funds, installs or deployment.
 */
const test=require('node:test'),assert=require('node:assert/strict'),{spawn}=require('node:child_process');
const readline=require('node:readline'),fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const {chromium}=require(process.env.ONE_BROWSER_TEST_DRIVER||'playwright-core');
const PASSWORD='fixture passphrase not for funds',sha=x=>crypto.createHash('sha256').update(x).digest('hex');
async function settled(page){await page.waitForFunction(()=>!document.querySelector('#feedback').textContent.startsWith('Working'));}
async function select(page,invoice){await page.locator('.request-item').filter({has:page.locator('b').filter({hasText:new RegExp('^'+invoice.amount+' DEV$')})}).click();
  assert.equal(await page.locator('#request-id').textContent(),invoice.request_id);}
async function consent(page){await page.locator('#purchase-review').click();await page.locator('#purchase-confirmation').waitFor({state:'visible'});
  assert.equal(await page.locator('#purchase-retrieve').isDisabled(),true);await page.locator('#purchase-share').check();}
async function saveDownload(page,fixture,invoice,phase,kind){
  if(kind==='proof')await consent(page);
  const offered=page.waitForEvent('download');await page.locator(kind==='resource'?'#purchase-retrieve':'#purchase-proof').click();
  const d=await offered;assert.equal(await d.failure(),null);assert.equal(path.basename(d.suggestedFilename()),d.suggestedFilename());
  assert.match(d.suggestedFilename(),kind==='resource'?/^1soft-purchase-[0-9a-f]{64}\.bin$/:/^1soft-merchant-proof-[0-9a-f]{64}\.json$/);
  const target=path.join(fixture.download_dir_windows,invoice.role+'-'+phase+'.'+kind);assert.equal(fs.existsSync(target),false);await d.saveAs(target);await settled(page);
  if(kind==='resource')assert.equal(sha(fs.readFileSync(target)),invoice.resource_sha256);
  return {kind,phase,role:invoice.role,sha256:sha(fs.readFileSync(target)),bytes:fs.statSync(target).size};
}
test('three real browser payments retrieve original resources with a pending hold, lost return and cold listener reopen',async t=>{
  const root=process.env.ONE_BROWSER_SERVICE_ROOT,python=process.env.ONE_BROWSER_SERVICE_PYTHON,
    engine=process.env.ONE_MERCHANT_BROWSER_ENGINE,output=process.env.ONE_MERCHANT_BROWSER_OUTPUT,artifacts=process.env.ONE_BROWSER_TEST_ARTIFACTS;
  assert.ok(root&&python&&engine&&output&&artifacts,'explicit owned source/runtime/evidence required');assert.equal(fs.existsSync(artifacts),false);fs.mkdirSync(artifacts);
  const child=spawn('wsl.exe',['--distribution','Ubuntu','--user','xnuonux','--cd',root,'--exec',python,
    '-B','tools/private-payments/tests/alpha_resource_browser_fixture.py',engine,output],{stdio:['pipe','pipe','pipe']});
  let exit=null,browser=null,context=null,workflowComplete=false,readyResolve,readyReject;
  const lines=[],stderr=[],calls=[],downloads=[],waiters=new Map(),errors=[];
  const ready=new Promise((r,j)=>{readyResolve=r;readyReject=j;});
  const closed=new Promise((resolve,reject)=>{child.once('error',reject);child.once('exit',code=>exit=code);child.once('close',resolve);});
  child.stderr.on('data',x=>stderr.push(x.toString()));
  const stream=readline.createInterface({input:child.stdout});
  stream.on('line',x=>{try{const q=JSON.parse(x);lines.push(q);
    if(q.ready&&!q.reply)readyResolve(q.ready);
    if(q.reply){const key=q.reply+':'+(q.request_id||'')+':'+(q.phase||'');const receive=waiters.get(key);assert.ok(receive,'unexpected fixture reply');waiters.delete(key);receive(q);}
  }catch(e){readyReject(e);}});
  function command(q){const key=q.operation+':'+(q.request_id||'')+':'+(q.phase||'');assert.equal(waiters.has(key),false);
    return new Promise((resolve,reject)=>{const timer=setTimeout(()=>{waiters.delete(key);reject(Error('fixture control deadline exceeded: '+q.operation));},150000);
      waiters.set(key,v=>{clearTimeout(timer);resolve(v);});child.stdin.write(JSON.stringify(q)+'\n');});}
  t.after(async()=>{
    const stopped=await Promise.allSettled([context?.close(),browser?.close()]);if(exit===null)child.stdin.end('stop\n');
    let timer;const code=await Promise.race([closed,new Promise((_,reject)=>timer=setTimeout(()=>reject(Error('owned fixture cleanup deadline exceeded')),90000))]).finally(()=>clearTimeout(timer));
    const final=lines.at(-1),fixturePassed=code===0&&final?.status==='passed'&&final.payments===3&&final.owned_processes_after_cleanup===0&&final.source_unchanged===true&&final.cleanup_errors.length===0;
    const cleanupPassed=stopped.every(r=>r.status==='fulfilled')&&stderr.join('')==='';
    fs.writeFileSync(path.join(artifacts,'browser-result.json'),JSON.stringify({schema:1,passed:workflowComplete&&fixturePassed&&cleanupPassed,
      workflow_complete:workflowComplete,fixture_passed:fixturePassed,cleanup_passed:cleanupPassed,calls,downloads,fixture_return:final,errors,
      scope:'short actual browser, guarded wallet bridge and real fixed loopback merchant HTTP; three original DEV payments/four validators; lost return and cold same-home listeners; no real-hour, public service or privacy qualification'},null,2)+'\n');
    fs.writeFileSync(path.join(artifacts,'fixture-ipc.jsonl'),lines.map(q=>JSON.stringify(q)).join('\n')+'\n');
    fs.writeFileSync(path.join(artifacts,'fixture.stderr.log'),stderr.join(''));
    assert.equal(workflowComplete,true);assert.equal(fixturePassed,true);assert.equal(cleanupPassed,true);assert.deepEqual(errors,[]);
  });
  let timer;let fixture=await Promise.race([ready,closed.then(code=>{throw Error('fixture exited before ready: '+code);}),new Promise((_,reject)=>timer=setTimeout(()=>reject(Error('native startup deadline exceeded')),240000))]).finally(()=>clearTimeout(timer));
  browser=await chromium.launch({headless:true,executablePath:process.env.ONE_BROWSER_TEST_EXECUTABLE});
  t.diagnostic('Chromium '+browser.version()+'; playwright-core '+require(path.join(process.env.ONE_BROWSER_TEST_DRIVER||'playwright-core','package.json')).version);
  context=await browser.newContext({viewport:{width:1280,height:900},acceptDownloads:true});const page=await context.newPage();page.setDefaultTimeout(20000);
  page.on('pageerror',e=>errors.push(e.message));let lost=false,offered=0;page.on('download',()=>offered++);
  for(const endpoint of ['sign-invoice','submit'])await page.route('**/api/'+endpoint,async route=>{
    calls.push({path:'/api/'+endpoint,request_id:route.request().postDataJSON().request_id});await route.continue();});
  await page.route('**/api/merchant-retrieve',async route=>{
    const rid=route.request().postDataJSON().request_id;calls.push({path:'/api/merchant-retrieve',request_id:rid,generation:fixture.generation});
    if(!lost&&rid===fixture.invoices[0].request_id){lost=true;const response=await route.fetch({maxRetries:0,maxRedirects:0});assert.equal(response.status(),200);
      assert.equal(sha(await response.body()),fixture.invoices[0].resource_sha256);await route.abort('failed');}else await route.continue();});
  const response=await page.goto(fixture.origin+'/');assert.match(response.headers()['content-security-policy'],/connect-src 'self'/);
  await page.waitForFunction(()=>document.querySelector('#feedback').textContent.startsWith('Ready.'));
  for(const [i,invoice] of fixture.invoices.entries()){
    await select(page,invoice);await page.locator('#role').selectOption(invoice.role);await page.locator('#prepare').click();await page.locator('#payment-review').waitFor({state:'visible'});
    assert.match(await page.locator('#terms-facts').textContent(),new RegExp(invoice.resource_sha256));
    await page.locator('#password').fill(PASSWORD);await page.locator('#sign-check').check();assert.equal(await page.locator('#sign').isDisabled(),true);await page.locator('#terms-check').check();await page.locator('#sign').click();
    await page.waitForFunction(()=>document.querySelector('#progress-title').textContent==='Signed and reserved');assert.equal(await page.locator('#password').inputValue(),'');
    await page.locator('#submission-review').click();await page.locator('#dispatch-review').waitFor({state:'visible'});await page.locator('#send-check').check();await page.locator('#send').click();await settled(page);
    let state,entry;
    for(let n=0;n<15;n++){
      await page.locator('#collect').click();await settled(page);state=await (await context.request.get(fixture.origin+'/api/state')).json();entry=state.requests.find(e=>e.request_id===invoice.request_id);
      if(entry.delivery.receipt_status==='verified_historical_receipt')break;await new Promise(r=>setTimeout(r,1000));}
    assert.equal(entry.delivery.receipt_status,'verified_historical_receipt');assert.equal(state.wallet.pending_debit_units,String(BigInt(invoice.amount)+2n));
    await page.locator('#retain').click();await settled(page);assert.equal(await page.locator('#purchase-review').isDisabled(),true);
    const enrolled=await command({operation:'operator-enroll',request_id:invoice.request_id});assert.equal(enrolled.passed,true);
    await page.locator('#reload').click();await settled(page);await consent(page);
    if(i===0){
      await page.locator('#purchase-retrieve').click();await settled(page);assert.equal(offered,0);
      assert.equal(calls.filter(c=>c.path==='/api/merchant-retrieve').length,1);assert.match(await page.locator('#purchase-status').textContent(),/retains the original consumption/);
      assert.equal((await command({operation:'inspect-retained',request_id:invoice.request_id})).passed,true);await consent(page);
      await page.screenshot({path:path.join(artifacts,'purchase-consent-desktop.png'),fullPage:true});await page.setViewportSize({width:390,height:844});
      assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true);await page.screenshot({path:path.join(artifacts,'purchase-consent-mobile.png'),fullPage:true});await page.setViewportSize({width:1280,height:900});
    }
    downloads.push(await saveDownload(page,fixture,invoice,'pending','resource'));assert.match(await page.locator('#purchase-status').textContent(),/digest-verified/);
    downloads.push(await saveDownload(page,fixture,invoice,'pending','proof'));
    const audit=await command({operation:'audit-downloads',request_id:invoice.request_id,phase:'pending'});assert.equal(audit.passed,true);assert.equal(audit.financial_rows_unchanged,true);assert.equal(audit.pending_debit_units,String(BigInt(invoice.amount)+2n));
    assert.equal(await page.locator('#submission-review').isDisabled(),true);
    await page.locator('#reconcile').click();await settled(page);assert.equal(await page.locator('#progress-title').textContent(),'Execution reconciled');
  }
  const restarted=await command({operation:'restart-listeners'});assert.equal(restarted.passed,true);fixture=restarted.ready;
  await page.goto(fixture.origin+'/');await page.waitForFunction(()=>document.querySelector('#feedback').textContent.startsWith('Ready.'));
  for(const invoice of fixture.invoices){await select(page,invoice);await consent(page);
    downloads.push(await saveDownload(page,fixture,invoice,'cold','resource'));downloads.push(await saveDownload(page,fixture,invoice,'cold','proof'));
    const audit=await command({operation:'audit-downloads',request_id:invoice.request_id,phase:'cold'});assert.equal(audit.passed,true);assert.equal(audit.pending_debit_units,'0');}
  for(const [name,width,height] of [['desktop',1280,900],['mobile',390,844]]){await page.setViewportSize({width,height});assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true);await page.screenshot({path:path.join(artifacts,'purchase-complete-'+name+'.png'),fullPage:true});}
  assert.equal(await page.locator('#balance').textContent(),'957 DEV');assert.equal(calls.filter(c=>c.path==='/api/sign-invoice').length,3);assert.equal(calls.filter(c=>c.path==='/api/submit').length,3);
  assert.equal(calls.filter(c=>c.path==='/api/merchant-retrieve').length,7);assert.equal(downloads.length,12);assert.equal(lost,true);assert.deepEqual(errors,[]);
  workflowComplete=true;child.stdin.write('stop\n');
});
