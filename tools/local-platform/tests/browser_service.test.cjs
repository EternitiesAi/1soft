/* Actual guarded API/native application fixture reached through Chromium events.
 * Committee signatures and RPC are deterministic fixtures, not CometBFT consensus.
 * This script creates only owned temporary development fixtures. No installs.
 * Windows/WSL: ONE_BROWSER_SERVICE_PYTHON and ONE_BROWSER_SERVICE_ROOT are required.
 */
const test=require('node:test');const assert=require('node:assert/strict');
const {spawn}=require('node:child_process');const readline=require('node:readline');
const fs=require('node:fs'),path=require('node:path');
const {chromium}=require(process.env.ONE_BROWSER_TEST_DRIVER||'playwright-core');
const PUBLIC_FIXTURE_PASSWORD='fixture passphrase not for funds';
async function waitForLoopback(origin){
  // WSL's Windows loopback forwarding can lag the actual server listen event.
  // Inspect only the same guarded GET asset; never retry a financial action.
  const http=require('node:http'),limit=Date.now()+10000;
  while(true){
    try{
      const status=await new Promise((resolve,reject)=>{
        const r=http.get(origin+'/',response=>{response.resume();response.once('end',()=>resolve(response.statusCode));});
        r.once('error',reject);r.setTimeout(1000,()=>r.destroy(Error('loopback readiness timed out')));
      });
      assert.equal(status,200,'same guarded loopback asset refused');return;
    }catch(e){
      if(e.code!=='ECONNREFUSED'||Date.now()>=limit)throw e;
      await new Promise(resolve=>setTimeout(resolve,100));
    }
  }
}

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
  assert.equal(result.passed,true);assert.equal(result.backup_format_version,3);
  assert.equal(result.all_seven_tables_exact,true);assert.equal(result.source_logical_rows_unchanged,true);
  assert.equal(result.spending_authority,false);assert.equal(result.keys_unlocked,false);
  assert.equal(result.signing_or_submission_performed,false);
  if(stage==='signed-pending')assert.ok(BigInt(result.pending_debit_units)>0n);
  else assert.equal(result.pending_debit_units,'0');
  return result;
}

test('Chromium completes the guarded service flow with one original native payment',async t=>{
  const root=process.env.ONE_BROWSER_SERVICE_ROOT,python=process.env.ONE_BROWSER_SERVICE_PYTHON;
  assert.ok(root&&python,'explicit existing WSL source/Python required; no auto-install');
  const artifacts=process.env.ONE_BROWSER_TEST_ARTIFACTS;assert.ok(artifacts);assert.equal(fs.existsSync(artifacts),false);fs.mkdirSync(artifacts);
  const backupAudits=[],auditWaiters=new Map();let workflowComplete=false;
  function awaitAudit(stage){return new Promise((resolve,reject)=>{const timer=setTimeout(()=>reject(Error('owned download audit timed out')),15000);auditWaiters.set(stage,v=>{clearTimeout(timer);resolve(v);});});}
  const child=spawn('wsl.exe',['--distribution','Ubuntu','--user',process.env.ONE_BROWSER_SERVICE_USER||'xnuonux',
    '--cd',root,'--exec',python,'tools/local-platform/tests/browser_service_fixture.py'],{stdio:['pipe','pipe','pipe']});
  const lines=[],stderr=[];let exit=null;
  child.stderr.on('data',x=>stderr.push(x.toString()));
  const closed=new Promise((resolve,reject)=>{child.once('error',reject);child.once('exit',(code)=>{exit=code;resolve(code);});});
  const stream=readline.createInterface({input:child.stdout});
  let readyResolve;const ready=new Promise(r=>readyResolve=r);
  stream.on('line',x=>{const value=JSON.parse(x);lines.push(value);if(value.origin)readyResolve(value);if(value.backup_audit){const a=value.backup_audit;backupAudits.push(a);const receive=auditWaiters.get(a.stage);assert.ok(receive);auditWaiters.delete(a.stage);receive(a);}});
  let browser=null,context=null;
  t.after(async()=>{
    const stopped=await Promise.allSettled([context?.close(),browser?.close()]);
    if(exit===null)child.stdin.end('stop\n');
    let timer;const code=await Promise.race([closed,new Promise((_,reject)=>timer=setTimeout(()=>reject(Error('owned fixture cleanup timed out')),15000))]).finally(()=>clearTimeout(timer));
    for(const r of stopped)assert.equal(r.status,'fulfilled');
    assert.equal(code,0,stderr.join(''));assert.equal(stderr.join(''),'');
    assert.equal(lines.at(-1).owned_cleanup,true);
    const submissions=lines.find(x=>'submissions'in x).submissions;
    t.diagnostic('owned Chromium contexts and native service fixture closed; native submissions '+submissions);
    assert.equal(submissions,1);assert.equal(backupAudits.length,2);
    fs.writeFileSync(path.join(artifacts,'browser-result.json'),JSON.stringify({schema:1,passed:workflowComplete&&code===0&&submissions===1,submissions,backup_audits:backupAudits,scope:fixture.scope},null,2)+'\n');
  });
  let timer;const fixture=await Promise.race([ready,closed.then(code=>{throw Error('fixture exited before ready: '+code+' '+stderr.join(''));}),new Promise((_,reject)=>timer=setTimeout(()=>reject(Error('owned fixture startup timed out')),15000))]).finally(()=>clearTimeout(timer));
  assert.match(fixture.scope,/no CometBFT/);
  await waitForLoopback(fixture.origin);
  browser=await chromium.launch({headless:true,executablePath:process.env.ONE_BROWSER_TEST_EXECUTABLE});
  t.diagnostic('Chromium '+browser.version()+'; playwright-core '+require(require('node:path').join(process.env.ONE_BROWSER_TEST_DRIVER||'playwright-core','package.json')).version);
  context=await browser.newContext({viewport:{width:1280,height:900},acceptDownloads:true});const page=await context.newPage();page.setDefaultTimeout(5000);
  const errors=[];page.on('pageerror',e=>errors.push(e.message));
  const response=await page.goto(fixture.origin+'/');
  assert.match(response.headers()['content-security-policy'],/default-src 'none'/);
  assert.equal(response.headers()['cache-control'],'no-store');
  await page.waitForFunction(()=>document.querySelector('#feedback').textContent.startsWith('Ready.'));
  await page.locator('#units').fill('58');await page.locator('#note').fill('Actual API browser fixture');
  await page.locator('#request-form button').click();
  await page.waitForFunction(()=>document.querySelector('#feedback').textContent.startsWith('Request retained.'));
  await page.locator('#role').selectOption('raven');await page.locator('#prepare').click();
  await page.locator('#payment-review').waitFor({state:'visible'});
  assert.match(await page.locator('#payment-facts').textContent(),/60 DEV/);
  await page.locator('#sign-check').check();await page.locator('#password').fill(PUBLIC_FIXTURE_PASSWORD);
  await page.locator('#sign').click();await page.waitForFunction(()=>document.querySelector('#feedback').textContent.startsWith('Original signed decision'));
  assert.match(await page.locator('#pending').textContent(),/60 DEV/);assert.equal(await page.locator('#password').inputValue(),'');
  await page.locator('#submission-review').click();await page.locator('#dispatch-review').waitFor({state:'visible'});
  await page.locator('#send-check').check();await page.locator('#send').click();
  await page.waitForFunction(()=>document.querySelector('#feedback').textContent.startsWith('Submission attempt retained'));
  assert.match(await page.locator('#progress-title').textContent(),/outcome unknown/i);
  await downloadHistory(page,fixture,child,awaitAudit,'signed-pending');
  for(const [name,width,height]of [['desktop',1280,900],['mobile',390,844]]){await page.setViewportSize({width,height});assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true);await page.screenshot({path:path.join(artifacts,'history-'+name+'.png'),fullPage:true});}
  await page.setViewportSize({width:1280,height:900});
  await page.locator('#collect').click();await page.waitForFunction(()=>document.querySelector('#progress-title').textContent==='Receipt verified');
  assert.match(await page.locator('#pending').textContent(),/60 DEV/);
  await page.locator('#reconcile').click();await page.waitForFunction(()=>document.querySelector('#progress-title').textContent==='Execution reconciled');
  assert.equal(await page.locator('#pending').textContent(),'0 DEV');
  await page.locator('#retain').click();await page.waitForFunction(()=>document.querySelector('#feedback').textContent.startsWith('Verified capsule retained'));
  for(const id of ['original-download','capsule-download']){
    const href=await page.locator('#'+id).getAttribute('href');const r=await context.request.get(fixture.origin+href);
    assert.equal(r.status(),200);assert.equal(r.headers()['cache-control'],'no-store');
    assert.doesNotMatch(await r.text(),/fixture passphrase not for funds/);
    assert.ok((await r.body()).length>100);
  }
  await downloadHistory(page,fixture,child,awaitAudit,'receipt-complete');
  assert.equal(await page.locator('#submission-review').isDisabled(),true);assert.deepEqual(errors,[]);workflowComplete=true;
});
