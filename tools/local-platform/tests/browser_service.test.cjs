/* Actual guarded API/native application fixture reached through Chromium events.
 * Committee signatures and RPC are deterministic fixtures, not CometBFT consensus.
 * This script creates only owned temporary development fixtures. No installs.
 * Windows/WSL: ONE_BROWSER_SERVICE_PYTHON and ONE_BROWSER_SERVICE_ROOT are required.
 */
const test=require('node:test');const assert=require('node:assert/strict');
const {spawn}=require('node:child_process');const readline=require('node:readline');
const {chromium}=require(process.env.ONE_BROWSER_TEST_DRIVER||'playwright-core');
const PUBLIC_FIXTURE_PASSWORD='fixture passphrase not for funds';
test('Chromium completes the guarded service flow with one original native payment',async t=>{
  const root=process.env.ONE_BROWSER_SERVICE_ROOT,python=process.env.ONE_BROWSER_SERVICE_PYTHON;
  assert.ok(root&&python,'explicit existing WSL source/Python required; no auto-install');
  const child=spawn('wsl.exe',['--distribution','Ubuntu','--user',process.env.ONE_BROWSER_SERVICE_USER||'xnuonux',
    '--cd',root,'--exec',python,'tools/local-platform/tests/browser_service_fixture.py'],{stdio:['pipe','pipe','pipe']});
  const lines=[],stderr=[];let exit=null;
  child.stderr.on('data',x=>stderr.push(x.toString()));
  const closed=new Promise((resolve,reject)=>{child.once('error',reject);child.once('exit',(code)=>{exit=code;resolve(code);});});
  const stream=readline.createInterface({input:child.stdout});
  let readyResolve;const ready=new Promise(r=>readyResolve=r);
  stream.on('line',x=>{const value=JSON.parse(x);lines.push(value);if(value.origin)readyResolve(value);});
  let browser=null,context=null;
  t.after(async()=>{
    const stopped=await Promise.allSettled([context?.close(),browser?.close()]);
    if(exit===null)child.stdin.end('stop\n');
    let timer;const code=await Promise.race([closed,new Promise((_,reject)=>timer=setTimeout(()=>reject(Error('owned fixture cleanup timed out')),15000))]).finally(()=>clearTimeout(timer));
    for(const r of stopped)assert.equal(r.status,'fulfilled');
    assert.equal(code,0,stderr.join(''));assert.equal(stderr.join(''),'');
    assert.equal(lines.at(-1).owned_cleanup,true);assert.equal(lines.find(x=>'submissions'in x).submissions,1);
    t.diagnostic('owned Chromium contexts and native service fixture closed; one native submission');
  });
  let timer;const fixture=await Promise.race([ready,closed.then(code=>{throw Error('fixture exited before ready: '+code+' '+stderr.join(''));}),new Promise((_,reject)=>timer=setTimeout(()=>reject(Error('owned fixture startup timed out')),15000))]).finally(()=>clearTimeout(timer));
  assert.match(fixture.scope,/no CometBFT/);
  browser=await chromium.launch({headless:true,executablePath:process.env.ONE_BROWSER_TEST_EXECUTABLE});
  t.diagnostic('Chromium '+browser.version()+'; playwright-core '+require(require('node:path').join(process.env.ONE_BROWSER_TEST_DRIVER||'playwright-core','package.json')).version);
  context=await browser.newContext({viewport:{width:1280,height:900}});const page=await context.newPage();page.setDefaultTimeout(5000);
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
  assert.equal(await page.locator('#submission-review').isDisabled(),true);assert.deepEqual(errors,[]);
});
