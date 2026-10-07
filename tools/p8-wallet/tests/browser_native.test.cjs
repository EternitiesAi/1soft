'use strict';
// Windows/WSL local qualification, actual browser and actual protected children.
// No private display, credential, opening or request body is retained in evidence.
const assert=require('assert/strict'),fs=require('fs'),path=require('path'),cp=require('child_process'),readline=require('readline');
const playwright=require(process.env.ONE_BROWSER_TEST_DRIVER);
const [repo,python,out,...nativeArgs]=process.argv.slice(2);
assert(repo&&python&&out);fs.mkdirSync(out,{recursive:true});
const report=path.join(out,'browser-native.json');assert(!fs.existsSync(report));
const processArgs=['-d','Ubuntu','--',python,'-B',repo+'/tools/p8-wallet/scripts/demo_wallet.py','--automated',...nativeArgs];
const child=cp.spawn('wsl.exe',processArgs,{stdio:['pipe','pipe','pipe']});
const events=[],waiters=[],trace=[],errors=[],external=[];let diagnostic=false,exit=null,finished=false;
child.stderr.on('data',()=>{diagnostic=true;});
child.on('exit',code=>{exit=code;for(const w of waiters.splice(0))w.reject(new Error('Demo process exited: '+code));});
readline.createInterface({input:child.stdout}).on('line',line=>{
  if(line.startsWith('ALPHA_EVENT ')){
    const value=JSON.parse(line.slice(12));
    const i=waiters.findIndex(w=>w.event===value.event||value.event==='failed');
    if(i>=0){const w=waiters.splice(i,1)[0];clearTimeout(w.timer);value.event==='failed'?w.reject(new Error('Native fixture failed: '+value.error_type)):w.resolve(value);}
    else events.push(value);
    // Delivery path is local UI input, deliberately omitted from the raw log.
    console.log('BROWSER_NATIVE_EVENT',value.event,value.role||'',value.status||'');
  }
});
function event(name){
  const index=events.findIndex(e=>e.event===name||e.event==='failed');
  if(index>=0){const value=events.splice(index,1)[0];return value.event==='failed'?Promise.reject(new Error('Native fixture failed: '+value.error_type)):Promise.resolve(value);}
  if(exit!==null)return Promise.reject(new Error('Demo process exited: '+exit));
  return new Promise((resolve,reject)=>{const w={event:name,resolve,reject,timer:null};w.timer=setTimeout(()=>{const i=waiters.indexOf(w);if(i>=0)waiters.splice(i,1);reject(new Error('Demo stage timeout: '+name));},12*60*1000);waiters.push(w);});
}
async function fixture(command,eventName,extra={}){child.stdin.write(JSON.stringify({command,...extra})+'\n');return event(eventName);}
async function action(page,role,command,click){
  const responsePromise=page.waitForResponse(r=>r.url().endsWith('/api/action')&&r.request().method()==='POST',{timeout:12*60*1000});
  await click();const response=await responsePromise;assert.equal(response.status(),200);
  const value=await response.json();assert.equal(value.command,command);assert.equal(value.automatic_retry,false);
  trace.push({role,command,status:value.status,state:value.console_receipt.view.state,console_pid:value.process.pid,
    console_start_ticks:value.process.start_ticks,process_reaped:value.process.process_reaped});
  // Await handler/render completion without retaining private stdout.
  await page.waitForFunction(()=>!document.getElementById('refresh').disabled,{timeout:12*60*1000});
  return value;
}
async function inputs(page){
  const promise=page.waitForResponse(r=>r.url().endsWith('/api/context'));
  await page.getByRole('button',{name:'Load synthetic demo inputs',exact:true}).click();
  assert.equal((await promise).status(),200);
}
async function flow(page,role,amount){
  await inputs(page);
  await page.getByRole('button',{name:'Receive',exact:true}).click();
  let value=await action(page,role,'observe',()=>page.getByRole('button',{name:'Authenticate signed state',exact:true}).click());
  assert.equal(value.status,'console-completed');
  value=await action(page,role,'import-note',()=>page.getByRole('button',{name:'Import selected note',exact:true}).click());
  assert.equal(value.status,'console-completed');
  await action(page,role,'guide',()=>page.getByRole('button',{name:'Authenticate wallet',exact:true}).click());
  await page.getByRole('button',{name:'Overview',exact:true}).click();
  assert.equal(await page.locator('#notes .row').count(),1);
  await page.locator('#notes .row button').first().click();
  const commitment=await page.locator('#commitment').inputValue();assert.match(commitment,/^[0-9a-f]{64}$/);
  await page.locator('#prepare-form [name=confirmation]').fill('PREPARE '+commitment);
  value=await action(page,role,'prepare',()=>page.getByRole('button',{name:'Prepare this payment',exact:true}).click());
  assert.equal(value.status,'console-completed');
  assert.equal(value.console_receipt.view.state,'prepared-not-attempted');
  assert.equal(value.console_receipt.view.prepared_not_sent,true);
  assert.equal(value.console_receipt.view.can_submit,false);
  assert.equal(value.console_receipt.view.payment_child_started,false);
  assert.equal(value.console_receipt.child_responses[0].status,'original-wire-retained');
  const txid=value.console_receipt.view.txid;assert.match(txid,/^[0-9a-f]{64}$/);
  await page.getByRole('button',{name:'Review & recovery',exact:true}).click();
  value=await action(page,role,'review',()=>page.getByRole('button',{name:'Review original payment',exact:true}).click());
  assert.equal(value.status,'console-completed');assert.equal(value.console_receipt.view.can_submit,true);
  const display=await page.locator('#private-review').textContent();
  // Check the real private review in memory. Never write it or the screenshot.
  assert(display.includes('Payment: '+amount)||display.includes('Amount: '+amount));
  const confirmation='SUBMIT '+txid+' '+value.console_receipt.view.review.wire_sha256;
  await page.locator('#submit-form [name=confirmation]').fill(confirmation);
  value=await action(page,role,'submit',()=>page.getByRole('button',{name:'Send once',exact:true}).click());
  assert.equal(value.console_receipt.view.state,'attempted-outcome-unknown');assert.equal(value.console_receipt.view.attempts,1);
  assert.equal(await page.locator('#send').isEnabled(),false);assert.equal(await page.locator('#private-review').textContent(),'');
  value=await action(page,role,'status',()=>page.getByRole('button',{name:'Check status',exact:true}).click());
  assert.equal(value.console_receipt.view.state,'attempted-outcome-unknown');assert.equal(value.console_receipt.view.attempts,1);
  const settled=await fixture('settle','settled',{role});assert.equal(settled.txid,txid);assert.equal(settled.four_validator_agreement,true);
  await inputs(page);
  value=await action(page,role,'reconcile',()=>page.getByRole('button',{name:'Reconcile original payment',exact:true}).click());
  assert.equal(value.console_receipt.view.state,'executed-exact');assert.equal(value.console_receipt.view.attempts,1);
  // Deliberate hostile UI replay test: new nonce and correct original confirmation.
  // Protected caller must refuse before additional transport I/O.
  const repeated=await page.evaluate(async({txid,confirmation})=>{
    const token=document.querySelector('meta[name="1soft-session"]').content;
    const nonce=Array.from(crypto.getRandomValues(new Uint8Array(24)),v=>v.toString(16).padStart(2,'0')).join('');
    const r=await fetch('/api/action',{method:'POST',headers:{'Content-Type':'application/json','X-1soft-Session':token},body:JSON.stringify({command:'submit',fields:{txid},confirmation,nonce})});
    const v=await r.json();return {http:r.status,status:v.status,command:v.command,state:v.console_receipt.view.state};
  },{txid,confirmation});
  assert.equal(repeated.http,200);assert.equal(repeated.status,'refused');
  trace.push({role,command:'submit-replay-test',status:repeated.status,state:repeated.state});
  // Exports use the exact protected original; explicit opening delivery follows signed recovery.
  value=await action(page,role,'export',()=>page.getByRole('button',{name:'Write new local file',exact:true}).click());
  assert.equal(value.status,'console-completed');
  const delivery=await fixture('delivery','delivery',{role});
  await page.locator('#output-form [name=kind]').selectOption('deliver');
  await page.locator('#output-form [name=output]').fill(delivery.output);
  value=await action(page,role,'deliver',()=>page.getByRole('button',{name:'Write new local file',exact:true}).click());
  assert.equal(value.status,'console-completed');
  await page.getByRole('button',{name:'Overview',exact:true}).click();
  await action(page,role,'guide',()=>page.getByRole('button',{name:'Authenticate wallet',exact:true}).click());
  return txid;
}
// Read-only Windows-to-WSL page readiness. Never call an action or retain HTML.
const alphaHttp=require('http');
async function waitWalletPage(origin){
  assert.match(origin,/^http:\/\/127\.0\.0\.1:[1-9][0-9]*$/);
  const started=Date.now(),attempts=[];
  function probe(){return new Promise(resolve=>{
    let done=false;const finish=v=>{if(!done){done=true;resolve(v);}};
    const request=alphaHttp.get(origin+'/',response=>{
      let body='',bytes=0;
      response.on('data',chunk=>{bytes+=chunk.length;if(bytes>16384){request.destroy();finish({error:'page-bound'});}else body+=chunk;});
      response.on('end',()=>finish({http_status:response.statusCode,
        wallet_page:response.statusCode===200&&body.includes('<title>1soft | Local wallet</title>')&&
          response.headers['cache-control']==='no-store'&&response.headers['x-frame-options']==='DENY'}));
      response.on('error',e=>finish({error:e.code||'read-failed'}));
    });
    request.on('error',e=>finish({error:e.code||'connection-failed'}));
    request.setTimeout(1000,()=>{request.destroy();finish({error:'readiness-timeout'});});
  });}
  do{
    const value=await probe();attempts.push({...value,since_ready_ms:Date.now()-started});
    if(value.http_status===200&&value.wallet_page)return {attempts,read_only_gets:true,page_html_or_token_retained:false};
    if(value.http_status!==undefined)throw new Error('Local wallet page readiness refused: HTTP '+value.http_status);
    await new Promise(resolve=>setTimeout(resolve,250));
  }while(Date.now()-started<30000);
  throw new Error('Windows-to-WSL wallet page readiness timed out; no financial action started.');
}

async function main(){
  let browser=null,context=null;
  try{
    const ready=await event('ready');assert.equal(ready.synthetic_funds,true);
    const transport_readiness={};
    for(const role of ['bob','carol'])transport_readiness[role]=await waitWalletPage(ready.wallets[role]);
    browser=await playwright.chromium.launch({executablePath:process.env.ONE_BROWSER_EXECUTABLE,headless:true});
    context=await browser.newContext({viewport:{width:1280,height:900}});
    const pages={};
    for(const role of ['bob','carol']){
      const page=await context.newPage();pages[role]=page;
      page.on('pageerror',e=>errors.push(e.message));
      page.on('request',r=>{if(!r.url().startsWith(ready.wallets[role]+'/'))external.push(r.url().split('?')[0]);});
      await page.goto(ready.wallets[role],{waitUntil:'networkidle'});assert.equal(await page.locator('#connection').textContent(),'Wallet not loaded');
    }
    const txids=[await flow(pages.bob,'bob',4),await flow(pages.carol,'carol',2)];assert.notEqual(txids[0],txids[1]);
    await pages.bob.screenshot({path:path.join(out,'wallet-actual-desktop.png'),fullPage:true});
    await pages.carol.setViewportSize({width:390,height:844});
    assert(await pages.carol.evaluate(()=>document.documentElement.scrollWidth<=innerWidth));
    await pages.carol.screenshot({path:path.join(out,'wallet-actual-mobile.png'),fullPage:true});
    for(const page of Object.values(pages))assert(await page.evaluate(()=>localStorage.length===0&&sessionStorage.length===0));
    assert.deepEqual(errors,[]);assert.deepEqual(external,[]);
    const value={status:'passed-actual-browser-flow',browser:browser.version(),trace,txids,
      transport_readiness,driver_sha256:require('crypto').createHash('sha256').update(fs.readFileSync(__filename)).digest('hex'),
      actual_receive_prepare_review_send_recovery_delivery:true,recipient_received_funds_used:true,
      two_explicit_one_attempt_sends:true,two_replay_refusals:true,private_display_checked_in_memory:true,
      private_display_retained:false,browser_storage_empty:true,private_display_cleared:true,
      mobile_no_page_overflow:true,page_errors:errors,external_requests:external,
      scope:'One trusted host, synthetic disposable wallets, real local validators, deliberate lost replies. No public deployment/real custody/freshness certification.'};
    fs.writeFileSync(report,JSON.stringify(value,null,2)+'\n');
    const done=await fixture('finish','finished',{browser:value});finished=true;
    assert.equal(done.status,'qualified-one-host-synthetic-browser-alpha');
    child.stdin.end();await new Promise(resolve=>{if(exit!==null)resolve();else child.once('exit',resolve);});
    assert.equal(exit,0);assert.equal(diagnostic,false);console.log('ACTUAL_BROWSER_ALPHA_PASSED',txids.join(' '));
  }finally{
    if(context)await context.close();if(browser)await browser.close();
    if(!finished&&exit===null){child.stdin.end();await new Promise(resolve=>{child.once('exit',resolve);setTimeout(resolve,20000);});}
  }
}
main().catch(e=>{console.error(e.stack);process.exitCode=1;});
