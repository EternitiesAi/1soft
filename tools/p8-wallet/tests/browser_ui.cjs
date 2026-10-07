'use strict';
// Actual Chromium UI over the explicitly canned preview service. This does not
// qualify native proof, custody, payment, signed recovery or validator execution.
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const {chromium}=require(process.env.ONE_BROWSER_TEST_DRIVER||'playwright-core');
async function main(){
  const [origin,out]=process.argv.slice(2);assert(/^http:\/\/127\.0\.0\.1:\d+$/.test(origin));assert(out);
  const report=path.join(out,'browser-preview-01.json');assert(!fs.existsSync(report));
  const browser=await chromium.launch({executablePath:process.env.ONE_BROWSER_EXECUTABLE,headless:true});
  const context=await browser.newContext({viewport:{width:1280,height:1000},reducedMotion:'reduce'});
  const page=await context.newPage();const errors=[],commands=[],external=[];
  page.on('pageerror',e=>errors.push(e.message));page.on('request',r=>{
    if(!r.url().startsWith(origin+'/'))external.push(r.url().split('?')[0]);
    if(r.url()===origin+'/api/action')commands.push(JSON.parse(r.postData()).command);
  });
  try{
    await page.goto(origin,{waitUntil:'networkidle'});
    assert.equal(await page.locator('#connection').textContent(),'Wallet not loaded');assert.equal(commands.length,0);
    await page.getByRole('button',{name:'Authenticate wallet',exact:true}).click();
    await page.waitForFunction(()=>document.getElementById('connection').textContent==='Authenticated local wallet');
    assert.equal(await page.locator('#notes .row').count(),2);
    await page.screenshot({path:path.join(out,'wallet-desktop-preview.png'),fullPage:true});
    await page.locator('#notes .row button').first().click();
    await page.locator('#prepare-form [name=destination]').fill('88'.repeat(32));
    await page.locator('#prepare-form [name=payment]').fill('4');
    await page.locator('#prepare-form [name=payment_expiry]').fill('56');
    await page.locator('#prepare-form [name=valid_until]').fill('32');
    await page.locator('#prepare-form [name=confirmation]').fill('PREPARE '+'11'.repeat(32));
    await page.getByRole('button',{name:'Prepare this payment',exact:true}).click();
    await page.waitForFunction(()=>document.getElementById('txid').value==='44'.repeat(32));
    await page.getByRole('button',{name:'Review & recovery',exact:true}).click();
    await page.getByRole('button',{name:'Review original payment',exact:true}).click();
    await page.locator('#review-panel').waitFor({state:'visible'});
    assert((await page.locator('#private-review').textContent()).includes('Amount: 4 atomic units'));
    assert.equal(await page.locator('#send').isEnabled(),true);
    await page.locator('#submit-form [name=confirmation]').fill('SUBMIT '+'44'.repeat(32)+' '+'55'.repeat(32));
    await page.getByRole('button',{name:'Send once',exact:true}).click();
    await page.waitForFunction(()=>document.getElementById('result-heading').textContent==='attempted outcome unknown');
    assert.equal(await page.locator('#send').isEnabled(),false);
    await page.getByRole('button',{name:'Check status',exact:true}).click();
    await page.waitForFunction(()=>document.getElementById('notice').textContent.startsWith('Canned interface'));
    await page.getByRole('button',{name:'Reconcile original payment',exact:true}).click();
    await page.waitForFunction(()=>document.getElementById('result-heading').textContent==='executed exact');
    assert.equal(await page.locator('#private-review').textContent(),'');
    assert.equal(commands.filter(x=>x==='submit').length,1);
    await page.getByRole('button',{name:'Overview',exact:true}).click();
    await page.setViewportSize({width:390,height:844});
    await page.screenshot({path:path.join(out,'wallet-mobile-preview.png'),fullPage:true});
    assert(await page.evaluate(()=>document.documentElement.scrollWidth<=window.innerWidth));
    assert.deepEqual(errors,[]);assert.deepEqual(external,[]);
    const value={status:'passed-browser-presentation-preview',fixture:'Canned UI service; no native proof/custody/node/financial effects',browser:browser.version(),commands,
      explicit_authentication_no_auto_fetch:true,one_submit_click_no_retry:true,private_display_cleared:true,mobile_no_page_overflow:true,page_errors:errors,external_requests:external,
      native_wallet_qualified:false,validator_execution_qualified:false};
    fs.writeFileSync(report,JSON.stringify(value,null,2)+'\n');console.log(JSON.stringify(value));
  }finally{await context.close();await browser.close();}
}
main().catch(e=>{console.error(e.stack);process.exitCode=1;});
