/* Bounded browser byte validation. No signatures or consensus are simulated. */
const test=require('node:test'),assert=require('node:assert/strict'),crypto=require('node:crypto');
const wallet=require('../web/wallet.js');
const bytes=Buffer.from('original public purchase');
const pin={request_id:'1'.repeat(64),quote_sha256:'2'.repeat(64),wire_sha256:'3'.repeat(64),
  capsule_sha256:'4'.repeat(64),native_txid:'5'.repeat(64),resource_sha256:crypto.createHash('sha256').update(bytes).digest('hex'),fulfilled_ns:null};
function reply({body=bytes,changes={}}={}){
  const headers={'Content-Type':'application/octet-stream','Content-Length':String(bytes.length),
    'X-1soft-Fulfilled-Ns':'1700000000000000001'};
  for(const key of ['request_id','quote_sha256','wire_sha256','capsule_sha256','native_txid','resource_sha256'])
    headers['X-1soft-'+key.replaceAll('_','-')]=pin[key];
  Object.assign(headers,changes);return new Response(body,{status:200,headers});
}
function required(){assert.equal(typeof wallet.resourceBlob,'function','bounded merchant resource validation is missing');return wallet.resourceBlob;}
test('original bytes and all invoice/payment bindings yield one verified resource',async()=>{
  const result=await required()(reply(),pin);assert.equal(await result.blob.text(),bytes.toString());
  assert.equal(result.fulfilled_ns,'1700000000000000001');
});
test('changed resource bytes never yield a successful download',async()=>{
  await assert.rejects(required()(reply({body:Buffer.from('changed public purchase')}),pin));
});
test('missing declared size is refused',async()=>{
  const response=reply();response.headers.delete('Content-Length');await assert.rejects(required()(response,pin));
});
test('another native transaction declaration is refused',async()=>{
  await assert.rejects(required()(reply({changes:{'X-1soft-Native-Txid':'0'.repeat(64)}}),pin));
});
test('excess resource bytes are refused without a download',async()=>{
  await assert.rejects(required()(reply({body:Buffer.concat([bytes,Buffer.from('x')])}),pin));
});
test('merchant HTML is never accepted as a browser resource response',async()=>{
  await assert.rejects(required()(reply({changes:{'Content-Type':'text/html'}}),pin));
});
test('a completed retry cannot change the original fulfillment time',async()=>{
  await assert.rejects(required()(reply(),{...pin,fulfilled_ns:'1700000000000000000'}));
});
for(const changes of [{'X-1soft-Native-Txid':'0'.repeat(64)},
  {'X-1soft-Proof-Format':'unsupported','X-1soft-Proof-Sha256':pin.resource_sha256}]){
  test('refusal cancels the response stream: '+Object.keys(changes)[0],async()=>{
    let cancelled=false;const stream=new ReadableStream({cancel(){cancelled=true;}});
    const response=reply({body:stream,changes});
    const validate=changes['X-1soft-Proof-Format']?wallet.merchantProofBlob:required();
    await assert.rejects(validate(response,pin));assert.equal(cancelled,true);
  });
}
function review(){
  const summary={...pin,format:'1soft/alpha-browser-resource-review/v1',payer:'original payer',
    grant_id:'original role',reference_id:'6'.repeat(64),full_public_ledger_disclosed:true,signing_or_submission_performed:false};
  const review_json=JSON.stringify(summary);
  return {summary,review_json,confirmation:crypto.createHash('sha256').update(review_json).digest('hex')};
}
test('review display is derived from the exact confirmed original text',async()=>{
  const prepared=review();assert.deepEqual(await wallet.checkedMerchantReview(prepared),prepared.summary);
});
for(const key of ['grant_id','payer','reference_id'])test('changed displayed '+key+' cannot authorize retrieval',async()=>{
  const prepared=review();prepared.summary[key]='another value';await assert.rejects(wallet.checkedMerchantReview(prepared));
});
test('changed review text with old confirmation cannot authorize retrieval',async()=>{
  const prepared=review();prepared.summary.grant_id='changed role';prepared.review_json=JSON.stringify(prepared.summary);
  await assert.rejects(wallet.checkedMerchantReview(prepared));
});
test('proof digest is verified before download',async()=>{
  const response=reply({changes:{'X-1soft-Proof-Format':'alpha-v1','X-1soft-Proof-Sha256':pin.resource_sha256}});
  assert.equal(await (await wallet.merchantProofBlob(response,pin)).blob.text(),bytes.toString());
});
test('a changed proof digest refuses the exact original bytes',async()=>{
  await assert.rejects(wallet.merchantProofBlob(reply({changes:{'X-1soft-Proof-Format':'alpha-v1','X-1soft-Proof-Sha256':'0'.repeat(64)}}),pin));
});
