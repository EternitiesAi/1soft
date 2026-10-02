const test=require('node:test');const assert=require('node:assert/strict');
const wallet=require('../web/wallet.js');
const secret='public history backup passphrase';
test('backup scope and UTF8 byte limits are enforced before fetching',()=>{
  assert.equal(typeof wallet.backupInputs,'function','backup input validator is missing');
  assert.deepEqual(wallet.backupInputs(secret,secret,true),{passphrase:secret,repeat_passphrase:secret,scope_confirmed:true});
  assert.deepEqual(wallet.backupInputs('界'.repeat(6),'界'.repeat(6),true).passphrase,'界'.repeat(6));
  for(const [a,b,scope] of [[secret,secret,false],[secret,secret,1],['a'.repeat(15),'a'.repeat(15),true],
      ['界'.repeat(342),'界'.repeat(342),true],[secret,secret+'x',true],['\ud800'.repeat(16),'\ud800'.repeat(16),true]]){
    assert.throws(()=>wallet.backupInputs(a,b,scope));
  }
});
test('binary history validates content type, declared length, completed size and format',async()=>{
  assert.equal(typeof wallet.historyBlob,'function','binary backup reader is missing');
  const raw=Buffer.from('1SOFTP4B3\npublic test ciphertext');
  const reply=(data=raw,headers={})=>new Response(data,{headers:{'Content-Type':'application/octet-stream','Content-Length':String(raw.length),...headers}});
  const blob=await wallet.historyBlob(reply());assert.equal(blob.size,raw.length);
  for(const response of [reply(raw,{'Content-Type':'application/json'}),reply(raw,{'Content-Length':'0'}),
      reply(raw,{'Content-Length':'16777217'}),reply(raw,{'Content-Length':'01'}),reply(raw.subarray(1)),
      reply(Buffer.concat([raw,Buffer.from('tail')])),reply(Buffer.from('0'.repeat(raw.length)))]){
    await assert.rejects(wallet.historyBlob(response));
  }
});
test('binary refusal remains a history-specific recoverable error',async()=>{
  assert.equal(typeof wallet.historyBlob,'function');
  await assert.rejects(wallet.historyBlob(new Response('{"error":"request_refused"}',{status:400})),/history|CLI/i);
});
test('a stream crossing its declared size is cancelled before retaining excess bytes',async()=>{
  let cancelled=false;
  const stream=new ReadableStream({start(controller){controller.enqueue(new Uint8Array(11));},cancel(){cancelled=true;}});
  await assert.rejects(wallet.historyBlob(new Response(stream,{headers:{'Content-Type':'application/octet-stream','Content-Length':'10'}})),/bound/);
  assert.equal(cancelled,true);
});
test('an interrupted stream refuses a completed download',async()=>{
  const stream=new ReadableStream({start(controller){controller.enqueue(new Uint8Array([49,83]));controller.error(Error('injected interruption'));}});
  await assert.rejects(wallet.historyBlob(new Response(stream,{headers:{'Content-Type':'application/octet-stream','Content-Length':'10'}})),/interruption/);
});
