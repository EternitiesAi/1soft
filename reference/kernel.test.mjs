import test from 'node:test';
import assert from 'node:assert/strict';
import { Kernel } from './kernel.mjs';
function setup() {
  const k = new Kernel();
  k.createAccount({accountId:'luna',spendable:'100',protectedContinuity:'40'});
  k.grant({grantId:'root',accountId:'luna',limit:'80',payees:['render','research'],rails:['x402','card'],notBefore:0,expiresAt:100},0);
  return k;
}
const reserve = (k,overrides={},now=1) => k.reserve({intentId:'job-1',grantId:'root',epoch:0,payee:'render',rail:'x402',amount:'30',...overrides},now);
const child = (k,name,extra={}) => k.grant({grantId:name,accountId:'luna',parent:'root',limit:'60',payees:['render'],rails:['x402'],notBefore:0,expiresAt:90,...extra},0);
function unchanged(k,fn) { const before=k.snapshot(); assert.throws(fn); assert.deepEqual(k.snapshot(),before); k.assertInvariants(); }

test('reserve keeps protected continuity separate',()=>{const k=setup();reserve(k);assert.equal(k.account('luna').available,'70');assert.equal(k.account('luna').protectedContinuity,'40');k.assertInvariants();});
test('retry returns existing intent without new reservation',()=>{const k=setup();assert.equal(reserve(k).created,true);const s=k.snapshot();assert.equal(reserve(k).created,false);assert.deepEqual(k.snapshot(),s);});
test('same intent cannot change amount',()=>{const k=setup();reserve(k);unchanged(k,()=>reserve(k,{amount:'31'}));});
test('same intent cannot switch rails',()=>{const k=setup();reserve(k);unchanged(k,()=>reserve(k,{rail:'card'}));});
test('payee is checked',()=>{const k=setup();unchanged(k,()=>reserve(k,{payee:'unknown'}));});
test('rail is checked',()=>{const k=setup();unchanged(k,()=>reserve(k,{rail:'bridge'}));});
test('sibling workers share ancestor limit',()=>{const k=setup();child(k,'a');child(k,'b');reserve(k,{grantId:'a',amount:'50'});unchanged(k,()=>reserve(k,{intentId:'job-2',grantId:'b',amount:'50'}));});
test('child has its own smaller cap',()=>{const k=setup();child(k,'a',{limit:'20'});unchanged(k,()=>reserve(k,{grantId:'a',amount:'21'}));});
test('child cannot widen recipient scope',()=>{const k=setup();unchanged(k,()=>child(k,'a',{payees:['unknown']}));});
test('child cannot widen amount',()=>{const k=setup();unchanged(k,()=>child(k,'a',{limit:'81'}));});
test('child cannot extend expiry',()=>{const k=setup();unchanged(k,()=>child(k,'a',{expiresAt:101}));});
test('deny empty allowlist rather than treat it as unrestricted',()=>{const k=setup();unchanged(k,()=>child(k,'a',{payees:[]}));});
test('reject floating point / noncanonical and excessive amounts',()=>{for(const amount of [1.5,'1.5','-1','01','1e2','0','9'.repeat(40)]){const k=setup();unchanged(k,()=>reserve(k,{amount}));}});
test('exact expiry is rejected',()=>{const k=setup();unchanged(k,()=>reserve(k,{},100));});
test('clock regression fails without mutation',()=>{const k=setup();reserve(k,{},20);unchanged(k,()=>reserve(k,{intentId:'job-2'},19));});
test('revoking ancestor stops descendant reservation',()=>{const k=setup();child(k,'a');k.revoke('root');unchanged(k,()=>reserve(k,{grantId:'a'}));});
test('revocation after reserve stops dispatch but allows safe cancellation',()=>{const k=setup();reserve(k);k.revoke('root');unchanged(k,()=>k.dispatch('job-1',2));k.cancelBeforeDispatch('job-1');assert.equal(k.account('luna').available,'100');k.assertInvariants();});
test('rotation fences old authority',()=>{const k=setup();k.rotateAuthority('luna');unchanged(k,()=>reserve(k));});
test('new epoch does not refresh funds consumed by old one',()=>{const k=setup();reserve(k,{amount:'70'});k.dispatch('job-1',2);k.markUnknown('job-1');k.rotateAuthority('luna');k.grant({grantId:'new-root',accountId:'luna',limit:'100',payees:['render'],rails:['x402'],notBefore:2,expiresAt:100},2);unchanged(k,()=>reserve(k,{intentId:'job-2',grantId:'new-root',epoch:1,amount:'31'},3));k.assertInvariants();});
test('unknown delivery remains encumbered',()=>{const k=setup();reserve(k);k.dispatch('job-1',2);k.markUnknown('job-1');assert.equal(k.account('luna').pending,'30');unchanged(k,()=>k.cancelBeforeDispatch('job-1'));unchanged(k,()=>k.dispatch('job-1',3));});
test('dispatch is one-shot',()=>{const k=setup();reserve(k);k.dispatch('job-1',2);unchanged(k,()=>k.dispatch('job-1',3));});
test('late settlement remains valid after authority rotation',()=>{const k=setup();reserve(k);k.dispatch('job-1',2);k.markUnknown('job-1');k.rotateAuthority('luna');k.reconcile('job-1','settled','receipt-1');assert.equal(k.account('luna').spent,'30');k.assertInvariants();});
test('settlement is idempotent',()=>{const k=setup();reserve(k);k.dispatch('job-1',2);k.reconcile('job-1','settled','receipt-1');const s=k.snapshot();k.reconcile('job-1','settled','receipt-1');assert.deepEqual(k.snapshot(),s);});
test('contradictory receipt cannot reverse terminal settlement',()=>{const k=setup();reserve(k);k.dispatch('job-1',2);k.reconcile('job-1','settled','receipt-1');unchanged(k,()=>k.reconcile('job-1','not-settled','receipt-2'));});
test('trusted not-settled evidence releases reservation',()=>{const k=setup();reserve(k);k.dispatch('job-1',2);k.markUnknown('job-1');k.reconcile('job-1','not-settled','receipt-1');assert.equal(k.account('luna').available,'100');k.assertInvariants();});
test('replaying cancelled intent cannot create new execution',()=>{const k=setup();reserve(k);k.cancelBeforeDispatch('job-1');assert.equal(reserve(k).created,false);unchanged(k,()=>k.dispatch('job-1',2));});
test('snapshots do not expose mutable live state',()=>{const k=setup();const s=k.snapshot();s.accounts[0].available='999';s.grants[0].payees.push('unknown');assert.equal(k.account('luna').available,'100');unchanged(k,()=>reserve(k,{payee:'unknown'}));});
test('promise-scheduled siblings cannot oversubscribe single serialized kernel',async()=>{const k=setup();const results=await Promise.allSettled([1,2].map(i=>Promise.resolve().then(()=>reserve(k,{intentId:`job-${i}`,amount:'50'}))));assert.equal(results.filter(r=>r.status==='fulfilled').length,1);k.assertInvariants();});
test('cross-rail intents share account and root budget',()=>{const k=setup();reserve(k,{amount:'50'});unchanged(k,()=>reserve(k,{intentId:'card-job',rail:'card',amount:'31'}));});
test('500 deterministic transitions preserve accounting invariants',()=>{const k=new Kernel();k.createAccount({accountId:'a',spendable:'100000',protectedContinuity:'500'});k.grant({grantId:'g',accountId:'a',limit:'100000',payees:['vendor'],rails:['sim'],notBefore:0,expiresAt:10000},0);for(let i=0;i<500;i++){const name=`p-${i}`;k.reserve({intentId:name,grantId:'g',epoch:0,payee:'vendor',rail:'sim',amount:String(1+(i*71)%97)},i+1);if(i%3===0)k.cancelBeforeDispatch(name);else{k.dispatch(name,i+1);if(i%3===1)k.markUnknown(name);else k.reconcile(name,'settled',`receipt-${i}`);}k.assertInvariants();}assert.equal(k.account('a').protectedContinuity,'500');});
