/** Second implementation of the project SMT specification, using only Node core.
 * Root construction is iterative, bottom-up; the Python implementation compresses
 * paths recursively. This is cross-implementation testing, NOT an independent audit.
 */
import {createHash} from 'node:crypto';
import {readFileSync} from 'node:fs';

const h = bytes => createHash('sha256').update(bytes).digest();
const join = (...bytes) => Buffer.concat(bytes);
const branch = (a,b) => h(join(Buffer.from([1]),a,b));
const bytes = x => Buffer.from(x,'utf8');
const json = x => bytes(JSON.stringify(x)); // Vectors contain ASCII arrays only.
const assert = (x,msg) => {if(!x) throw new Error(msg);};
const empty=[h(Buffer.from([2]))];
for(let level=0;level<256;level++) empty.push(branch(empty[level],empty[level]));
function path(table,key) {return h(join(bytes('1soft/state-key/v1\0'),json([table,key])));}
function leaf(p,value) {return h(join(Buffer.from([0]),p,h(json(value))));}
function digest(text) {
 assert(typeof text==='string' && /^[0-9a-f]{64}$/.test(text),'bad hex');
 return Buffer.from(text,'hex');
}
function root(state) {
 let current=new Map();
 for(const [table,rows] of Object.entries(state)) for(const row of rows) {
  const p=path(table,row[0]);const pos=BigInt('0x'+p.toString('hex'));
  assert(!current.has(pos),'duplicate key');current.set(pos,leaf(p,row));
 }
 for(let level=0;level<256;level++) {
  const parents=new Set([...current.keys()].map(x=>x>>1n));const next=new Map();
  for(const parent of parents) next.set(parent,branch(current.get(parent<<1n)||empty[level],current.get((parent<<1n)|1n)||empty[level]));
  current=next;
 }
 return current.get(0n)||empty[256];
}
function verify(r,table,key,p) {
 assert(p.table===table && p.key===key,'changed key');
 const pk=path(table,key);let position=BigInt('0x'+pk.toString('hex'));
 let value;
 if(p.value===null) value=empty[0];
 else {assert(Array.isArray(p.value)&&p.value[0]===key,'bad leaf');value=leaf(pk,p.value);}
 let mask=BigInt('0x'+digest(p.mask).toString('hex'));let used=0;
 for(let level=0;level<256;level++) {
  let sibling=empty[level];
  if((mask>>BigInt(level))&1n) {
   sibling=digest(p.siblings[used++]);assert(!sibling.equals(empty[level]),'redundant default');
  }
  value=((position>>BigInt(level))&1n)?branch(sibling,value):branch(value,sibling);
 }
 assert(used===p.siblings.length,'trailing sibling');assert(value.equals(r),'bad root');
 return true;
}
try {
 const raw=readFileSync(process.argv[2]);assert(raw.length<=4*1024*1024,'oversized vector file');
 const cases=JSON.parse(raw);assert(Array.isArray(cases)&&cases.length>0&&cases.length<=20,'bad cases');
 let roots=0,proofs=0,negative=0;
 for(const c of cases) {
  const expected=digest(c.root);assert(root(c.state).equals(expected),'independent root mismatch');roots++;
  for(const p of c.proofs) {
   verify(expected,p.table,p.key,p);proofs++;
   const wrong=Buffer.from(expected);wrong[0]^=1;
   let rejected=false;try{verify(wrong,p.table,p.key,p);}catch{rejected=true;}
   assert(rejected,'changed root accepted');negative++;
  }
 }
 console.log(JSON.stringify({status:'passed',roots_checked:roots,proofs_checked:proofs,
   mutated_roots_rejected:negative,scope:'second implementation, not independent audit or consensus'}));
} catch(error) {console.error('Reference verification failed: '+error.message);process.exitCode=1;}
