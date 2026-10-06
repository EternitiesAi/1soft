import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
const fixture = JSON.parse(readFileSync(new URL('../dist/fixture.json', import.meta.url)));

// A narrow DOM harness executes the production event handlers. It does not
// emulate layout or claim browser QA.
const decode = s => s.replaceAll('&quot;', '"').replaceAll('&#39;', "'").replaceAll('&lt;', '<').replaceAll('&gt;', '>').replaceAll('&amp;', '&');
class Element {
  constructor(id = '') { this.id = id; this.dataset = {}; this.handlers = {}; this.attributes = {}; this.value = ''; this._html = ''; this.children = []; this.tagName = 'DIV'; this.classes = new Set(); this.classList = { add: c => this.classes.add(c), remove: c => this.classes.delete(c) }; }
  addEventListener(type, handler) { (this.handlers[type] ||= []).push(handler); }
  async fire(type, extra = {}) { const event = { target: this, preventDefault() { this.prevented = true; }, ...extra }; for (const fn of this.handlers[type] || []) await fn(event); return event; }
  focus() { this.focused = true; }
  setAttribute(k, v) { this.attributes[k] = v; }
  removeAttribute(k) { delete this.attributes[k]; }
  set innerHTML(html) {
    this._html = html; this.children = [];
    if (this.id !== 'content') return;
    for (const [id, el] of doc.elements) if (el.generated) doc.elements.delete(id);
    for (const match of html.matchAll(/<(form|input|button)[^>]*\bid="([^"]+)"[^>]*>/g)) {
      const el = new Element(match[2]); el.generated = true; el.tagName = match[1].toUpperCase();
      el.value = decode(match[0].match(/\bvalue="([^"]*)"/)?.[1] || '');
      el.dataset.section = match[0].match(/data-section="([^"]+)"/)?.[1];
      doc.elements.set(el.id, el);
    }
    for (const match of html.matchAll(/<button[^>]*data-(mode|copy)="([^"]*)"[^>]*>/g)) { const el = new Element(); el.dataset[match[1]] = decode(match[2]); this.children.push(el); }
  }
  get innerHTML() { return this._html; }
  querySelectorAll(selector) { const key = selector === '[data-copy]' ? 'copy' : 'mode'; return this.children.filter(el => el.dataset[key]); }
}
let doc;
function setup({ failure = false, invalid = false } = {}) {
  doc = { elements: new Map(['content', 'data-mode', 'search-form', 'global-search', 'toast'].map(id => [id, new Element(id)])), handlers: {}, getElementById(id) { return this.elements.get(id); }, querySelectorAll(selector) { return selector === '[data-nav]' ? this.nav : []; }, addEventListener(type, fn) { (this.handlers[type] ||= []).push(fn); } };
  doc.nav = ['overview', 'blocks', 'transactions', 'addresses', 'network'].map(name => { const el = new Element(); el.dataset.nav = name; return el; });
  globalThis.document = doc;
  const handlers = {};
  globalThis.window = { addEventListener(type, fn) { (handlers[type] ||= []).push(fn); }, scrollTo() {} };
  let hash = '#/overview';
  let reloaded = false;
  globalThis.location = { get hash() { return hash; }, set hash(v) { hash = v; for (const fn of handlers.hashchange || []) fn(); }, reload() { reloaded = true; } };
  const storage = new Map();
  globalThis.sessionStorage = { getItem: k => storage.get(k), setItem: (k, v) => storage.set(k, v) };
  Object.defineProperty(globalThis, 'navigator', { configurable: true, value: { clipboard: { async writeText(value) { setup.copied = value; } } } });
  const requests = [];
  globalThis.fetch = async (url, opts) => { requests.push({ url, opts }); if (failure) throw Error('load failed'); return { ok: true, json: async () => invalid ? { mode: 'live' } : fixture }; };
  return { doc, storage, requests, reload: () => reloaded };
}

test('production event handlers support block → transfer → address, search, filter, pager and modes', async () => {
  const env = setup();
  const app = await import('../dist/app.js?success');
  const main = doc.getElementById('content');
  assert.match(main.innerHTML, /Follow the ledger/);
  const block = fixture.blocks.find(b => b.transactions.length > 0);
  app.navigate('block', block.height);
  assert.match(main.innerHTML, new RegExp('Block #' + block.height));
  assert.ok(main.innerHTML.includes(block.transactions[0]));
  app.navigate('transaction', block.transactions[0]);
  const tx = fixture.transactions.find(t => t.native_txid === block.transactions[0]);
  assert.ok(main.innerHTML.includes(tx.payer)); assert.ok(main.innerHTML.includes(tx.recipient));
  app.navigate('address', tx.payer); assert.match(main.innerHTML, /RECORDED FIXTURE BALANCE/);
  assert.equal(doc.nav.find(a => a.dataset.nav === 'addresses').attributes['aria-current'], 'page');
  doc.getElementById('global-search').value = '143'; await doc.getElementById('search-form').fire('submit');
  assert.equal(location.hash, '#/block/143');
  doc.getElementById('global-search').value = 'studio'; await doc.getElementById('search-form').fire('submit');
  assert.match(location.hash, /address\//);
  doc.getElementById('global-search').value = 'unknown'; await doc.getElementById('search-form').fire('submit');
  assert.match(main.innerHTML, /No matching fixture records/);
  app.navigate('transactions');
  doc.getElementById('filter-input').value = 'raven'; await doc.getElementById('filter-form').fire('submit');
  assert.equal(location.hash, '#/transactions?q=raven');
  assert.ok(!main.innerHTML.includes('Grant: atlas'));
  app.navigate('blocks', '', { page: 2 });
  assert.match(main.innerHTML, /11–20 of 24/);
  app.navigate('blocks', '', { page: 3 });
  assert.match(main.innerHTML, /21–24 of 24/);
  app.navigate('transaction', tx.native_txid);
  await main.querySelectorAll('[data-copy]')[0].fire('click');
  assert.equal(setup.copied, tx.native_txid); assert.equal(doc.getElementById('toast').textContent, 'Copied to clipboard');
  navigator.clipboard.writeText = async () => { throw Error('unavailable'); };
  await main.querySelectorAll('[data-copy]')[0].fire('click');
  assert.match(doc.getElementById('toast').textContent, /Copy unavailable/);
  doc.getElementById('data-mode').value = 'live'; await doc.getElementById('data-mode').fire('change');
  assert.match(main.innerHTML, /Live ledger unavailable/);
  assert.ok(!main.innerHTML.includes(tx.native_txid));
  doc.getElementById('global-search').value = '143'; await doc.getElementById('search-form').fire('submit');
  assert.equal(location.hash, '#/search?q=143'); assert.match(main.innerHTML, /Live ledger unavailable/);
  await main.querySelectorAll('[data-mode]')[0].fire('click');
  assert.equal(doc.getElementById('data-mode').value, 'fixture');
  assert.match(main.innerHTML, /Block #143/);
  assert.equal(env.storage.get('1soft-explorer-mode'), 'fixture');
  assert.equal(env.requests.length, 1); assert.equal(env.requests[0].url, './fixture.json');
  const event = { key: '/', target: { tagName: 'BODY' }, preventDefault() { this.prevented = true; } };
  doc.handlers.keydown[0](event); assert.ok(event.prevented); assert.ok(doc.getElementById('global-search').focused);
});

test('fixture load failure shows unavailable state with a working retry control', async () => {
  const env = setup({ failure: true });
  await import('../dist/app.js?failed');
  assert.match(doc.getElementById('content').innerHTML, /Explorer data unavailable/);
  assert.ok(!doc.getElementById('content').innerHTML.includes('<table>'));
  await doc.getElementById('reload').fire('click'); assert.ok(env.reload());
});

test('an invalid or mislabeled fixture cannot become a ledger display', async () => {
  setup({ invalid: true }); await import('../dist/app.js?invalid');
  assert.match(doc.getElementById('content').innerHTML, /Explorer data unavailable/);
});
