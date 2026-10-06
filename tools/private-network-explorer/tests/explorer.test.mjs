import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { parseRoute, routeURL, lookup, selectRows, paginate, relatedTransactions, formatUnits, sourceLink } from '../dist/model.js';
import { renderView } from '../dist/view.js';

const data = JSON.parse(readFileSync(new URL('../dist/fixture.json', import.meta.url)));
const render = (hash, mode = 'fixture') => renderView(data, mode, parseRoute(hash));
const links = html => [...html.matchAll(/href="(#[^"]+)"/g)].map(m => m[1].replaceAll('&amp;', '&'));

test('every fixture transfer has a real linked fixture block, payer and recipient', () => {
  assert.equal(data.mode, 'fixture');
  assert.match(data.provenance, /synthetic/);
  assert.equal(new Set(data.transactions.map(t => t.native_txid)).size, data.transactions.length);
  for (const t of data.transactions) {
    const block = data.blocks.find(b => b.height === t.height);
    assert.ok(block?.transactions.includes(t.native_txid));
    assert.equal(block.transactions[Number(t.index)], t.native_txid);
    assert.ok(data.accounts.some(a => a.id === t.payer));
    assert.ok(data.accounts.some(a => a.id === t.recipient));
    for (const field of ['units', 'fee_units', 'nonce', 'height', 'index']) assert.match(t[field], /^\d+$/);
  }
});

test('fixture accounting conserves units and includes fees without float arithmetic', () => {
  const balances = Object.fromEntries(data.accounts.map(a => [a.id, BigInt(a.initial_balance)]));
  for (const t of data.transactions) {
    balances[t.payer] -= BigInt(t.units) + BigInt(t.fee_units);
    balances[t.recipient] += BigInt(t.units);
    balances['system:fees'] += BigInt(t.fee_units);
  }
  for (const account of data.accounts) assert.equal(balances[account.id].toString(), account.recorded_balance);
  assert.equal(Object.values(balances).reduce((a, b) => a + b, 0n).toString(), data.supply_units);
  assert.equal(formatUnits('9007199254740991'), '9,007,199,254,740,991');
  assert.equal(formatUnits(null), 'Unavailable');
});

test('height, block hash, native transaction hash, wire hash and account searches resolve', () => {
  for (const b of data.blocks) {
    assert.deepEqual(lookup(data, b.height).map(r => [r.type, r.id]), [['block', b.height]]);
    assert.equal(lookup(data, b.hash.toUpperCase())[0].id, b.height);
  }
  const tx = data.transactions[0];
  assert.equal(lookup(data, '#00143')[0].id, '143');
  assert.equal(lookup(data, tx.native_txid)[0].type, 'transaction');
  assert.equal(lookup(data, tx.wire_sha256)[0].id, tx.native_txid);
  assert.equal(lookup(data, '  STUDIO ')[0].type, 'address');
  assert.equal(lookup(data, data.accounts[0].id)[0].id, data.accounts[0].id);
  assert.deepEqual(lookup(data, 'unknown-record'), []);
  assert.deepEqual(lookup(data, ''), []);
});

test('filtering and pagination cover every row once and clamp invalid pages', () => {
  for (const name of ['blocks', 'transactions', 'addresses']) {
    const rows = selectRows(data, name);
    const first = paginate(rows);
    const walked = [];
    for (let i = 1; i <= first.pages; i++) walked.push(...paginate(rows, i).rows);
    assert.deepEqual(walked, rows);
    assert.equal(paginate(rows, 999).page, first.pages);
    assert.equal(paginate(rows, -4).page, 1);
  }
  assert.equal(selectRows(data, 'addresses', 'studio').length, 1);
  assert.ok(selectRows(data, 'transactions', 'raven').length > 0);
  const empty = paginate([]); assert.equal(empty.total, 0); assert.equal(empty.start, 0);
});

test('routes preserve addresses and search strings, reject malformed paths', () => {
  const address = data.accounts.at(-1).id;
  assert.equal(parseRoute(routeURL('address', address)).id, address);
  assert.equal(parseRoute(routeURL('search', '', { q: '<script>x</script>' })).query, '<script>x</script>');
  assert.equal(parseRoute('#/blocks?page=-9').page, 1);
  assert.equal(parseRoute('#/%broken').name, 'not-found');
  assert.equal(parseRoute('#/no-such-route').name, 'not-found');
  assert.equal(parseRoute('').name, 'overview');
});

test('overview and all detail links resolve to meaningful rendered views', () => {
  const pages = ['#/overview', '#/blocks', '#/transactions', '#/addresses', '#/network'];
  for (const block of data.blocks) pages.push(routeURL('block', block.height));
  for (const tx of data.transactions) pages.push(routeURL('transaction', tx.native_txid));
  for (const account of data.accounts) pages.push(routeURL('address', account.id));
  for (const page of pages) {
    const html = render(page);
    assert.match(html, /fixture|Fixture|synthetic|Synthetic/);
    assert.ok(!html.includes('undefined'));
    for (const href of links(html)) {
      const route = parseRoute(href);
      assert.notEqual(route.name, 'not-found', href);
      if (['block', 'transaction', 'address'].includes(route.name)) assert.ok(!render(href).includes('<h1>Record unavailable</h1>'), href);
    }
  }
});

test('linked block and account transfers are exact', () => {
  const block = data.blocks.find(b => b.transactions.length > 1);
  assert.equal(relatedTransactions(data, 'block', block.height).length, block.transactions.length);
  const account = data.accounts[1];
  assert.equal(relatedTransactions(data, 'address', account.id).length, data.transactions.filter(t => t.payer === account.id || t.recipient === account.id).length);
  assert.match(render(routeURL('address', account.id)), /Pending wallet holds are excluded/);
  assert.match(render(routeURL('transaction', data.transactions[0].native_txid)), /No payment outcome established/);
});

test('live mode never falls back to fixture records or reports unavailable values as zero', () => {
  for (const route of ['#/overview', '#/blocks', '#/transactions', '#/addresses', routeURL('block', '143'), routeURL('transaction', data.transactions[0].native_txid), routeURL('address', data.accounts[0].id), '#/search?q=143']) {
    const html = render(route, 'live');
    assert.match(html, /Live ledger unavailable/);
    assert.match(html, /remain unknown/);
    assert.ok(!html.includes('<table>'));
    for (const t of data.transactions) assert.ok(!html.includes(t.native_txid));
    assert.ok(!html.includes(data.accounts[0].recorded_balance));
  }
  const network = render('#/network', 'live');
  assert.match(network, /Unavailable · not zero/);
  assert.match(network, /Illustrative validator roster/);
  assert.match(network, /No consensus proof verified/);
});

test('unknown records, empty searches and injection-like queries remain safe and honest', () => {
  for (const route of ['#/block/99999', '#/transaction/not-real', '#/address/unknown']) assert.match(render(route), /does not prove a missing block/);
  const query = '<img src=x onerror=alert(1)>';
  const html = render(routeURL('search', '', { q: query }));
  assert.ok(!html.includes(query)); assert.ok(html.includes('&lt;img'));
  assert.match(html, /No matching fixture records/);
  const filter = render(routeURL('transactions', '', { q: '" onclick="attack' }));
  assert.ok(filter.includes('&quot;')); assert.ok(!filter.includes(' onclick="attack'));
});

test('source evidence is pinned and assets have no external network dependency', () => {
  assert.match(sourceLink('README.md'), /19842665496ac677b5f6f78b7c3dd7a06baa16fd\/README.md$/);
  const html = readFileSync(new URL('../dist/index.html', import.meta.url), 'utf8');
  const app = readFileSync(new URL('../dist/app.js', import.meta.url), 'utf8');
  assert.ok(!html.match(/(?:src|href)="https?:/));
  assert.match(app, /fetch\('\.\/fixture.json'/);
  assert.equal((app.match(/fetch\(/g) || []).length, 1);
  assert.ok(!app.includes('broadcast')); assert.ok(!app.includes('sendTransaction'));
  assert.match(html, /Content-Security-Policy/);
  assert.match(html, /noindex, nofollow/);
});
