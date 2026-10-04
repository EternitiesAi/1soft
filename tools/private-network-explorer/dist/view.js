import { SOURCE, short, formatUnits, routeURL, lookup, selectRows, paginate, relatedTransactions, sourceLink } from './model.js';

export const esc = value => String(value ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const paths = {
  overview: '<rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/>',
  blocks: '<path d="m12 3 9 5v9l-9 5-9-5V8l9-5Z"/><path d="m3 8 9 5 9-5M12 13v9M7.5 5.5l9 5"/>',
  transactions: '<path d="M4 7h16m-4-4 4 4-4 4M20 17H4m4-4-4 4 4 4"/>',
  addresses: '<rect x="3" y="5" width="18" height="15" rx="3"/><path d="M7 5V3m10 2V3M7 16h5"/><circle cx="8.5" cy="11.5" r="1.5"/><path d="M15 10h3m-3 4h3"/>',
  network: '<circle cx="12" cy="5" r="2"/><circle cx="5" cy="18" r="2"/><circle cx="19" cy="18" r="2"/><path d="m11 7-5 9m7-9 5 9M7 18h10"/>',
  search: '<circle cx="10.5" cy="10.5" r="6.5"/><path d="m16 16 5 5"/>',
  lock: '<rect x="5" y="10" width="14" height="11" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/>',
  arrow: '<path d="M5 12h14m-5-5 5 5-5 5"/>',
  copy: '<rect x="8" y="8" width="12" height="12" rx="2"/><path d="M15 8V4H4v11h4"/>',
  clock: '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
  info: '<circle cx="12" cy="12" r="9"/><path d="M12 11v6m0-10v1"/>',
  chevron: '<path d="m9 5 7 7-7 7"/>',
};
export const icon = name => `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${paths[name] || paths.info}</svg>`;
const badge = (text = 'Fixture') => `<span class="badge fixture">${esc(text)}</span>`;
const time = value => { const date = new Date(value); return Number.isNaN(date.getTime()) ? 'Unavailable' : date.toISOString().slice(11, 19) + ' UTC'; };
const date = value => { const d = new Date(value); return Number.isNaN(d.getTime()) ? 'Unavailable' : d.toISOString().slice(0, 10) + ' · ' + time(value); };
const code = value => `<code title="${esc(value)}">${esc(short(value))}</code>`;
const link = (name, id, label, cls = '') => `<a class="${cls}" href="${esc(routeURL(name, id))}">${label}</a>`;
const accountLabel = (data, id) => data.accounts.find(a => a.id === id)?.label || short(id);
const accountLink = (data, id) => link('address', id, `<span>${esc(accountLabel(data, id))}</span><small>${code(id)}</small>`, 'entity-link');
const copy = value => `<button type="button" class="copy-button" data-copy="${esc(value)}" aria-label="Copy ${esc(value)}">${icon('copy')}</button>`;
const fixtureNotice = `<div class="source-notice"><span class="source-dot"></span><div><strong>Illustrative fixture ledger</strong><span>All ledger values below are synthetic. No live node is connected.</span></div><a href="#/network">Data provenance ${icon('arrow')}</a></div>`;
const heading = (title, sub, actions = '') => `<div class="page-heading"><div><div class="eyebrow">1SOFT / LAYER 1 DEVELOPMENT</div><h1>${esc(title)}</h1><p>${esc(sub)}</p></div><div class="heading-actions">${actions}</div></div>`;
const panelHead = (title, sub, action = '') => `<div class="panel-head"><div><h2>${esc(title)}</h2>${sub ? `<p>${esc(sub)}</p>` : ''}</div>${action}</div>`;
const empty = (title, sub, action = '') => `<div class="empty-state"><span class="empty-icon">${icon('search')}</span><h2>${esc(title)}</h2><p>${esc(sub)}</p>${action}</div>`;
const field = (label, value, note = '') => `<div class="field-row"><dt>${esc(label)}</dt><dd>${value}${note ? `<small>${esc(note)}</small>` : ''}</dd></div>`;
const fullHash = value => `<span class="full-hash">${esc(value)}${copy(value)}</span>`;
const table = (headers, rows, message = 'No matching fixture records. Network absence is not established.') => `<div class="table-scroll"><table><thead><tr>${headers.map(h => `<th scope="col">${esc(h)}</th>`).join('')}</tr></thead><tbody>${rows.join('')}</tbody></table>${!rows.length ? `<p class="table-empty">${esc(message)}</p>` : ''}</div>`;

function blockRows(rows) {
  return rows.map(b => `<tr><td>${link('block', b.height, `<span class="block-chip">${icon('blocks')}</span><strong>#${esc(b.height)}</strong>`, 'block-link')}</td><td>${link('block', b.height, code(b.hash), 'hash-link')}</td><td><span class="count-badge">${b.transactions.length}</span></td><td class="time-cell">${time(b.time)}</td></tr>`);
}
function transactionRows(data, rows, compact = false, owner = null) {
  return rows.map(t => `<tr><td>${link('transaction', t.native_txid, `<span class="transfer-icon">${icon('transactions')}</span><span><strong>${code(t.native_txid)}</strong><small>${t.grant_id ? 'Grant: ' + esc(t.grant_id) : 'Owner transfer'}</small></span>`, 'transaction-link')}</td><td>${accountLink(data, owner ? (t.payer === owner ? t.recipient : t.payer) : t.recipient)}</td>${!compact ? `<td>${link('block', t.height, '#' + esc(t.height), 'height-link')}</td>` : ''}<td class="numeric"><strong>${owner ? `<span class="direction ${t.payer === owner ? 'out' : 'in'}">${t.payer === owner ? '−' : '+'}</span>` : ''}${formatUnits(t.units)}</strong><small>atomic units</small></td></tr>`);
}
function pager(route, paged) {
  const nav = page => routeURL(route.name, '', { q: route.query, page });
  return `<div class="pagination"><span>${paged.start}–${paged.end} of ${paged.total} fixture records</span><div>${paged.page > 1 ? `<a class="button small" href="${esc(nav(paged.page - 1))}" aria-label="Previous page">← Previous</a>` : '<button class="button small" disabled>← Previous</button>'}<span class="page-number">${paged.page} / ${paged.pages}</span>${paged.page < paged.pages ? `<a class="button small" href="${esc(nav(paged.page + 1))}" aria-label="Next page">Next →</a>` : '<button class="button small" disabled>Next →</button>'}</div></div>`;
}
function metrics(data) {
  return `<div class="metrics">${[
    ['Latest shown block', '#' + data.blocks.at(-1).height, 'Within this fixture', 'blocks'],
    ['Native transfers', String(data.transactions.length), 'Synthetic payment records', 'transactions'],
    ['Ledger addresses', String(data.accounts.length), 'Recorded fixture balances', 'addresses'],
    ['Validator roster', String(data.validators.length), 'Illustrative · liveness unknown', 'network'],
  ].map(([label, value, note, type]) => `<a class="metric" href="#/${type}"><div><span>${label}</span>${icon(type)}</div><strong>${value}</strong><small>${note}</small></a>`).join('')}</div>`;
}

function overview(data) {
  const max = Math.max(...data.blocks.map(b => b.transactions.length), 1);
  const count = data.transactions.length;
  const chart = `<div class="activity-summary"><strong>${count}<span>native transfers</span></strong><div>${badge('Synthetic activity')}<span class="chart-period">03 OCT 2026 · UTC</span></div></div><div class="activity-chart" role="group" aria-label="Fixture transfer count per block">${data.blocks.map(b => `<a class="bar-slot" href="${esc(routeURL('block', b.height))}" aria-label="Fixture block ${b.height}, ${b.transactions.length} transfers"><span class="bar bar-${b.transactions.length}"></span><span class="bar-tooltip">#${b.height} · ${b.transactions.length} transfers</span></a>`).join('')}</div><div class="chart-axis"><span>Block ${data.blocks[0].height}</span><span>24 illustrative blocks</span><span>Block ${data.blocks.at(-1).height}</span></div>`;
  return fixtureNotice + heading('Follow the ledger.', 'A clear view of blocks, native payments and the accounts between them.', badge('Development network')) + metrics(data) + `<div class="overview-mid"><section class="panel activity">${panelHead('Ledger activity', 'Transfers by block · fixture data', '<a class="text-link" href="#/blocks">Inspect blocks ↗</a>')}${chart}</section><section class="panel implementation">${panelHead('Built for native payments', 'Current repository capabilities')}<div class="capability"><span>${icon('transactions')}</span><div><strong>Scoped agent spending</strong><p>Grants share a parent budget and signing journal.</p></div></div><div class="capability"><span>${icon('blocks')}</span><div><strong>Recoverable execution evidence</strong><p>Historical payments and exact receipts remain separate from delivery.</p></div></div><div class="connection-note"><span class="source-dot"></span><div><strong>Live network unavailable</strong><span>No approved endpoint or read store connected.</span></div></div><a class="text-link" href="#/network">View implementation & status ${icon('arrow')}</a></section></div><div class="overview-tables"><section class="panel">${panelHead('Latest blocks', 'Illustrative block history', '<a class="text-link" href="#/blocks">View all ↗</a>')}${table(['Block', 'Hash', 'Transfers', 'Time'], blockRows([...data.blocks].reverse().slice(0, 5)))}</section><section class="panel">${panelHead('Latest transfers', 'Native atomic units · no fiat valuation', '<a class="text-link" href="#/transactions">View all ↗</a>')}${table(['Transaction', 'Recipient', 'Amount'], transactionRows(data, [...data.transactions].reverse().slice(0, 5), true))}</section></div><p class="fine-print">Fixture chain: <code>${data.chain_id}</code> · Amounts are integer atomic units. These records do not establish consensus, current balances or payment outcomes.</p>`;
}

function listing(data, route) {
  const names = { blocks: ['Blocks', 'Inspect block identities and their linked native transfers.'], transactions: ['Transactions', 'Inspect native transfer records, recipients, fees and delegated grants.'], addresses: ['Addresses', 'Inspect recorded accounts and the transfers linked to them.'] };
  const [title, sub] = names[route.name];
  const rows = selectRows(data, route.name, route.query), paged = paginate(rows, route.page);
  const heads = route.name === 'blocks' ? ['Block', 'Hash', 'Transfers', 'Time (UTC)'] : route.name === 'transactions' ? ['Transaction', 'Recipient', 'Block', 'Amount'] : ['Address', 'Role', 'Key epoch / nonce', 'Recorded balance'];
  const output = route.name === 'blocks' ? blockRows(paged.rows) : route.name === 'transactions' ? transactionRows(data, paged.rows) : paged.rows.map(a => `<tr><td>${accountLink(data, a.id)}</td><td>${esc(a.kind)}</td><td><code>${a.epoch} / ${a.nonce}</code></td><td class="numeric"><strong>${formatUnits(a.recorded_balance)}</strong><small>atomic units</small></td></tr>`);
  return fixtureNotice + heading(title, sub, badge()) + `<section class="panel list-panel"><div class="list-tools"><span class="record-count">${rows.length} ${title.toLowerCase()}<small>Fixture ledger</small></span><form id="filter-form" data-section="${route.name}"><label class="sr-only" for="filter-input">Filter ${title.toLowerCase()}</label><span>${icon('search')}</span><input id="filter-input" type="search" name="q" value="${esc(route.query)}" placeholder="Filter ${title.toLowerCase()}…" maxlength="200"><button type="submit" class="button small">Filter</button>${route.query ? `<a href="#/${route.name}" class="text-link">Clear</a>` : ''}</form></div>${table(heads, output)}${pager(route, paged)}</section>${route.name === 'addresses' ? '<p class="fine-print">Recorded balances exclude pending wallet reservations and do not establish current spending authority.</p>' : '<p class="fine-print">Every record on this page is synthetic display data. No original proof has been verified.</p>'}`;
}

function detail(data, route) {
  let item, title, sub, fields, related, extra = '', actions = '';
  if (route.name === 'block') {
    item = data.blocks.find(b => b.height === route.id || b.hash === route.id);
    if (item) {
      title = 'Block #' + item.height; sub = 'A synthetic block identity with its linked native transfers.';
      const i = data.blocks.indexOf(item);
      actions = `${i ? link('block', data.blocks[i - 1].height, '← Previous', 'button small') : ''}${i < data.blocks.length - 1 ? link('block', data.blocks[i + 1].height, 'Next →', 'button small') : ''}`;
      fields = field('Block height', '<strong>' + item.height + '</strong>') + field('Block hash', fullHash(item.hash)) + field('Previous block', fullHash(item.previous_hash), i ? 'Previous fixture block is in this view.' : 'Previous fixture hash only; earlier history is not included.') + field('Timestamp', date(item.time)) + field('Native transfers', String(item.transactions.length)) + field('Proposer key', fullHash(item.proposer)) + field('Header AppHash', fullHash(item.app_hash), 'Illustrative state H−1 commitment; this is not a verified hash.') + field('Data origin', badge('Synthetic fixture'), 'No signed headers, validator votes or original proof supplied.');
      related = relatedTransactions(data, 'block', item.height);
    }
  } else if (route.name === 'transaction') {
    item = data.transactions.find(t => t.native_txid === route.id);
    if (item) {
      title = 'Native transfer'; sub = 'Inspect the payer, recipient and exact integer amount shown in this fixture.';
      extra = `<div class="transfer-summary"><div><span>TRANSFER AMOUNT</span><strong>${formatUnits(item.units)}<small>atomic units</small></strong></div><div>${badge('Fixture execution')}<p>No payment outcome established</p></div></div><div class="transfer-parties"><div><span>PAYER</span>${accountLink(data, item.payer)}</div><span class="party-arrow">${icon('arrow')}</span><div><span>RECIPIENT</span>${accountLink(data, item.recipient)}</div></div>`;
      fields = field('Native transaction ID', fullHash(item.native_txid)) + field('Block / index', link('block', item.height, '#' + item.height, 'height-link') + ' / ' + item.index) + field('Timestamp', date(item.time)) + field('Operation', '<code>transfer</code>') + field('Fee', formatUnits(item.fee_units) + ' atomic units') + field('Signing lane nonce', item.nonce, item.grant_id ? 'Grant lane; separate from the owner account nonce.' : 'Owner account lane.') + field('Grant reference', item.grant_id ? '<code>' + esc(item.grant_id) + '</code>' : 'Owner key', 'Fixture role label; it does not identify a live agent or establish permission.') + field('Signed wire hash', fullHash(item.wire_sha256), 'Synthetic identifier; original signed wire is unavailable.') + field('Receipt hash', fullHash(item.receipt_sha256), 'Synthetic identifier; no proof capsule available.');
    }
  } else {
    item = data.accounts.find(a => a.id === route.id);
    if (item) {
      title = item.label; sub = 'An illustrative native account, recorded at fixture block ' + data.blocks.at(-1).height + '.';
      extra = `<div class="account-summary"><div class="account-avatar">${icon('addresses')}</div><div><span>RECORDED FIXTURE BALANCE</span><strong>${formatUnits(item.recorded_balance)}<small>atomic units</small></strong></div>${badge()}</div><p class="balance-note">Pending wallet holds are excluded. A recorded balance is not current spending authority.</p>`;
      fields = field('Account address', fullHash(item.id)) + field('Account role', esc(item.kind)) + field('Owner key epoch', item.epoch, 'Account key epochs are separate from validator epochs.') + field('Owner nonce', item.nonce) + field('Public key', item.public_key ? fullHash(item.public_key) : 'Native fee account · no owner key') + field('Snapshot', '#' + data.blocks.at(-1).height + ' · ' + date(data.snapshot_at)) + field('Data origin', badge('Synthetic fixture'));
      related = relatedTransactions(data, 'address', item.id);
      if (item.id === 'system:fees') extra += '<p class="fine-print">This fixture balance accumulates transfer fees. Fees are not shown as direct recipient transfers.</p>';
    }
  }
  if (!item) return fixtureNotice + heading('Record unavailable', 'The requested record is not included in the fixture ledger.') + empty('No matching fixture record', 'This does not prove a missing block, failed transaction, zero balance or network absence.', '<a href="#/overview" class="button">Return to overview</a>');
  const back = route.name === 'block' ? ['blocks', 'Blocks'] : route.name === 'transaction' ? ['transactions', 'Transactions'] : ['addresses', 'Addresses'];
  return fixtureNotice + `<a class="back-link" href="#/${back[0]}">← ${back[1]}</a>` + heading(title, sub, actions + badge()) + `<section class="panel detail-panel">${extra}<dl>${fields}</dl></section>${related ? `<section class="panel related-panel">${panelHead(route.name === 'block' ? 'Transfers in this block' : 'Linked native transfers', related.length + ' synthetic records')}${table(['Transaction', route.name === 'address' ? 'Counterparty' : 'Recipient', 'Block', 'Amount'], transactionRows(data, related, false, route.name === 'address' ? item.id : null), route.name === 'block' ? 'This fixture block has no transfers.' : 'No direct transfers involving this fixture account.')}</section>` : ''}`;
}

function network(mode, data) {
  const evidence = [
    ['Development chain', 'No public mainnet, value-bearing service or audited production wallet.', 'README.md'],
    ['Consensus implementation', 'Pinned CometBFT 0.38.25; Protocol 4 combines native payments and validator registry state.', 'docs/PROTOCOL4_DEVELOPMENT.md'],
    ['Historical read boundary', 'The P4 explorer verifies original history under external pins. State H is anchored by signed header H+1; latestness and spend permission are separate.', 'tools/protocol4-explorer/README.md'],
    ['Durable local alpha', 'Opt-in fresh genesis with four local validators, bounded 4,096-block history and an original 24-hour trust horizon.', 'docs/DURABLE_ALPHA.md'],
  ];
  return heading('Network & provenance', 'See what is connected, what is illustrated and what the implementation supports.', '<span class="badge neutral">Live state unavailable</span>') + `<div class="network-status"><div><span class="offline-symbol">${icon('network')}</span><div><h2>No live network connected</h2><p>No approved RPC endpoint or authenticated read store was available for this deployment.</p></div></div><span class="badge neutral">Unavailable</span></div><div class="network-metrics">${[['Live block height', 'blocks'], ['Node liveness', 'network'], ['Peer count', 'network'], ['Last observation', 'clock']].map(([label, type]) => `<div><span>${label}${icon(type)}</span><strong>—</strong><small>Unavailable · not zero</small></div>`).join('')}</div><div class="provenance-grid"><section class="panel">${panelHead('Display source', 'Clear boundaries for every record')}<dl>${field('Selected mode', mode === 'fixture' ? badge('Fixture ledger') : '<span class="badge neutral">Live network · unavailable</span>')}${field('Ledger provenance', 'Hand-authored synthetic display data', 'The fixture is shaped around repository primitives, but its values do not come from repository run evidence or a node.')}${field('Fixture snapshot', date(data.snapshot_at), 'A fixed illustrative timestamp, not a last-seen network time.')}${field('Verification', 'No consensus proof verified', 'Hashes, balances and executions are illustrative. Historical or live authority is not inferred.')}${field('Amounts', 'Integer atomic units', 'No decimal scale or fiat price is assigned. DEV is valueless fixture notation.')}</dl></section><section class="panel">${panelHead('Repository evidence', 'Pinned source snapshot · 03 Oct 2026')}<div class="repository-ref"><span class="repo-icon">${icon('blocks')}</span><div><strong>${SOURCE.repository}</strong><code>${SOURCE.commit}</code></div></div><p class="repo-context">Source documentation describes capabilities and boundaries; it is not live telemetry or an independent audit of this deployment.</p><div class="evidence-links">${evidence.map(([label, text, path]) => `<a href="${sourceLink(path)}" target="_blank" rel="noopener noreferrer"><div><strong>${label}</strong><p>${text}</p><small>${path}</small></div><span>↗</span></a>`).join('')}</div></section></div><section class="panel roster-panel">${panelHead('Illustrative validator roster', 'Synthetic keys and voting power. No independent hosts or live participation established.', badge())}${table(['Validator', 'Public key', 'Voting power', 'Host status'], data.validators.map(v => `<tr><td><span class="validator-mark">${icon('network')}</span><strong>${v.label}</strong></td><td>${code(v.public_key)}</td><td>${v.power}</td><td><span class="badge neutral">${v.host_status}</span></td></tr>`))}</section><p class="fine-print">Public operations, economic design, reviewed custody and independent operators remain separate release gates. This private explorer does not qualify the chain for value-bearing use.</p>`;
}

function unavailable(route) {
  const name = ({ overview: 'Network overview', blocks: 'Blocks', transactions: 'Transactions', addresses: 'Addresses', block: 'Block details', transaction: 'Transaction details', address: 'Address details', search: 'Search results' })[route.name] || 'Explorer';
  return heading(name, 'Live network mode', '<span class="badge neutral">Unavailable</span>') + `<section class="panel live-empty"><span class="live-orbit">${icon('network')}</span><span class="eyebrow">AWAITING A LIVE DATA SOURCE</span><h2>Live ledger unavailable.</h2><p>No approved endpoint or authenticated read store is connected.<br>Height, balances, transactions and node health remain unknown.</p><div><button class="button primary" type="button" data-mode="fixture">Explore the fixture ledger ${icon('arrow')}</button><a class="button" href="#/network">View network status</a></div><small>Switching to fixtures is explicit. Fixture records are never presented as live data.</small></section>`;
}

export function renderView(data, mode, route) {
  if (route.name === 'network') return network(mode, data);
  if (route.name === 'not-found') return heading('Page unavailable', 'This route is not part of the explorer.') + empty('Nothing at this route', 'Return to the explorer to inspect the available views.', '<a href="#/overview" class="button">Return to overview</a>');
  if (mode === 'live') return unavailable(route);
  if (route.name === 'overview') return overview(data);
  if (['blocks', 'transactions', 'addresses'].includes(route.name)) return listing(data, route);
  if (['block', 'transaction', 'address'].includes(route.name)) return detail(data, route);
  const results = lookup(data, route.query);
  return fixtureNotice + heading('Search results', route.query ? 'Results for “' + route.query + '” within the fixture ledger.' : 'Enter a block height, hash, account label or address.', badge()) + (results.length ? `<section class="panel search-results">${panelHead(results.length + ' matching records', 'Fixture ledger only')}${results.map(r => `<a href="${esc(routeURL(r.type, r.id))}"><span class="result-icon">${icon(r.type === 'block' ? 'blocks' : r.type === 'address' ? 'addresses' : 'transactions')}</span><div><span class="result-type">${r.type}</span><strong>${esc(r.title)}</strong><code>${esc(r.description)}</code></div>${icon('chevron')}</a>`).join('')}</section>` : empty('No matching fixture records', 'Try a shown block height (120–143), “studio”, or a copied transaction hash. This does not establish absence on a live network.', '<a href="#/overview" class="button">Return to overview</a>'));
}
