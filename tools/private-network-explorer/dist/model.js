export const SOURCE = Object.freeze({ repository: 'EternitiesAi/1soft', commit: '19842665496ac677b5f6f78b7c3dd7a06baa16fd', observed: '2026-10-03', engine: 'CometBFT 0.38.25' });
export const PAGE_SIZE = 10;
export const formatUnits = value => value == null ? 'Unavailable' : String(value).replace(/\B(?=(\d{3})+(?!\d))/g, ',');
export const short = (value, length = 8) => String(value).length > length * 2 + 3 ? String(value).slice(0, length) + '…' + String(value).slice(-length) : String(value);
export function parseRoute(hash) {
  try {
    const raw = (hash || '#/overview').replace(/^#\/?/, '');
    const [path, query = ''] = raw.split('?');
    const parts = path.split('/').map(decodeURIComponent);
    const allowed = ['overview', 'blocks', 'transactions', 'addresses', 'network', 'block', 'transaction', 'address', 'search'];
    const params = new URLSearchParams(query);
    return { name: allowed.includes(parts[0]) ? parts[0] : 'not-found', id: parts[1] || '', query: params.get('q') || '', page: Math.max(1, Math.min(100000, Number.parseInt(params.get('page') || '1', 10) || 1)) };
  } catch { return { name: 'not-found', id: '', query: '', page: 1 }; }
}
export function routeURL(name, id = '', params = {}) {
  const search = new URLSearchParams(Object.entries(params).filter(([, value]) => value !== '' && value != null));
  return '#/' + name + (id ? '/' + encodeURIComponent(id) : '') + (search.size ? '?' + search.toString() : '');
}
export function lookup(data, query) {
  const q = query.trim().toLowerCase();
  if (!data || !q) return [];
  if (/^#?\d{1,12}$/.test(q)) {
    const height = q.replace(/^#/, '').replace(/^0+(?=\d)/, '');
    const block = data.blocks.find(b => b.height === height);
    return block ? [{ type: 'block', id: block.height, title: 'Block #' + block.height, description: block.hash }] : [];
  }
  const matches = [];
  for (const block of data.blocks) if (q === block.height || block.hash.toLowerCase().includes(q)) matches.push({ type: 'block', id: block.height, title: 'Block #' + block.height, description: block.hash });
  for (const tx of data.transactions) if ([tx.native_txid, tx.wire_sha256].some(x => x.toLowerCase().includes(q))) matches.push({ type: 'transaction', id: tx.native_txid, title: 'Native transfer · ' + formatUnits(tx.units) + ' units', description: tx.native_txid });
  for (const account of data.accounts) if ([account.id, account.label].some(x => x.toLowerCase().includes(q))) matches.push({ type: 'address', id: account.id, title: account.label, description: account.id });
  return matches;
}
export function selectRows(data, name, query = '') {
  const q = query.trim().toLowerCase();
  const rows = name === 'blocks' ? [...data.blocks].reverse() : name === 'transactions' ? [...data.transactions].reverse() : data.accounts;
  return rows.filter(row => !q || Object.values(row).some(value => (typeof value === 'string' || Array.isArray(value)) && String(value).toLowerCase().includes(q)));
}
export function paginate(rows, requestedPage = 1, size = PAGE_SIZE) {
  const pages = Math.max(1, Math.ceil(rows.length / size));
  const page = Math.min(pages, Math.max(1, requestedPage));
  return { rows: rows.slice((page - 1) * size, page * size), page, pages, total: rows.length, start: rows.length ? (page - 1) * size + 1 : 0, end: Math.min(page * size, rows.length) };
}
export function relatedTransactions(data, kind, id) {
  return data.transactions.filter(t => kind === 'block' ? t.height === id : t.payer === id || t.recipient === id).reverse();
}
export const sourceLink = path => 'https://github.com/' + SOURCE.repository + '/blob/' + SOURCE.commit + '/' + path;
