import { parseRoute, routeURL, lookup } from './model.js';
import { renderView, icon } from './view.js';

const main = document.getElementById('content');
const sourceSelect = document.getElementById('data-mode');
let data = null;
let mode = 'fixture';
let toastTimer;
try { mode = sessionStorage.getItem('1soft-explorer-mode') === 'live' ? 'live' : 'fixture'; } catch {}
sourceSelect.value = mode;
document.querySelectorAll('[data-icon]').forEach(element => { element.innerHTML = icon(element.dataset.icon); });

function notify(message) {
  const toast = document.getElementById('toast');
  clearTimeout(toastTimer); toast.textContent = message; toast.classList.add('visible');
  toastTimer = setTimeout(() => toast.classList.remove('visible'), 2200);
}
export function setMode(value) {
  mode = value === 'live' ? 'live' : 'fixture';
  sourceSelect.value = mode;
  try { sessionStorage.setItem('1soft-explorer-mode', mode); } catch {}
  render();
}
export function navigate(name, id = '', params = {}) {
  const next = routeURL(name, id, params);
  if (location.hash === next) render(); else location.hash = next;
}
function render() {
  if (!data) return;
  const route = parseRoute(location.hash);
  main.innerHTML = renderView(data, mode, route);
  const active = ({ block: 'blocks', transaction: 'transactions', address: 'addresses' })[route.name] || route.name;
  document.querySelectorAll('[data-nav]').forEach(a => { if (a.dataset.nav === active) a.setAttribute('aria-current', 'page'); else a.removeAttribute('aria-current'); });
  document.title = '1soft · ' + ({ block: 'Block ' + route.id, transaction: 'Native transfer', address: 'Address', network: 'Network & provenance', search: 'Search', blocks: 'Blocks', transactions: 'Transactions', addresses: 'Addresses' }[route.name] || 'Network Explorer');
  const filter = document.getElementById('filter-form');
  if (filter) filter.addEventListener('submit', event => { event.preventDefault(); navigate(filter.dataset.section, '', { q: document.getElementById('filter-input').value.trim() }); });
  main.querySelectorAll('[data-mode]').forEach(button => button.addEventListener('click', () => setMode(button.dataset.mode)));
  main.querySelectorAll('[data-copy]').forEach(button => button.addEventListener('click', async () => {
    try { await navigator.clipboard.writeText(button.dataset.copy); notify('Copied to clipboard'); }
    catch { notify('Copy unavailable. Select the displayed value to copy.'); }
  }));
}
sourceSelect.addEventListener('change', () => setMode(sourceSelect.value));
document.getElementById('search-form').addEventListener('submit', event => {
  event.preventDefault();
  const query = document.getElementById('global-search').value.trim();
  if (!query) { notify('Enter a block height, hash or address'); return; }
  const matches = mode === 'fixture' && data ? lookup(data, query) : [];
  if (matches.length === 1) navigate(matches[0].type, matches[0].id); else navigate('search', '', { q: query });
});
document.addEventListener('keydown', event => {
  if (event.key === '/' && !['INPUT', 'TEXTAREA', 'SELECT'].includes(event.target?.tagName) && !event.target?.isContentEditable) { event.preventDefault(); document.getElementById('global-search').focus(); }
});
window.addEventListener('hashchange', () => { render(); window.scrollTo({ top: 0, behavior: 'instant' }); main.focus({ preventScroll: true }); });

try {
  const response = await fetch('./fixture.json', { cache: 'no-store' });
  if (!response.ok) throw new Error('Fixture unavailable');
  data = await response.json();
  if (data.mode !== 'fixture' || data.schema !== 1 || !Array.isArray(data.blocks) || !Array.isArray(data.transactions) || !Array.isArray(data.accounts) || !Array.isArray(data.validators)) throw new Error('Fixture schema invalid');
  render();
} catch {
  main.innerHTML = '<div class="empty-state"><h1>Explorer data unavailable</h1><p>The illustrative ledger could not be loaded. No network state or payment outcome is inferred.</p><button type="button" class="button" id="reload">Retry loading</button></div>';
  document.getElementById('reload').addEventListener('click', () => location.reload());
}
