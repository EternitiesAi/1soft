"""Static, self-contained private account report. No JavaScript or remote assets.

The renderer is not a verifier. Only render outputs of read_account for verified
use; a standalone HTML/JSON file can be edited and is never payment authority.
"""
from __future__ import annotations
from datetime import datetime, timezone
from html import escape


def _text(value):
    return escape(str(value), quote=True)


def _num(value):
    return '—' if value is None else _text(f'{value:,}')


def _short(value):
    return _text(value if value is None or len(value) < 35 else value[:19]+'…'+value[-9:])


def render_html(view: dict, *, specimen: bool = False) -> str:
    """No raw interpolation of account identifiers or provider-controlled text."""
    if view.get('schema') != 1 or view.get('kind') != 'verified-historical-account-view':
        raise ValueError('unsupported account view')
    f, o, s = view['funds'], view['observation'], view['state']
    timing = 'Within local observation policy' if o['within_local_time_and_frontier_policy'] else 'Historical view · refresh required'
    blockers = ', '.join(x.replace('_',' ') for x in o['blockers']) or 'No local time or header-progress warning at inspection.'
    badge = ('DEVELOPMENT SPECIMEN · SYNTHETIC COMMITTEE' if specimen else 'PRIVATE ACCOUNT REPORT · HISTORICAL SNAPSHOT')
    stamp = datetime.fromtimestamp(o['observed_at_ns']/1e9, timezone.utc).isoformat(timespec='seconds')
    def table(headers, rows, empty):
        if not rows:
            return '<p class="empty">'+_text(empty)+'</p>'
        return '<div class="table-wrap"><table><thead><tr>'+''.join('<th>'+_text(h)+'</th>' for h in headers)+'</tr></thead><tbody>'+''.join('<tr>'+''.join('<td>'+v+'</td>' for v in row)+'</tr>' for row in rows)+'</tbody></table></div>'
    budget_rows=[]
    for b in view['budgets']:
        label=b['id'].split('::',1)[-1]
        status='Active at checkpoint' if b['active_at_next_height'] else ', '.join(b['inactive_reasons']).replace('_',' ')
        budget_rows.append([_text(label),_num(b['cap_units']),_num(b['recorded_spent_units']),_num(b['pending_debit_units']),_num(b['uncommitted_allowance_units']),_text(status)])
    grant_rows=[]
    for g in view['grants']:
        grant_rows.append([_text(g['id'].split('::',1)[-1]),_text(g['budget_id'].split('::',1)[-1] if g['budget_id'] else 'Individual grant'),_num(g['uncommitted_allowance_units']),_num(g['shared_budget_headroom_units']),_num(g['effective_next_debit_ceiling_units'])])
    decision_rows=[]
    for d in view['decisions']:
        decision_rows.append([_short(d['decision_id']),_text(d['grant_id'] or 'Account key'),_text(d['status'].replace('_',' ')),_num(d['debit_units']),_num(d['valid_until'])])
    history_rows=[]
    for h in view['history']:
        delta=h['delta_units'];shown=('+' if delta>0 else '')+f'{delta:,}'
        history_rows.append([_num(h['height']),_text(h['operation'].replace('_',' ')),_short(h['counterparty'] or 'Account administration'),_text(shown),_short(h['native_txid'])])
    def coverage(name):
        return f"Showing {len(view[name])} of {view['coverage']['total_items'][name]}. Totals use the complete verified inventory."
    return f'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<meta name="referrer" content="no-referrer"><title>1soft — Private account statement</title>
<style>
:root{{--paper:#f4f1e9;--ink:#252627;--muted:#656660;--line:#d8d6ce;--accent:#672e37;--card:#fcfbf6}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--paper);color:var(--ink);font:15px/1.6 ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}}
.shell{{max-width:1180px;margin:auto;padding:40px 44px 70px}}header{{display:flex;justify-content:space-between;align-items:center;border-bottom:1px solid var(--line);padding-bottom:22px;gap:20px}}
.wordmark{{font-size:29px;letter-spacing:-1.5px;font-weight:750}}.seal{{border:1px solid var(--ink);display:inline-grid;place-items:center;border-radius:50%;width:42px;height:42px;margin-right:12px;font-family:Georgia,serif;font-weight:400;vertical-align:middle}}
.eyebrow{{text-transform:uppercase;letter-spacing:.15em;font-size:10px;font-weight:650;color:var(--muted)}}.badge{{text-align:right;max-width:340px}}h1{{font:400 clamp(38px,6vw,65px)/1.06 Georgia,serif;letter-spacing:-2px;margin:26px 0 16px}}h2{{font:400 26px/1.25 Georgia,serif;margin:0 0 6px}}p{{margin:8px 0}}.lead{{max-width:700px;color:var(--muted);font-size:16px}}.hero{{padding:42px 0 30px}}
.identity{{margin-top:18px;font:11px/1.8 ui-monospace,SFMono-Regular,Consolas,monospace;color:var(--muted);overflow-wrap:anywhere}}
.funds{{display:grid;grid-template-columns:1fr 1fr 1fr;border:1px solid var(--line);background:var(--card)}}.fund{{padding:25px 26px;min-width:0}}.fund+.fund{{border-left:1px solid var(--line)}}.fund strong{{font-size:43px;line-height:1.25;font-weight:500;letter-spacing:-1.8px;display:block;margin:10px 0 9px;font-variant-numeric:tabular-nums;overflow-wrap:anywhere}}.fund.primary{{background:var(--accent);color:#fff8ef}}.fund.primary .eyebrow,.fund.primary small{{color:#e7d2ce}}small{{font-size:12px;color:var(--muted)}}
.notice{{border-left:3px solid var(--accent);padding:9px 17px;margin:22px 0 33px}}.notice p{{font-size:13px;color:var(--muted)}}.notice strong{{font-size:14px;font-weight:600}}
section{{margin-top:34px;padding-top:28px;border-top:1px solid var(--line)}}.section-head{{display:flex;justify-content:space-between;gap:18px;align-items:baseline}}.caption{{color:var(--muted);font-size:12px;max-width:740px}}.table-wrap{{overflow:auto;margin-top:18px}}table{{border-collapse:collapse;width:100%;font-size:12px}}th{{color:var(--muted);font-size:10px;letter-spacing:.05em;text-transform:uppercase;font-weight:550;text-align:left;white-space:nowrap}}th,td{{padding:13px 10px;border-bottom:1px solid var(--line);vertical-align:top}}th:first-child,td:first-child{{padding-left:0}}td{{font-variant-numeric:tabular-nums}}td:nth-last-child(1){{overflow-wrap:anywhere}}.empty{{padding:24px;background:var(--card);color:var(--muted);font-size:13px}}.two{{display:grid;grid-template-columns:1fr 1fr;gap:30px}}dl{{font-size:12px}}dt{{color:var(--muted);margin-top:10px}}dd{{margin:2px 0 0;overflow-wrap:anywhere;font-family:ui-monospace,SFMono-Regular,Consolas,monospace}}footer{{margin-top:38px;padding-top:24px;border-top:1px solid var(--line);font-size:11px;color:var(--muted)}}.balance-note{{margin-top:12px;color:var(--muted);font-size:12px}}a{{color:inherit}}
@media(max-width:700px){{.shell{{padding:23px 20px 40px}}header{{align-items:flex-start}}.badge{{max-width:150px;font-size:8px}}.hero{{padding-top:25px}}h1{{letter-spacing:-1px}}.funds{{grid-template-columns:1fr}}.fund{{padding:19px 22px}}.fund+.fund{{border-left:0;border-top:1px solid var(--line)}}.fund strong{{font-size:36px}}.two{{grid-template-columns:1fr;gap:0}}.section-head{{display:block}}.table-wrap{{max-width:100%}}}}
@media print{{body{{background:white}}.shell{{padding:15px}}.table-wrap{{overflow:visible}}section{{break-inside:avoid}}}}
</style></head><body><main class="shell">
<header><div class="wordmark"><span class="seal">1</span>1soft</div><div class="eyebrow badge">{_text(badge)}</div></header>
<div class="hero"><div class="eyebrow">Account / Verified state</div><h1>Every balance.<br>Every obligation.</h1><p class="lead">Recorded money and signed commitments, viewed together. This report inspects your wallet; it cannot move funds.</p><div class="identity">{_text(view['account'])}<br>{_text(view['asset'])} · {_text(view['units'])} · state {_num(s['application_height'])}</div></div>
<div class="funds"><div class="fund primary"><div class="eyebrow">Recorded balance</div><strong>{_num(f['recorded_balance_units'])}</strong><small>At verified state {_num(s['application_height'])}</small></div><div class="fund"><div class="eyebrow">Pending signed debits</div><strong>{_num(f['pending_debit_units'])}</strong><small>Includes native fees; not a second balance</small></div><div class="fund"><div class="eyebrow">Uncommitted headroom</div><strong>{_num(f['uncommitted_headroom_units'])}</strong><small>Historical estimate · not spending permission</small></div></div>
<p class="balance-note">Balance reconciles to genesis allocation {_num(f['genesis_allocation_units'])} plus recorded net change {_num(f['net_recorded_change_units'])}. Uncovered pending debit: {_num(f['overcommitted_units'])}.</p>
<div class="notice"><strong>{_text(timing)}</strong><p>{_text(blockers)} A newer chain state or another signer may change these figures. No claim of latest state, dollar backing or production readiness.</p></div>
<section><div class="section-head"><h2>Shared budgets</h2><span class="eyebrow">One allowance, multiple workers</span></div><p class="caption">Individual grant ceilings do not multiply the parent allowance. Expired or revoked permissions do not erase historical spending.</p>{table(['Budget','Cap','Recorded spend','Pending','Headroom','Permission'],budget_rows,'No shared native budgets at this checkpoint.')}<p class="caption">{_text(coverage('budgets'))}</p></section>
<section><h2>Agent permissions</h2><p class="caption">The effective debit ceiling includes fees and is the minimum of account, grant and shared-budget headroom. It is not transaction approval; a dash means the observation needs refresh.</p>{table(['Grant','Parent budget','Own headroom','Shared headroom','Effective ceiling'],grant_rows,'No native agent grants at this checkpoint.')}<p class="caption">{_text(coverage('grants'))}</p></section>
<section><h2>Local signed commitments</h2><p class="caption">Pending does not mean broadcast. Recorded means an exact receipt exists in the verified state. Consent alone is not a payment.</p>{table(['Decision','Authority','State','Debit incl. fee','Valid through'],decision_rows,'No signed decisions for this account in the selected journal.')}<p class="caption">{_text(coverage('decisions'))}</p></section>
<section><h2>Recorded activity</h2><p class="caption">Native execution receipts only. External banks, cards and other cryptocurrencies are not represented.</p>{table(['Height','Operation','Counterparty','Net change','Native transaction'],history_rows,'No native execution receipts for this account at the checkpoint.')}<p class="caption">{_text(coverage('history'))}</p></section>
<section class="two"><div><h2>Evidence checkpoint</h2><dl><dt>Application / state header / observed header heights</dt><dd>{_num(s['application_height'])} / {_num(s['witness_header_height'])} / {_num(s['verified_header_height'])}</dd><dt>Application commitment</dt><dd>{_text(s['app_hash'])}</dd><dt>Observation time (UTC)</dt><dd>{_text(stamp)}</dd></dl></div><div><h2>Inspection, not authority</h2><p class="caption">Read-only database access. No key unlock, signature creation, reservation change, network query or broadcast. An exported report is private account data and can be edited; it is not a portable cryptographic proof.</p><dl><dt>View checksum (integrity identifier, not a signature)</dt><dd>{_text(view['view_sha256'])}</dd></dl></div></section>
<footer>1soft · development account tooling. The source wallet remains authoritative for local obligations. Keep this report private. {_text('All displayed subjects, units and committee signatures are test fixtures.' if specimen else 'This is a point-in-time statement, not a live account session.')}</footer>
</main></body></html>'''
