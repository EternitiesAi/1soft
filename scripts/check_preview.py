#!/usr/bin/env python3
"""Browser checks for the offline concept. Requires Playwright and Chromium."""
from pathlib import Path
import json
import os
import shutil
from playwright.sync_api import sync_playwright
root=Path(__file__).resolve().parents[1]
checks=[]
with sync_playwright() as p:
    executable=os.environ.get('CHROMIUM_EXECUTABLE') or shutil.which('chromium') or shutil.which('chromium-browser')
    browser=p.chromium.launch(executable_path=executable,headless=True,args=['--no-sandbox'] if os.environ.get('USER')=='root' else [])
    for label,width,height in [('desktop',1440,1050),('mobile',390,844)]:
        page=browser.new_page(viewport={'width':width,'height':height},device_scale_factor=1)
        errors=[]; external=[]
        page.on('pageerror',lambda exc:errors.append(str(exc)))
        page.on('request',lambda req:external.append(req.url) if req.url.startswith(('http:','https:')) else None)
        page.set_content((root/'web/index.html').read_text(), wait_until='load')
        for tab in ['home','native','agents','assets','card']:
            page.locator(f'#nav-{tab}').click()
            assert page.locator('#'+tab).is_visible()
            assert page.evaluate('document.documentElement.scrollWidth<=window.innerWidth'), (label,tab,'horizontal overflow')
            checks.append({'check':f'{label}:{tab}:render-and-width','passed':True})
        page.locator('#card-toggle').click(); page.locator('#simulate').click()
        assert 'Blocked' in page.locator('#sim-result').inner_text()
        checks.append({'check':f'{label}:paused-card-simulation-blocked','passed':True})
        page.locator('#nav-agents').click();page.locator('#agents [data-modal=policy]').click()
        page.locator('#agent-state').select_option('paused')
        page.locator('#allowance').fill('200');page.locator('#allowance').dispatch_event('input')
        page.locator('#save-policy').click()
        assert page.locator('#agents .raven-budget').inner_text()=='$200.00'
        assert page.locator('#agents .raven-status').inner_text()=='Paused'
        checks.append({'check':f'{label}:policy-dialog-updates-preview','passed':True})
        page.locator('#nav-native').click();page.locator('[data-modal=receipt]').click()
        expected=json.loads((root/'evidence/demo.json').read_text())['native']['receipts'][1]['txid']
        assert page.locator('#txid').inner_text()==expected
        page.keyboard.press('Escape');assert not page.locator('#modal').is_visible()
        checks.append({'check':f'{label}:receipt-matches-executed-fixture','passed':True})
        page.locator('#nav-assets').click();page.locator('[data-modal=route]').click()
        assert 'not an executable quote' in page.locator('#modal-content').inner_text()
        page.keyboard.press('Escape')
        checks.append({'check':f'{label}:route-not-live-disclosure','passed':True})
        assert not errors,errors;assert not external,external
        checks.append({'check':f'{label}:no-script-errors-or-network-requests','passed':True})
        # Screenshots use fresh initial UI state, not the mutations above.
        page.close();page=browser.new_page(viewport={'width':width,'height':height},device_scale_factor=1);page.set_content((root/'web/index.html').read_text(), wait_until='load');page.screenshot(path=str(root/f'evidence/preview-{label}.png'),full_page=True)
        page.locator('#nav-card').click();page.screenshot(path=str(root/f'evidence/card-{label}.png'),full_page=True)
        page.close()
    browser.close()
(root/'evidence/browser-checks.json').write_text(json.dumps({'checks':checks,'passed':len(checks),'failed':0},indent=2)+'\n')
print(f'{len(checks)} browser checks passed')
