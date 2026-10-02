#!/usr/bin/env python3
"""Optional authored-HTML rendering checks, not deployed navigation or consensus."""
import argparse
import json
from pathlib import Path
import shutil
from playwright.sync_api import sync_playwright


def main():
    p=argparse.ArgumentParser();p.add_argument('--html',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True);p.add_argument('--browser',default=shutil.which('chromium'))
    a=p.parse_args();a.output.mkdir(parents=True,exist_ok=True);checks=[];errors=[];requests=[]
    def checked(name,ok):
        checks.append({'name':name,'passed':bool(ok)})
        if not ok:raise AssertionError(name)
    with sync_playwright() as play:
        browser=play.chromium.launch(executable_path=a.browser,headless=True,args=['--no-sandbox'])
        page=browser.new_page(viewport={'width':1440,'height':1100},device_scale_factor=1)
        page.on('pageerror',lambda e:errors.append(str(e)));page.on('request',lambda r:requests.append(r.url))
        # This environment prohibits file navigation. Rendering only the HTML we
        # authored needs no navigation, filesystem access in the browser or network.
        page.set_content(a.html.read_text(),wait_until='load')
        checked('overview and source data rendered',page.locator('h1').inner_text()=='Network overview' and page.locator('tbody tr').count()==5)
        checked('fixture attribution visible','synthetic' in page.locator('#notice').inner_text())
        page.screenshot(path=str(a.output/'desktop.png'),full_page=True)
        page.locator('nav [data-tab="transactions"]').click();checked('transaction pagination first page',page.locator('tbody tr').count()==20)
        page.locator('[data-page="1"]').click();checked('transaction pagination next page',page.locator('tbody tr').count()==4)
        page.locator('[data-kind="transaction"]').first.click();checked('transaction inspector opens',page.locator('#drawer').is_visible())
        page.keyboard.press('Escape');checked('escape closes inspector',page.locator('#drawer').is_hidden())
        page.locator('#search').fill('raven');checked('search filters agent activity',page.locator('h1').inner_text()=='Search the record' and page.locator('tbody tr').count()==14)
        page.locator('nav [data-tab="budgets"]').click();checked('revoked grant remains visible','Revoked' in page.locator('#page').inner_text())
        page.locator('nav [data-tab="validators"]').click();checked('validator status not misrepresented','Live status: not assessed' in page.locator('#page').inner_text())
        page.locator('nav [data-tab="overview"]').click();page.set_viewport_size({'width':390,'height':844})
        checked('mobile document does not overflow',not page.evaluate('document.documentElement.scrollWidth>innerWidth'))
        page.screenshot(path=str(a.output/'mobile.png'),full_page=True)
        checked('no JavaScript runtime errors',not errors);checked('no remote resource requests',not requests)
        browser.close()
    report={'scope':'authored HTML loaded in memory; file navigation blocked; not deployed browser verification','checks':checks,'errors':errors,'network_requests':requests,'passed':all(c['passed'] for c in checks)}
    (a.output/'browser.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))

if __name__=='__main__':main()
