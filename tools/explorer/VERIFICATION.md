# 1soft Explorer verification — 28 September 2026

## Source scope

The exact parent is PR #16, commit 3d4a11f90b540d195d8c0e40b341434333f8110d,
repository tree 6fa6525e73f8ea12a211c5cefd7619c2b739eec4. This add-on changes
nothing in the existing native application, consensus integration, wallet, receipt
archive or root source inventory. PR #11, PR #13 and the incomplete operator kit
are not silently merged or credited as part of this line.

The local dependency checkout was reconstructed from existing conversation source
packages and exact later overlays. 109 of 112 parent required-source entries match;
the unused scripts/run_state_sync.py, tests/test_state_sync.py and
tests/test_state_sync_runner.py do not match the final parent and were not executed
or credited. All 23 native runtime modules, the dependency file and two imported
fixture helpers match (26 files); DEPENDENCIES.json records their exact hashes.
The 14 new executable/test/browser files match SOURCE_MANIFEST.json before and
after the final tests. The portable package is an add-on, not a substitute full
node checkout. The published branch retains the complete parent source.

## Executed final tests

63 distinct new Python tests passed, zero skips/failures/errors. They cover import,
initial external trust pins, exact header continuation, altered evidence, same-height
conflicts, alternate valid quorum subsets for the same block, preservation of
recorded receipts, unknown block bodies, type/size/capacity boundaries, revalidation
of altered materialized views, private file/sidecar boundaries, no wallet reuse,
idempotency, concurrent importers, actual process exits before/after SQLite commit,
and real subprocess CLI import/inspect/export. The fixture amounts include the
maximum supported integer to check exact string/BigInt display plumbing.

Loopback HTTP tests exercise the read-only collector against a local fixture
server, including one captured state, fixed-H+1 retries, missing commitments,
partial collection failures, stale captures, saved-frontier continuation, host and
origin checks, no write routes and no source-node requests from the browser API.
These servers use synthetic signed fixtures, not CometBFT validator processes.

114 existing certified-wallet/obligation/budget tests and 154 existing
certificate/compact-proof/local-retention tests also passed after matching their
source bytes. Across the final runs, that is 331 distinct Python cases. The separate
JavaScript reference passed 30/30. No full native-suite or new real-validator
qualification is claimed. The code has not had an independent security audit.

The first completed explorer suite passed 54 cases, then 61 with CLI coverage.
Subsequent review added two cases: multiple valid quorum-signature subsets for the
same block must not be treated as a fork, and unauthenticated extra block-response
fields must not enter the read model. Both pass in the final 63-case suite. A
scratch smoke command initially had an extra closing parenthesis; this was a
command typo, not a production defect or a counted test failure/pass.

## Native example and saved real-validator evidence

The reproducible demo executes 24 native development transactions through 24
application blocks, including a shared studio budget, Raven/Atlas grants, spending
and Atlas revocation. It imports state12, closes/reopens the index, extends it to
state24, then repeats the update without adding another indexed payment. It shows
five non-system accounts, 2,500,000 DEV atomic units including the fee pool, and
483 units of recorded shared-budget spending. Its anchor is signed header25.
Synthetic committee signatures are explicitly labelled throughout the preview.
There are no private-key files, real funds, AI-agent executions or live validators.

Additionally, four saved certificates from Codex's earlier dd096 return were
independently fed through the new explorer's verifier and indexer. The return ZIP
rehashes to 8395c131a62166dbcf57812b4c07f8a24c77fb118c1b182f71179e7b477576ee.
P1/P2/P3-flat/P3-SMT states at heights13/18/21/20 import with their exact AppHashes,
4/10/7/7 recorded native transactions and corresponding accounts. The saved packet
set does not supply the contiguous nearby block bodies needed for explorer body
coverage, so those imports correctly show zero indexed block bodies, not empty
blocks or failed payments. These are OFFLINE certificate imports, not observations
of another validator run, binary build, live quorum or network freshness.

## Browser checks

Twelve authored-HTML checks passed in installed Chromium: overview data, visible
fixture attribution, transaction pagination, detail inspection, Escape handling,
search, revoked grants, validator-liveness qualification, mobile page width,
no JavaScript runtime errors and zero network asset requests. Desktop1440px and
mobile390px screenshots were inspected; mobile chart/button sizing and table
truncation were adjusted so the key fields fit their containers.

The default Playwright browser executable was absent. The installed system Chromium
was used. Browser policy blocked navigation to local file URLs; no policy was
changed. The authored HTML was loaded in memory with set_content for rendering and
interaction checks. That is not a claim of deployed-browser navigation, reload/API
browser integration, production accessibility certification or public availability.
The local HTTP server/API is independently exercised by the Python integration
cases. Optional check_browser.py requires Playwright/Chromium already installed.

## Remaining limits

Current static-genesis verifier assumptions, complete native receipt history,
bounded full-state imports, trusted local filesystem and source pins remain. The
index has finite capacity and revalidates full evidence; it is not a high-throughput
streaming indexer. Missing records do not prove nonexecution. The UI is presentation,
not a browser light client, signing authority or standalone cryptographic proof.
Actual validator-driven collection/restart, independent hosts, state pruning,
upgrades, production custody, economics and value-bearing release remain unassessed.
No Actions, paid resources, DNS/site work, deployment, funds or merges occurred.
