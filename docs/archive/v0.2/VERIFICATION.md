# Verification and delivery record

**24 September 2026 — local research package, not production certification.**

## Executed in this session

| Check | Result | Actual scope |
|---|---|---|
| New Python tests | 58 passed, 0 failed | Native signatures, fees, caps, recipient restrictions, nonce/replay behavior, revocation/fencing, deterministic replay, rollback, reopen, competing SQLite writers, fixture reservations, uncertainty, refunds and late/overcapture liabilities. |
| Previous JavaScript prototype tests | 30 passed, 0 failed | Unchanged prior kernel, run again here. Separate implementation; not integrated with the Python core. |
| Browser checks | 20 passed, 0 failed | Five panels at desktop 1440px and mobile 390px; widths, simulated controls, modal behavior, receipt consistency and no external HTTP requests/script errors during tested flows. |
| Native demo | Executed | Three signed native transitions, followed by an old-grant attempt rejected after fencing. Same envelopes on a second local database produce identical state. |
| Settlement demo | Executed | $1,250 fixture funding, $25 held in an unresolved fixture-card intention, $1,225 left available. No real money. |
| Abrupt process-exit test | Passed | A committed transfer survives a child process using `os._exit`. Not a disk power-loss or storage-hardware guarantee. |
| Visual inspection | Performed | Desktop and mobile Overview screenshots reviewed after rendering. |

The native fixture uses a 100 DEV genesis and 6 decimal places. After its grant, transfer and fencing operations, the owner has 87.499700 DEV, the recipient has 12.500000 DEV, and the fee collector has 0.000300 DEV. These are test units, not a supply decision or a valuation.

## Browser limitation recorded, not hidden

Initial `file://` navigation failed with `ERR_BLOCKED_BY_ADMINISTRATOR` in the supplied browser environment. No browser policy was changed. The tests subsequently loaded the already-owned HTML through Playwright `set_content`. Direct file navigation and browser-to-server integration were therefore not established by this run. The preview is self-contained and the exercised UI made no external HTTP requests.

Browser checks are not a comprehensive accessibility, mobile-device, browser-compatibility or penetration audit. Only the listed sizes and flows were tested. Screenshots are visual evidence, not proof that a financial integration exists.

## Not executed or implemented

No distributed consensus, real node network, real coin issuance, real validator set, upstream cryptocurrency build, live reserve verification, banking integration, conversion route, bridge, exchange listing, real payment, agent-runtime adapter, issuer webhook authentication, issued card or independent security audit.

The native core and journal are separate databases. No atomic cross-system integration is claimed. The browser uses embedded demonstration data plus in-memory simulations; it does not call either Python model. The journal trusts fixture callers. Epoch fencing does not implement owner-key rotation or full resident migration. A receipt chain is not tamper-proof against a privileged operator rewriting the environment.

No full cryptocurrency repository audit was performed. Targeted static source excerpts and official product documentation informed the design. The earlier foundation's Docker/Cosmos bootstrap was not run in this continuation. Docker and GitHub CLI were not available in the verified runtime; public source dependency builds were not attempted through an unauthenticated substitute.

## Remote and external state

The connected GitHub request for `xnuonux/layer1-foundation` returned 404. That means the request did not resolve the repository; it does not establish that every possible matching project is absent. The exposed connector did not offer a repository-creation action. Plugin discovery found no additional connected creation route. No remote repository was created or modified.

No existing Eternities/Luna2/canon branch was changed. No public website was deployed. No issuer, bank or payment-network application was submitted. No real card or customer account was opened.

The Agent Finance Watch was successfully scheduled for Monday mornings around 8 a.m. America/Chicago, first run 28 September 2026. It is a research report, not an autonomous financial or deployment action.

## Reproduce and inspect

Run `python scripts/run_tests.py`, `python scripts/run_demo.py`, and optionally `node --test reference/kernel.test.mjs` and `python scripts/check_preview.py`. See README for dependencies. Raw reports are in `evidence/python-tests.txt`, `evidence/previous-kernel-tests.tap`, `evidence/browser-checks.json`, `evidence/demo.json` and `evidence/environment.json`.

Tests lower specific implementation uncertainty; they do not establish legal authorization, adequate capitalization, market demand, global safety, unique invention or resistance to every attack. Independent review and a real consensus integration are still required.
