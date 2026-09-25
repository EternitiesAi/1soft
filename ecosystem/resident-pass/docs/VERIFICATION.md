# Resident Pass v0.1 — observed verification

This checkpoint is an isolated add-on to the 1soft project, not a new full native
release. All executed checks used local fixtures, no hosted Actions, no live Luna
state, no actual Residents and no real funds. No DNS or deployed Worker was changed.

| Gate | Observed result | Scope |
|---|---|---|
| Parent native-v0.13 archive | 609 manifest entries matched | Existing local baseline, not new consensus evidence |
| Standalone identity suite | 46 passed | Issuer scope, signatures, fresh status, challenges, epochs and local recovery |
| Add-on including native bridge | 61 passed, zero skips/failures/errors | 46 identity + 15 native-association cases |
| Parent required-source inventory | 79 files matched | No parent source was modified |
| Deliberately weakened controls | 4 assertion failures, all detected | Issuer scope, status freshness, key separation, financial-key signature |
| Authored preview JS under Node WebCrypto | 15 checks passed | Exact script, actual Ed25519 operations, minimal DOM double |
| In-memory browser layout/UI | 24 checks passed | Desktop/mobile, no overflow, navigation, failure when crypto unavailable |
| New live website deployment | Not attempted | Supplied Codex receipt describes the existing public site |
| Real native consensus / protected Resident service | Not executed | No engine, issuer service, live specimen or custody integration |

The 61 includes the 46; Node and browser checks are not extra Python test cases.
The full native 705-case suite was NOT rerun. The optional bridge was exercised
against unchanged complete local v0.13 sources, not the distinct remote-main
wallet. Committee certificates are synthetic fixture signatures over real local
native application states. Identity subjects are invented specimens. No official
Eternities admission credential has been issued.

## What was actually exercised

Identity checks include tampered cards, copied-card failure without the holder
key, fake/untrusted issuer, external issuer scope escalation, audience mismatch,
stale status, time/status rollback, revocation during an open challenge, key
reissue, one-use challenges, two verifier connections, actual abrupt-process exit
and historical receipt recovery. Human membership cannot produce a KYC claim.

The bridge verifies a compact native account proof and two distinct keys, rejects
forged financial/identity signatures, wrong associations, altered Merkle proofs,
forged committee signatures, stale native evidence and checkpoint rollback.
Tests execute native transfers and key rotation locally to show that identity
revocation does not erase or seize the financial account, identity/issuer keys
cannot spend, and financial rotation requires the new controlling key.

## Initial failures retained

The first integration run had one test-fixture error: the test replaced a holder
key without increasing its epoch, and the verifier correctly rejected it before
the intended same-key assertion. The fixture now advances its epoch and uses a
new card ID before checking financial/identity key separation. That initial log
and JSON are retained; it is not described as a production vulnerability.

The first browser launch could not find Playwright's default Chromium package.
The system Chromium was then used. Navigation to an in-memory-routed origin was
blocked by the environment. No alternate navigation or policy bypass was used.
The final layout test loads the authored document with `set_content` at about:blank.
That context has no WebCrypto; the interface correctly refuses a successful
verification. A separate Node run supplies WebCrypto and tests the exact embedded
script's crypto decisions. The split is not a claim of actual HTTPS browser or
Cloudflare deployment validation.

## Evidence files in the complete downloadable package

`tests-initial.log/json` preserve the initial integration fixture failure.
`tests.log/json` contain the final 61-test result and exact successful IDs.
`guards.json` and `guard-*.log` capture four deliberately weakened implementations.
`preview-crypto.json/log` record the exact-script Node WebCrypto checks.
`browser.json/log` and `preview-desktop/mobile.png` record layout/UI checks.
`browser-navigation-blocked.log` records the actual navigation restriction.
`demo-public-fixtures.json` is an issued-and-verified public test fixture, not a
production credential or validator receipt.

A source/zip manifest checks integrity, not independent authorship, code safety,
issuer honesty, custody, consensus correctness or legal standing. Post-packaging
checks are recorded in the companion release-check JSON and must not be counted
as additional distinct tests.
