# v0.10 verification — read-only receipt collection

September 24, 2026. Local-only development. The intended publication extends PR #2's payment-dispatch branch, not remote main's separate wallet implementation. Domain/DNS setup is left to the owner's separate lane.

## Results actually observed

| Gate | Result | Scope |
|---|---|---|
| Original v0.9 archive | SHA-256 matched; 346 manifest entries checked | Preserved parent, not a new test result. |
| Full local Python tree | 535 cases passed, zero skips/failures/errors | Sixteen bounded processes, complete exact-ID reconciliation. |
| New receipt-collection cases | 37 passed, included in 535 | Actual loopback HTTP and synthetic signed committee fixtures. |
| Separate JavaScript model | 30 passed | Still not a shared native/card budget. |
| Deliberately weakened controls | All four detected by assertion failures | Wrong commitment height, query-height binding, exact receipt hint, pre-read expiry. |
| Full required-source inventory | 61/61 matched | Complete local package, not remote completeness. |
| Real-network runner | Unassessed; no engine steps executed | Engine absent; normal dependency-host DNS still fails here. |
| Actions/cloud/DNS operations | None | No hosted jobs, paid compute or domain changes. |

The new suite tests successful four-read receipt retrieval, explicitly bounded waiting for the same checkpoint's h+1 commitment, missing and altered evidence, invalid RPC framing, wrong transaction data, signatures and network identity, untrusted worker output, denied methods, expiry/clock regression, real process termination, historical proof export and command-line refresh. Missing evidence never becomes a verified failure or a replacement payment.

The initial collection suite passed 33 cases. Four proof-export cases were then added. Combined-suite discovery exposed a naming collision between a newly added CLI gate and the test module; the CLI was renamed before publication. An earlier evidence harness also had an incorrect root path. Both initial failed logs are retained; neither incomplete run is counted as passing. Final source ran through all 535 cases after these fixes.

The old offline/certified wallet, native-ledger and dispatch tests remain in that same 535-case local run. There is no claim of a single-process full-suite pass or of executing the different full remote-main tree. The 37 new cases and repeated subset runs are not additional to 535.

## Evidence and trust limits

Local logs and exact case IDs live under `evidence/v010/`. `test-coverage.json` reconciles all discovered tests once; `guard-regressions.json` identifies the four intentionally weakened variants and assertion failures. `network-attempt/result.json` reports the genuine unassessed gate without a mock fallback. The portable source contains no engine binary or real validator secrets.

The collected certificates are cryptographically signed fixtures, not real consensus output. The collector requires the existing static genesis trust model, trusted local clock/policy and private journal. It is not a general light client, a current-balance query, production custody, authenticated cross-chain settlement or an independent audit. Whole-state receipt witnesses retain size/scaling limitations.

The actual engine runner in the full local package additionally requires read-only client collection from real RPC. That integration code is written but unexecuted. Domain availability cannot establish this consensus result. No earlier platform-blocked ABCI file is uploaded or rerouted by this patch.

Publication head, archive hash, fresh-extraction checks and the remaining source-tree distinction are recorded in RELEASE.json and the companion release-check file after packaging. Those integrity checks do not imply signature-based software provenance or code safety.
