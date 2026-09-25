# v0.12 verification — shared native agent budgets

September 24, 2026 (America/Chicago). Local, disposable development only.

## Observed results

| Gate | Result | Scope |
|---|---|---|
| Parent v0.11 archive | 461 manifest entries matched | Preserved starting bytes, not a new execution result. |
| Complete local Python suite | 623 passed; zero skips/failures/errors | 16 completed batches with exact unique case-ID reconciliation. |
| New native-budget cases | 54 passed, included in 623 | 36 monetary-rule cases and 18 integration cases. |
| Separate JavaScript reference | 30 passed | Unchanged and separate from native/cash/card accounting. |
| Deliberately weakened controls | 4 caught by assertion failures | Aggregate precheck, pool revocation, state commitment, wallet parent check. |
| Required source inventory | 69 of 69 matched at network check | Complete local source, not complete GitHub import. |
| Actual-engine network command | Unassessed, zero steps | Engine absent; normal module-host DNS lookup failed. |
| Actions, DNS, paid compute, real funds | None | Domain setup remains a separate lane. |

All 623 cases are accounted for in `evidence/v012/test-coverage.json`; the file
contains exact IDs, not merely a test-count claim. The 54 new cases are not added
a second time. A single-process full-suite pass, full remote-main test run,
independent security audit or live-network certificate is not claimed.

## Exercised behavior

Two independently authorized agents share one native budget, including their
transfer fees. Actual spending cannot exceed the aggregate even when both grants
individually permit the payment. Tests include fee boundaries, simultaneous local
writers, ordered block proposals, rejection without partial state changes,
budget/grant revocation, epoch changes, two-sided key rotation, balance shortage,
ownership isolation, permanent labels and recipient/expiry inheritance.

A deterministic randomized test reconciles 150 attempted interleavings with a
separate integer-accounting model. Actual process terminations before and after
application commit exercise budget/grant/balance recovery. Golden vectors captured
before the changes verify protocol-1/2 transaction, receipt, state and application
hash compatibility. A wrong-genesis database reopen is tested for absence of an
unintended protocol-3 schema mutation.

The local certificate-backed wallet verifies and displays both allowance levels,
refuses excess spending before unlocking, and signs an exact payment subsequently
accepted by the native block application. The receipt verifier checks protocol-3
state commitments and exact native receipts. All committee certificates in these
tests are synthetic cryptographic fixtures, not actual validator votes.

## Initial failures preserved

The initial integration run had six errors from a synthetic header helper that
omitted the required prior-block identifier above height one. The fixture was
corrected; the failure log remains. A later full-suite batch exposed an inherited
negative test that still treated protocol 3 as unsupported; it was deliberately
updated to unsupported protocol 4, matching the explicit feature change. The
other unsupported-version checks were updated consistently, without accepting
boolean or malformed versions. The completed replacement batch passes.

Early partial 622-case discovery logs preceded one additional schema-isolation
regression. They are not combined with final coverage. The final sixteen batch
reports each discover the same 623 IDs and cover them exactly once. Moving the
integration module's direct-execution entrypoint below both test classes does not
change discovery; both new modules are rerun after that packaging cleanup.

## Source publication outcome

Observed main: `941c6241d89761f2074c121af29539c354f6cdcd`.
Observed open PR #2 head: `29705061c3cbb8b09ac18001c2b980d3183215a1`.
The complete local archive continues parent `5756dbae1854fb09ec06a7c918c9e6bf38979a09`.
These are different source histories; this archive is not an exact clone of main.

A normal GitHub tree write for the new budget helper succeeded, creating the
unreferenced tree `1f27fc17898d9f0c422010d4befe5b1ee4052c9a`. No commit or branch
points to it. The next normal tree write for the required native-core integration
was blocked by the platform with an indeterminate safety-status message. No tree,
commit or ref was returned by that blocked action. Coordinated source publication
stopped; no encoded, split or alternative-route retry was attempted. Consequently
v0.12 is delivered locally, not as a published or merged feature. Other update
files were not all individually attempted or blocked. Existing remote wallets and
PR source remain untouched by this checkpoint.

## Remaining limits

The real-engine runner now contains a protocol-3 aggregate-spend scenario and
retains the official codec, protocol-1/2 and quorum/recovery requirements. Its new
validator path has not executed. Greater application-test coverage does not
establish distributed consensus, operator independence or live payment finality.

Fresh development genesis is mandatory for protocol 3. Budgets are permission
ceilings, not escrow or balance reservations; owner-signed payments remain outside
agent caps. No supply, fee economics, public issuance, USD backing, banking/card
integration, cross-rail budget, arbitrary subdelegation or production custody was
introduced. Whole-state witnesses, static validator trust and development record
limits remain. The separate remote state wallet requires its own integration and
testing before claiming equivalence with this local certificate-backed wallet.

Final ZIP hash, fresh-extraction inventory, repeated subset tests and bundled
source-history checks are recorded in the companion release-check JSON. These
checks verify delivered bytes, not independent authorship or complete security.
