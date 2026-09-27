# Decision-bound delivery verification — 2026-09-27

## Exact inputs

The attached `1soft-transfer-workflow.zip` matched SHA-256
`a91f238422e89d6fc1d8df10bcf5b4390488d3c0b265882a7fbe621cfabf5148`.
All 240 manifest entries matched; its Git bundle restored all214 tracked files at
commit `1299b1d6d3a0ceaa2d6365f0f4987a59bfc3a2e4`, source tree
`c5e6afbccf2db7f3775f3c4840a7323e9cbed309`.
GitHub reads reconfirmed PR #10 at631dcc3, draft/open/unmerged. A separate checkout
reconstructed its exact `787e791857a0a0e8dc65f057da754614270e8c05` tree for
published-dependency testing, without the local transfer adapter.

All new runtime, CLI, test and documentation paths are under tools/wallet-delivery.
Native, account-view, transfer-flow, signing, reservation, transport, collector,
validator and root source-manifest bytes remain unchanged. The new component
imports published modules; it does not recreate the missing catch-up code.

## Executed scope

The original account/transfer suite passed93 cases before edits. Final delivery
checks cover49 distinct cases, with zero skips/errors/failures across four
completed partitions (12/12/12/13). All exact successful IDs and source-manifest
hashes are retained. This is not a new complete native regression-suite result.
The same49 cases are checked on exact published PR #10 plus the new add-on,
without the locally added transfer files; those reruns are not extra unique cases.

Separately,114 inherited wallet/obligation/budget cases passed. All93 inherited
transport/receipt-collection cases passed across four completed partitions.
The separate JavaScript budget reference passed30 cases. Source inventories are
104 native files,11 local account/transfer files (7 on the published base), and7
new add-on implementation/test/tool files. None of those inventories was reduced
to accommodate missing code.

Four deliberately weakened disposable copies triggered assertion failures for
explicit grant-role binding, route confirmation, separation of receipt vs wallet
status, and fresh preflight checks. The unchanged candidate source was not mutated;
the guard report identifies the exact focused tests and retained logs.

The49 new cases exercise explicit decision/account/grant binding, route consent,
canonical original signature bytes, no owner fallback, no arbitrary envelope
import, wrong journal types, missing files, source expiry/revocation, current-state
rechecking, concurrent dispatch exclusion, correct historical inspection, no key
access, receipt-vs-wallet separation, independent proof export, bounded read-only
recovery, exact-byte replay and explicit schema/overwrite refusal.

They also run real process termination after network execution and after wallet
reconciliation commit. One parameterized case exercises P1/P2/P3/P3-SMT; these
variants are not four extra test methods. Another test deliberately uses a second
transport journal and observes a second submission of the same bytes; it makes
the absence of global submission deduplication explicit.

The complete local demonstration uses the previous transfer prepare/approve API,
then this new decision-bound delivery API. Raven58+2 and Atlas38+2 are signed in
one wallet; Atlas39+2 is refused. The fixture executes each payment, closes the
actual TCP connection before sending its response, and later supplies receipt
proofs. Sessions reopen, read-only collection leaves pending funds unchanged, and
only the existing wallet sync reconciles each hold. Exactly two broadcast requests
occurred, one per original signature. Recorded spend is100 and final balance892.
The statements and independently verified public receipt fixtures are retained.

All new committee signatures are synthetic signatures over real local native
application state. There is NO new actual validator run, public-network result,
production-custody claim or independent security audit. Prior Codex engine results
remain inherited evidence for their exact earlier sources, not for this adapter.

## Incomplete/initial runs

The first34-case new-library run passed. After adding CLI and additional coverage,
an initial combined invocation reached its tool deadline before completion. Two
combined inherited transport invocations also exceeded their tool windows. Their
partial logs are retained and excluded; all stated final totals come only from
completed partition reports with exact unique-ID reconciliation.

The first CLI-specific run had two failures and two errors caused by its fixture
clock being one second AHEAD of actual subprocess time. The wallet correctly
refused clock rollback. Only the fresh-clock test setup was corrected; no
production clock/freshness policy was relaxed. The successful CLI and final49
cases retain the real clock checks, including a separate expiry-during-validation
negative test. All initial and corrected logs remain in the package.

## Publication and delivery

No new GitHub source write was made. Discovery in this session exposed read tools
but no create/commit/branch/comment operations. This is not a report of a new
platform source denial, successful push or changed PR. No previously blocked
source was retried or rerouted.

The companion release-check JSON records the final local commit/tree, patch
applicability, archive digest, exact source-file comparison and fresh tests.
Hash inventories establish byte identity, not authorship, code safety or trust.
The delivery-only patch is additive to exact PR #10; the complete downloadable
source also retains the preceding local transfer adapter. These are clearly
distinguished source scopes, not silently interchangeable remote revisions.

Next acceptance: run this decision-bound adapter on the existing real local
four-validator network using a disposable journal, verify lost-reply recovery and
both wallet/transport states, and retain the source pins and failure results.
Do not deploy or fund it, and do not replace the unchanged native verifier with a
fixture merely to obtain a pass.
