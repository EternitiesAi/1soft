# P4 transfer wallet — exact-source verification scope

29 September 2026. This is an additive client development result, not full-node,
real-engine, independent-security, custody or value-bearing qualification.

## Exact baseline and dependencies

Base: published draft PR28 at `b73a88ca53666972ae2c8ce35fd9edb7ac0cb41c`, tree
`123e5bfc57d42ee31736969f61aa5a6d32482832`. PR28 metadata was re-read and remained
open/draft/unmerged at that source. The prior P4 read-client archive rehashed to
`097f1a5cad085927f768f3bc212e242e16bf7b86e6f163947569d5afec51a158`; all 53
payload-manifest entries matched. All 15 installed read-client files are unchanged.

The available earlier full source was the PR26 registry package. Its native runtime
was reconciled to all 29 exact PR28 blobs, including the versioned P4 implementation
and legacy rejection guards. These files reproduce the complete PR28 src subtree
`7eca75793b8f083216fdfa4a64102c0555713357`. With requirements and the dynamic-header
primitive/wrapper, 32 native dependency files match the pinned inventory before
and after the final run. The full PR28 checkout was NOT reconstructed: newer
non-runtime P4 runner/test/docs files outside this scope were not installed or
counted as tested. The root manifest was not shortened to conceal that distinction.

The current change adds only tools/protocol4-wallet. It does not replace parent
node, signing, wallet, explorer, archive or registry implementation bytes. The
original read add-on is shipped unchanged as a dependency, not credited as new work.
The complete GitHub comparison from PR26 through PR28 confirmed that the selected
legacy wallet/proof/retention regression modules were unchanged; their original
bytes were checked against the registry package before execution.

## Completed checks

76 distinct new tests passed: 65 wallet/authority/storage/process cases and
11 command-line cases. There are zero skips, failures, errors, expected failures
or unexpected successes, and the discovered and successful IDs reconcile exactly.
Seven executable/test files match the wallet code manifest before and after.

The unchanged P4 read client was rerun separately: 97 passed. Existing certified
wallet, obligation and budget tests: 114 passed. Existing certificate, compact-state
and block-retention tests: 154 passed. That is 441 distinct Python test IDs across
these completed, separately scoped runs. The JavaScript reference passed 30 cases,
with no failure, skip, cancellation or todo. This is NOT PR28's full 1,622-case
release profile. Ancestor test reports were not counted as new executions.

The installed runtime was Python 3.13.5, cryptography 46.0.4 and protobuf 6.33.6.
The two Python dependency versions match the original pinned requirements. The
new code introduces no dependency, custom cryptographic primitive or environment
that downloads packages automatically.

## What those tests exercised

New tests cover exact native fees/limits, shared-budget and account reservations,
explicit signer selection, no owner fallback, changed reviews, changed checkpoint,
wrong password/vault, policy expiry before/during key load, stale state, clock
rollback, frozen caller inputs, one pending transfer per lane, concurrent writers,
exclusive database initialization, sidecar permissions, source-proof integrity,
corrupted stored signatures/reviews, storage capacity, and failed commit.

Exact positive execution receipts retire reservations; missing, expired, revoked
or unobserved transactions do not. A full validator roster replacement preserves
pending obligations, and a new transfer signed afterward executes successfully.
External raw-key spending can produce account or budget deficits; tests retain the
original holds, display the deficit and refuse overcommitting new transfers. These
controls do not coordinate another journal, device or direct signer.

The process cases actually terminate a local child just before wallet COMMIT and
just after committed approval, then reopen and recover the appropriate state. They
are not P4 engine Commit-acknowledgment tests or power-loss certification. The
terminal test uses a real pseudo-terminal and subprocess, verifies the passphrase
is not echoed, signs once, and recovers the original bytes after deleting the
fixture vault. Nonterminal password fallback is refused. A separate failed-output
case verifies the already-committed decision remains recoverable. No test uses
production keys, real funds or payment network submission.

## Integrated demonstration

The local P4 application creates one shared budget and two grants. Setup consumes
six development units, leaving owner balance994. The wallet signs Raven58+fee2,
refuses Atlas39+fee2 before key access, then signs Atlas38+fee2. Pending is100.
The harness executes Raven's original wire together with an administrative action,
then imports the signed proof: pending40, recorded budget spend60. The entire
validator roster changes; pending40 remains. Atlas's original wire then executes
under the new roster: pending0, spend100, owner894. A NEW owner transfer1+fee2 is
reviewed/signed after turnover, executes, and finishes at owner891/pending0.

Three exact signed decisions, six native receipts including setup, and five
checkpoint proofs are retained in the demonstration. The wallet is reopened and
all original signatures are recovered after policy expiry and deletion of fixture
vaults; fresh status/approval remains refused. The source application is closed.

These are actual P4 native transitions and cryptographic signatures with public
fixture seeds and SYNTHETIC committee headers. The test harness directly supplies
transactions to the application. The wallet never contacts or mutates a source node,
and there are zero payment broadcasts. No independent host or CometBFT voting was
executed. Saved fixture policies are time-limited: run the demo again for fresh
fixtures rather than treating old demo proofs as new spending authority.

## Negative controls and build history

Four deliberately weakened disposable wallet copies were rejected by assertion
failures: omitted shared-budget pending debits; ignored exact review context;
retiring an expired payment merely because a receipt was missing; and omitted
payer/role binding during recovery. Their logs are retained separately. These are
same-author negative tests, not an independent adversarial security audit.

Earlier completed development suites had 59, 74 and 75 cases; their results are
retained as history and are not added to the final 76. A shell launcher timed out
while its child test process continued; its separately captured final log/report
was inspected and it is not represented as a successful launcher call. Only the
completed child suite results establish those test outcomes. No production check
or pass condition was weakened to obtain a green result.

## Remaining qualification and publication

No genuine changing-validator engine run, official-Go comparison, full PR28 suite,
P4 bootstrap/Commit-acknowledgment crash drill, independent-host test, external
security audit or production custody review was performed for this add-on.
PR28's reported engine/oracle results remain bound to b73a88c and do not qualify
this wallet. Its Windows-only raw evidence ZIP was not available in this runtime.

The source is delivered as an additive wallet patch and a combined read-client +
wallet patch for PR28. Neither is a complete node archive. No GitHub source write,
PR creation, merge or force-push was performed. The package's separately delivered
check JSON records fresh extraction, exact patch reproduction and post-extraction
retests; repeated tests are not additional unique cases.

A real-engine acceptance run must preserve all current negative gates and exact
source identities. Delivery/retries, absence-based hold retirement, key/grant
lifecycle management, multi-device coordination, scalable state proofs, a consumer
wallet UI, governance/custody/economics and public release remain distinct work.
No Actions, paid/public compute, deployment, DNS/site or Resident/Luna work occurred.
