# P4 decision delivery — exact-source verification

29 September 2026. Additive client engineering, not a production release or an
independent security/consensus qualification.

## Source custody

Node base: PR #28 `b73a88ca53666972ae2c8ce35fd9edb7ac0cb41c`, repository tree
`123e5bfc57d42ee31736969f61aa5a6d32482832`. The GitHub PR was rechecked as open,
draft and unmerged at that exact head. Parallel PR #29 concerns node recovery and
is not a dependency, integration or substitute for this client work.

The prior wallet ZIP rehashed to
`31d8adeaa79662e6960270559c6c5aae101bcdce94aa30e139c45a9ba5899e85`.
All 68 listed payload entries matched. Its complete 15-file P4 read client and
11-file P4 wallet remain unchanged. These are the delivered local add-ons, not a
claim that GitHub already includes them on PR #28.

The available earlier full source was PR #26. Its runtime was reconciled to the
exact PR #28 versions: all 29 native runtime files reproduce published src subtree
`7eca75793b8f083216fdfa4a64102c0555713357`. Including requirements and the
unchanged dynamic-header helper/wrapper, all 32 native dependencies match their
pins. All 58 dependency entries (32 native plus the 26 prior client files) match
before and after the final delivery test run. The new code manifest covers seven
executable/test Python files; the delivery manifest covers documentation as well.

This is NOT a full PR #28 checkout. Newer non-runtime node runners/tests and the
full root inventory were not reconstructed, replaced or represented as current.
The full 1,622-case PR #28 release profile was NOT run. Selected unchanged inherited
regressions were checked against their exact prior source bytes. No old test was
removed from a root manifest to manufacture a complete release result.

The package includes all three add-ons and a clearly labelled 32-file test
dependency slice. The slice allows isolated component tests with already-installed
pinned dependencies; it is not a node distribution. Do not copy it over a repository
or deploy it. The combined additive patch is for the real published PR #28 checkout.

## Completed tests

| Scope | Distinct cases |
|---|---:|
| New P4 delivery, transport, process and CLI | 65 |
| Unchanged P4 wallet recheck | 76 |
| Unchanged P4 read-client recheck | 97 |
| Existing certified-wallet/obligation/budget | 114 |
| Existing certificate/compact-proof/local-retention | 154 |
| **Total across these completed profiles** | **506** |
| Separate JavaScript reference | 30 |

All 506 successful test IDs are distinct even without a suite prefix. The completed
profiles have zero failures, errors or skips; the new and prior client checkers also
require zero expected failures/unexpected successes. The 65 new cases are included
in 506, not added again. These were separately scoped local executions against the
same unchanged dependencies, not a whole-node release profile. Original JSON/logs
are retained in evidence/. Python 3.13.5, cryptography 46.0.4, protobuf 6.33.6 and
Node v22 were used; the Python dependencies match the existing pins.

The new cases cover exact reviewed context, wrong payer/grant, invalid/revoked/expired
transfers before HTTP, fixed policy expiry, pending account/budget deficits, literal
loopback restrictions, wallet/database sidecar disjointness, unknown configuration,
corrupt saved records, exact response hash and numeric code checks, one durable
attempt, concurrent dispatchers, no writer lock held during HTTP, private output,
failed response persistence, exact positive receipt verification and separate wallet
reconciliation. Missing evidence and a node admission reply never release a hold.
No-op receipt imports also check policy expiry before returning.

Four actual child-process tests terminate: before attempt COMMIT; after attempt
COMMIT before HTTP; after HTTP submission before response persistence; and after
wallet reconciliation COMMIT before returning. Reopening preserves the appropriate
old/new state. The attempt-before-I/O case intentionally remains consumed despite
zero submissions. A later automatic resend is refused. These are local process
exits, not hardware power loss, P4 engine Commit-acknowledgment tests or hostile
filesystem qualification.

One test deliberately creates another delivery journal and submits the same signed
bytes again. The native replay guard prevents a second execution/debit, but a second
HTTP submission occurs. This documents the local coordination limit: this is not
globally exactly-once delivery and copied/unrelated journals are not coordinated.

## Executed end-to-end example

Actual local P4 monetary and administrative execution creates a budget and two
grants. Raven signs58+fee2; Atlas39+fee2 refuses,38+fee2 fits. Fixture vault files
are removed before all delivery; key loading is prohibited during the remainder.

| Checkpoint | Wallet pending | Wallet recorded budget spend | Source spend |
|---|---:|---:|---:|
| Both signed | 100 | 0 | 0 |
| Raven receipt collected | 100 | 0 | 60 |
| Raven reconciled | 40 | 60 | 60 |
| Complete validator replacement | 40 | 60 | 60 |
| Atlas receipt collected | 40 | 60 | 100 |
| Both reconciled | 0 | 100 | 100 |

There are exactly two original signed-byte submissions. The first loopback fixture
executes the transfer and then closes TCP before returning its response. Reopened
receipt recovery reads only; it never resends. The second payment uses the original
signature after every validator is replaced, and its normal acknowledgment still
leaves wallet state unchanged until explicit reconciliation. Final payer balance894
includes six setup units and100 total fee-inclusive payment debits.

An older already-recorded receipt is recognized without checkpoint rollback or
releasing a hold twice. Both original proof exports remain available for historical
inspection after expiry and source shutdown. No current authority is renewed.

Committee headers are synthetic signatures over the actual P4 application state.
The fixture's reply-drop occurs after local execution, NOT after a real engine's
CheckTx admission. No CometBFT process ran. The forthcoming engine gate must observe
its own exact CheckTx/commit timing; the demonstration does not substitute for it.
Demo files contain public genesis, policy, proofs and signed wires, not private
keys, passphrases, databases or node homes. Fixture keys must never hold value.

## Negative controls and initial history

Four disposable weakened source copies were rejected by assertion failures: omitted
exact-review comparison; treating node acknowledgment as execution; synchronizing
wallet state during receipt collection; and ignoring the selected payer/grant.
Their selected tests, return codes and logs are retained separately; mutated source
is not included in the product. These are same-author controls, not external review.

The first combined shell test invocation exceeded the tool's45-second limit and
has an incomplete log only. It is excluded from all passing counts. A later
completed59-case development run passed58 and had one test-fixture clock error:
a real CLI sync recorded wall-clock time, then its parent fixture tried to read
with an earlier frozen clock. The existing wallet correctly refused that rollback.
The test fixture was updated to current time; production clock validation was not
changed. Six additional guards then brought the final passing suite to65. Both
initial logs and the development result remain available and are not relabelled.

## Publication and remaining qualification

The connector exposed read actions and no source-write action during this turn.
No new remote branch/PR, comment, merge or force-push was created. A direct source
fetch attempt encountered DNS failure; no successful network publication is implied.
The source is delivered as exact additive patches with source and package inventories.
Final fresh-extraction checks are in the separately delivered package-check JSON;
repeated tests are not extra unique cases.

The Windows-only PR #28 raw engine-evidence ZIP is still not an attached input to
this work. Its reported tests stay bound to their original source and are not
claimed as new client results. No official-Go oracle, real changing-validator
acceptance, full P4 release run, independent-host operation, P4 bootstrap/Commit-crash
qualification, external security audit or custody assessment was performed here.

One attempted submission per decision may leave a never-transmitted payment held
indefinitely. No retry/rearm/cancel/reset or absence-based hold release is supplied.
Key lifecycle, consumer UI, multiple-device coordination, production throughput,
complete storage bounds, governance/custody/economics and value-bearing launch remain
separate work. No Actions, paid/public compute, public deployment, real funds,
production keys, DNS/site changes or Resident/Luna/Psyche work occurred.
