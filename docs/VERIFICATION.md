# 1soft v0.16 — observed verification

Current integrated checkouts use [current qualification](CURRENT_QUALIFICATION.md).
The dated results below are preserved historical evidence for their original source.

September 25, 2026. Complete local parent: `ff6f085ebde1aeace38e31970e8d8dfa20a52a31`.
Cryptocurrency node only; no Actions, paid compute, DNS/site changes, Resident/Luna/
Psyche changes, real funds, protected custody or public deployment.

| Gate | Observed result | Scope |
|---|---|---|
| Original v0.15 package | SHA-256 matched; 770 manifest entries matched | Preserved parent archive |
| Initial wire/application baseline | 58 passed | Before editing |
| Existing wire/application/execution tests after initial edits | 95 passed | Selected regression run |
| New admission/socket cases | 65 passed | 41 cache/application cases plus 24 framed-I/O/server cases |
| Complete local Python tree | 862 passed; zero skips/failures/errors | 19 completed groups with exact unique-ID reconciliation |
| Selected injected faults | Six caught by assertion failures | Not independent audit |
| Four-application scripted exercises | 39 and 65 checks passed | Real processes and ABCI calls, not validator votes |
| Separate JavaScript budget reference | 30 passed | Not integrated cross-rail accounting |
| Existing second-structure Merkle check | 6 roots / 39 proofs agreed; 39 altered roots rejected | Not consensus evidence |
| Required-source inventory | 95/95 matched | Complete local tree, not remote publication |
| Normal local engine build | Failed before compilation at Go module-host DNS | One actual build step; no engine process |
| Actual-engine acceptance | Unassessed; zero engine steps | Missing pinned executable, no mock fallback |

The 65 new cases are included in 862. Selected reruns and the 39/65 scripted checks
are not extra unique Python cases. The two complete local/remote source lineages
are still distinct. No complete remote-main suite was run in this checkpoint.

## Meaningful tests

Exact signed bytes cannot inherit another signature's result; all checkpoint
dimensions and successful commits invalidate stale answers. Empty-block expiry,
nonce progression, revocation, key rotation, shared budgets, pending-state isolation,
failed commits and cross-thread checks are exercised. Proposal and finalization
execution remain independent of prior admission. Protocol 1/2/3 plus opt-in SMT
state/receipt/proof equivalence ran in the same full suite.

Socket tests use actual Unix sockets. Admission occurs before thread construction,
partial frames have absolute deadlines, non-readers time out, healthy idle channels
survive, malformed clients do not quarantine the app, oversized query responses
fail explicitly, and true internal faults do stop the endpoint. These are private
local transport checks, not public-peer denial-of-service or engine interoperability.

## Measured work, not TPS

`measurement/result.json` contains raw timings after 256 signed native transfers.
For both valid and invalid-signature repetitions: 512 uncached checks made 512
ledger forks; 512 repeated cached checks made one. Valid median: 1.6797765 ms vs
0.028603 ms. Invalid-signature median: 1.2699315 ms vs 0.027952 ms. Answers and state
are identical. A separate 2,048-malformed-input exercise made no ledger forks and
respected the selected 16-entry/4,096-byte cache limits. Retained-payload accounting
is not Python process RSS, and unique valid-looking traffic still consumes work.

## Incomplete/negative runs retained

The interactive execution-session call returned StreamingExecNotEnabledContainerError
and did not run a full suite. Tests were therefore run in bounded processes.
Batch 12's first combined invocation and batch 13's combined and diagnostic attempts
hit tool deadlines; their incomplete logs are retained outside the successful batch
inventory. Batch 12's separate retry passed. Batch 13 was covered by four smaller
completed groups; its partial attempts were not counted. Reconciliation verifies
that all 862 discovered IDs occur exactly once across 19 successful reports.

The first fault-injection run caught five controls by assertion. Its exact-byte
mutation instead produced a KeyError because the intentionally weakened lookup
still tried to reorder the original key. That is a mutation-harness error, not a
claimed product defect or successful guard detection. The mutation was corrected
on a disposable source copy; all six then produced assertion failures. Both runs
and their actual outcomes are preserved (`guards/`, `guards-fixed/`).

The normal module URL failed DNS through curl. A supported download helper also
refused its URL-view precondition; no bytes were downloaded and no workaround
bypassed it. The later actual `go install` recorded a DNS connection-refused error
before compiling. The network gate reported unassessed without executing a
consensus engine. Tool errors are not converted into successful tests.

## Publication and limits

No implementation tree/commit/ref publication is attempted here; previously blocked
prerequisite source uploads are not retried or rerouted. The complete deliverable
continues the local source lineage and includes its history. A status-only GitHub
comment may record the checkpoint, not publish the implementation. Main and PR #2
are inspected without changing their code or merge status.

Caches do not reserve money, give users priority, or establish settlement. Private
socket limits do not protect public RPC/P2P, prevent same-user idle-slot exhaustion,
or cap native execution time. Frames still use the existing codec. Existing snapshot
storage, repeated state scans and the fixed-validator trust model retain their
previous limits. No audit, bank/issuer operation, production launch or complete
network security claim is made. Fresh archive checks are recorded separately and
must not be counted as new unique tests.
