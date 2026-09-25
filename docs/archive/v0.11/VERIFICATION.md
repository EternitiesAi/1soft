# v0.11 verification — persistent payment jobs

September 24, 2026 (America/Chicago). Local development only.

## Observed results

| Gate | Result | Scope |
|---|---|---|
| Inherited v0.10 archive | SHA-256 matched; 407 manifest entries matched | Parent bytes, not a new consensus result. |
| Full local Python suite | 569 passed; zero skips/failures/errors | 16 completed batches with exact unique test-ID reconciliation. |
| New payment-job cases | 34 passed, included in 569 | Job binding, exact signature handoff, actual CLI/process/HTTP exercises. |
| Separate JavaScript reference | 30 passed | Still separate from native monetary/agent accounting. |
| Intentionally weakened job controls | 3 detected by assertion failures | Immutable intention, exact envelope and prepared signer binding. |
| Full local source inventory | 64 of 64 matched | Does not establish complete remote-node publication. |
| Pinned-engine network runner | Unassessed; zero engine steps | Local engine absent. No synthetic engine fallback. |
| Actions/DNS/paid resources | None | The owner's Cloudflare/domain lane remains untouched. |

The first run of batch 13 was interrupted by the execution time limit during a
long inherited RPC-response test; it has no completed report and is not counted
as a pass. Its log is preserved. Batch 13 was then rerun by itself with a larger
bounded invocation and passed. The 16 completed reports cover all 569 distinct
case IDs exactly once. No single-process full-suite or full remote-main pass is
claimed. The 34 new cases are included in 569, not in addition to it.

The initial standalone job run passed all 34 cases. No new production-state defect
or chain rule change is claimed: task-level identity was previously absent, while
transaction-level nonce/replay defenses already existed. Three copied source
variants deliberately weakened explicit binding checks; the original tests
failed with assertions, not import errors. This is developer verification, not
an independent audit or proof of complete security.

## Important exercised scenario

Prepare a stable job, sign the exact body using an encrypted *public-fixture*
Ed25519 key, attach it, and submit through actual loopback HTTP. The endpoint
executes the real NativeLedger and deliberately drops the response. The job
remains unresolved. A new process then refreshes through read-only RPC and
verifies the exact receipt. A later preparation under the same job ID with a
newer nonce is refused. Only one broadcast occurred. The generated committee
signatures are synthetic fixtures, not votes from a running CometBFT network.

## Evidence and remaining gate

Logs and machine-readable coverage are under `evidence/v011/`, including
`test-coverage.json`, the three `guard-*.log` records and
`network-attempt/result.json`. The complete local package continues v0.10
`7be0ab4b85899b5d9c8784fa7b23011700205cc4`; the remote PR continues the separate
main wallet lineage. The new adapter consumes their shared canonical signature
format and does not overwrite either wallet. Only the new job-related files are
intended for this update; no blocked ABCI transport upload is attempted.

Normal local DNS resolution was checked for the Go module host and official
container-registry hosts; it still fails here. The official project publishes a
v0.38.25 image, but its existence is not evidence that a binary was downloaded or
executed. The real engine gate remains unassessed. Changing the domain cannot
establish distributed consensus.

No on-chain job identifier, current balance guarantee, cross-device/global
idempotency, signing/dispatch distributed transaction, lost-key recovery, public
currency, USD reserve, issuer/card integration or production custody is delivered.
Caller-generated stable IDs and one trusted local workspace remain assumptions.
Public monetary policy and protocol versions 1/2 are unchanged.

Final publication head, archive hash and fresh-extraction checks are recorded
separately once the artifacts are finalized. Their checksums are integrity checks,
not authenticated authorship or independent security certification.

## Publication outcome

A normal GitHub tree action attempted to add the new `src/payment_jobs.py` and
`scripts/jobs.py`. The platform rejected that action with a safety-check block.
No tree/commit/ref was returned or advanced by that write. Coordinated source
publication was stopped; the other new files were not individually attempted.
The blocked content was not retried, encoded, split, or sent through another
upload route. This checkpoint is delivered as local development source, not as a
published PR update. PR #2's previously observed head remains the v0.10 parent
unless a later independent actor changes it. A separate status comment may record
this result without publishing blocked source.
