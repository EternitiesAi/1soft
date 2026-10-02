# 1soft v0.15 — observed verification

September 25, 2026. Cryptocurrency-only continuation from complete local v0.14 `721437c4eef75cf15e7cf784f8025373a026f69e`. No Codex runtime, Actions, paid compute, DNS change, website deployment, Resident/Luna/Psyche modification, customer funds or production keys were used.

| Gate | Actual result | Scope |
|---|---|---|
| Parent archive | SHA-256 matched; 686 manifest entries matched | Before editing |
| Existing application/index baseline | 64 tests passed | Rerun before changes |
| New execution snapshot suite | 37 tests passed | 14 image tests and 23 application tests |
| Complete Python suite | 797 passed, zero skips/failures/errors | 16 completed processes with exact unique-ID reconciliation |
| Selected deliberately weakened controls | All five caught by assertion failures | Source selection, startup validation, authorizer, promotion, checkpoint binding |
| Application-process exercises | 39 and 65 checks passed | Real local processes and scripted ABCI, not voting validators |
| Separate JS budget reference | 30 passed | Still separate from native accounting |
| Existing second-structure Merkle implementation | 6 roots and 39 proofs agreed; 39 altered roots rejected | Not independent audit or consensus |
| Required sources | 89/89 matched | Complete local package, not remote checkout |
| Actual-engine gate | Unassessed, zero engine steps | Pinned engine absent; ordinary module-host lookup still fails |

## What the tests establish

Read-only committed images cannot be mutated through their normal SQL interface. Independent forks can execute and close without changing the image or each other. Cross-thread application checks and forks run on real SQLite connections. A pending image is not used for committed checks; a durable commit promotes it exactly once. Failed commits preserve the older image; actual process exits before and after commit reopen the corresponding validated disk state.

Historical receipt validation remains mandatory on startup. A test changes a stored receipt signature and recomputes the surrounding disk application hash; startup still rejects it. New transaction signatures remain checked on every trial. Missing or mismatched execution checkpoints raise internal errors rather than accepting a transaction or silently rebuilding a cache.

Cached and reference paths agree on transaction checks, ordered proposal results, defensive finalization, receipts, native state, application hashes, and SMT proofs across protocol 1, protocol 2, protocol 3, and opt-in protocol-3 SMT genesis. Shared-budget debits and two-sided key rotation are exercised on the cached path. All existing protocol golden tests ran within the full suite. Neither native monetary code nor cryptographic primitives were changed.

## Measurement

`evidence/v015/measurement/result.json` contains raw samples for 12 alternating admission checks per path per case, after 1,024 actual signed transfers in 16 application blocks. Median valid-check times: reference 138.875402 ms; cached 1.506432 ms. Median invalid-signature times: reference 154.958627 ms; cached 1.227046 ms. Responses match and checks do not commit state. Reference checks scan 1,024 saved receipts; cached checks do not rescan saved signatures. This is local admission-check work, NOT consensus throughput, network latency, fee cost, or a production guarantee.

## Incomplete runs retained, not counted

The first full single-process run hit this tool environment's 180-second execution limit before completion. Its `full-suite.log` is retained; no full single-process pass is claimed. A combined batch-12/13 invocation also hit its limit after completing batch 12; the interrupted batch-13 log is retained separately. Its completed standalone retry passed. A singled-out receipt crash test passed separately under a traceback deadline, indicating that particular test did not reproduce a hang when isolated. Only the 16 complete JSON batch records count toward the reconciled 797 successful IDs.

One attempted interactive execution session was unavailable (`StreamingExecNotEnabledContainerError`); it did not run tests. A reporting command initially attempted to read the JS proof check's output directory as JSON; the underlying check succeeded, and its actual result file was read afterward. Neither tooling result is recast as a product-code failure or pass.

## Boundaries

Execution images are trusted local derived state, not authenticated network objects. Database copies and additional RAM remain; native invariant scans, full snapshot persistence, reference commitment construction, and startup validation still have growing costs. No new mempool security, production pruning, dynamic-validator light client, hardware custody, reserve backing or public issuance is claimed.

The normal network command verified all required source, then returned unassessed with an empty step list. No fake engine or fixture was used as a substitute. Process tests use scripted application calls, not validator votes. No real-network performance measurement is present.

The archive continues the complete local wallet lineage, not remote main's different state-wallet implementation. No previously blocked native-core, transport, job, or state-index source is retried through another upload route. Source publication, packaging hashes and fresh-extraction checks are recorded separately in RELEASE.json and the companion release-check. Integrity manifests do not constitute signed software provenance or an independent audit.

## Publication scope in this checkpoint

No source tree/commit/ref was written to GitHub in this checkpoint. Previously
blocked prerequisite uploads were not retried through another route. The complete
implementation and tests are in the local source package. A status-only PR comment
records the completed work without changing main or the existing PR code.
