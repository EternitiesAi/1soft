# v0.7 verification record — local execution and offline signing

24 September 2026. No Actions runs were requested. No real funds or public network were used.

| Gate | Observed result | Scope |
|---|---|---|
| Inherited v0.6 package inventory | 212 entries matched | Original bytes, before edits. |
| Inherited Python suite | 320 passed | Rerun locally before changes. |
| Current full Python suite | 395 passed, 0 skipped | 320 inherited + 55 wallet + 20 local-runner cases. |
| Required-source inventory | 48/48 matched | Full local package, not remote completeness. |
| Separate JavaScript model | 30 passed | Still separate from native accounting. |
| Scripted ABCI process exercise | 39 checks passed | Four application processes; no validator votes. |
| Scripted account-process exercise | 65 checks passed | Account lifecycle/crash behavior, not consensus. |
| Local engine build | Failed at dependency DNS lookup | No compilation or native engine execution. |
| Cache-only upstream codec probe | Unassessed | Required Go modules not cached. |
| Local real-network command | Unassessed, no steps | Engine absent; no simulated fallback. |

The terminal tests initially failed because their subprocess inherited a controlling terminal outside the test capture. The test harness now starts a separate session and applies a finite post-response deadline. Its initial interrupted log is retained. These were test-harness failures, not evidence of a password-echo defect. The final full test log includes successful real pseudo-terminal create-key and sign operations and confirms the fixture password is not echoed.

The local runner separately tests timeout cleanup, missing commands, exclusive evidence creation, incomplete core/full scopes, zero tests, explicit download permission and internally inconsistent pass reports. These checks are not additional consensus features.

Evidence is under `evidence/v07/`. Earlier evidence remains historical and retains its original scope. The original complete history remains in the local bundle; remote history is separate and is preserved rather than force-replaced.

Remote publication: Actions were archived in commit `f3a526825cf611d30fc1176b342078db4366c8d2`. New source-publication results and the final remote head are recorded in `RELEASE.json` and the publication inventory when packaging finishes. The previously blocked ABCI transport was not uploaded through another route; the remote node import remains partial.

## Boundaries

Wallet review is static and marks current authority unverified. The encrypted vault is development-only, has no hardware/memory-extraction protection or lost-key recovery, and does not make passwords safe to give to agents. The terminal digest is a binding to content, not authentication. No signing step broadcasts a payment.

The chain's actual consensus network, scalable authenticated state, operator independence, production custody, dollar backing, public economics, cash conversion, card issuance and bank integration remain unimplemented or unassessed. No new supply or monetary policy was selected. The standalone receipt fault-injection sweeps were not rerun as standalone scripts in v0.7; their relevant unit tests remain in the full suite.

A checksum inventory is neither a signature nor an independent audit. Fresh-archive tests are recorded separately after packaging and do not add new distinct test cases.
