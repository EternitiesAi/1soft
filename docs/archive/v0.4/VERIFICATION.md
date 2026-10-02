# v0.4 verification record

24 September 2026. Development evidence, not a security certification.

## Executed in this runtime

| Gate | Observed result | Evidence and scope |
|---|---|---|
| Python suite | **192 passed, zero failures** | `evidence/v04/python-tests.txt`; 122 inherited tests, 70 added tests. |
| Separate JavaScript reference | **30 passed** | `js-tests.tap`; unchanged, not connected to the native ledger. |
| Four scripted ABCI processes | **39 checks passed** | `abci-processes.json` and process logs; no CometBFT engine or votes. |
| Standalone verifier CLI | **6 cases passed** | `certificates/checks.json`; one synthetic valid packet plus five rejection cases. |
| Single-field/schema mutation sweep | **1,307 rejected; zero accepted; zero unexpected errors** | `certificate-mutations.json`; enumerated modifications of one synthetic packet, with separately supplied expected transaction IDs. |
| New targeted code faults | **7 detected** | `v04-regression-sensitivity.json`; disposable altered copies, tests fail as intended, original source unchanged. |
| Inherited targeted code faults | **3 detected** | `regression-sensitivity.json`; rerun, not new defects discovered in this continuation. |

The 70 new Python tests comprise 62 verifier tests, four encoded block-size tests and four committed-block metadata tests. Individual golden-vector subcases are included in those tests, not inflated into additional test counts.

The seven new deliberate code faults relax strict quorum, stop checking signatures after reaching quorum, count nil votes, omit header/commit hash binding, omit the state-h-to-header-h+1 relationship, omit expected-payment binding, and ignore protobuf framing. Detecting them establishes sensitivity only to those faults.

## Corrections and first-run history

The inherited 122-test baseline passed. Two new boundary assertions failed against v0.3: a raw-only transaction budget was accepted despite framing overhead, and a raw-full block could exceed the encoded limit. `block-size-before.txt` records that failure. `block-size-after.txt` records all four new boundary tests passing after the correction.

The first expanded full-suite run then had one failure in an old test whose expected behavior assumed the incorrect raw-only boundary. That assertion was updated to reject the raw-only budget and accept the correct encoded budget. `python-tests-first.txt` retains the failure. The final full suite passes; this is not represented as a clean first run.

While checking receipt request binding, a state-only packet was correctly acceptable to the state-verification API but did not establish the caller's intended payment. The production-facing development CLI was tightened to require explicit `--expect-txid` arguments, and omission/substitution tests were added. State-only library verification remains possible and explicitly reports `requested_transactions_bound: false`.

## What synthetic certificates establish

A deterministic local fixture executes a native transfer in the application, then signs constructed headers with disposable fixture validator keys. The independent verifier reconstructs header hashes and canonical vote bytes, checks Ed25519 signatures and >2/3 voting power, reconstructs transaction-data hashes, and checks the full committed-state hash and matching execution receipt.

These are genuine cryptographic operations on **synthetic certificates**, not evidence that validators ran consensus. The fixture generator controls every validator key. Its certificates establish neither a network nor independently operated validators. The packet and filenames say `SYNTHETIC`.

Our header hash matches the fixed expected hash in upstream `types/block_test.go` at v0.38.25. Canonical vote encodings match five published vectors in `types/vote_test.go`. This is narrow independent source-vector evidence, not successful runtime interoperability with the official engine.

## Unassessed or not executed

| Gate | Status | Reason |
|---|---|---|
| CometBFT v0.38.25 build | Dependency retrieval failed | Current `comet-build-attempt.txt`; no engine binary obtained. |
| Official Go codec probe | Unassessed | `upstream-wire.json`; dependency resolution failed. Its nine authored comparisons did not run. |
| Four actual validator processes | Unassessed | `devnet.json`; missing binary, zero engine checks executed. |
| Network receipt integration | Unassessed | Runner code added; no real network certificate produced. |
| Remote GitHub CI | Not run | No dedicated remote repository created. |
| Public deployment, external payments, audit | Not performed | No customer funds or live banking/card/crypto conversion integrations. |

A browser execution alternative was unavailable: one route was unsupported and another returned insufficient credits. No purchase was made. An inspected official upstream e2e workflow had no downloadable artifacts. These failures did not change any pass criteria.

## Security interpretation

The verifier is static-set, genesis-pinned and Ed25519-only. A caller must obtain the genesis digest through a trusted channel; accepting a genesis file and digest from the same untrusted packet defeats the trust model. Requested transaction IDs must come from the original payment intent.

The post-execution state at h is checked against the signed header at h+1. A transaction's inclusion alone is not success: packet verification also requires its matching execution receipt in the authenticated state. This is attestation under the pinned validator assumptions, not independent reexecution of the complete chain.

No freshness, full ancestry validation, dynamic validator tracking, independent-operator claim, Byzantine-network testing, authenticated compact query proof, measured TPS, mainnet readiness or reserve backing is established. The cryptographic tests are not an independent security audit.

## Reproduction and packaging

Use the commands in the current README. `bash scripts/verify_network.sh` is the actual-engine gate for an environment with dependency access. It has no simulated-consensus success branch.

The source archive carries a SHA-256 file manifest and local Git history. `evidence/v04/release-check.json`, when present in the packaged release, records a fresh extraction, manifest verification and rerun of the Python suite. It is packaging evidence, not another blockchain test.
