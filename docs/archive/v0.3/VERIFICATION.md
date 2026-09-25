# v0.3 verification record

**24 September 2026. Development evidence, not a security certification.**

## Passed in the current runtime

| Gate | Observed result | Boundary |
|---|---|---|
| Python unit/regression suite | **122 passed, 0 failed** | 58 previous tests plus 64 new block/wire/runner tests. |
| Earlier JavaScript model | **30 passed, 0 failed** | Separate reference implementation, unchanged. |
| Four-process ABCI test | **39 checks passed** | Four actual OS processes over private Unix sockets; scripted authoritative application requests. No validator voting or engine. |
| Mutation sensitivity | **3 deliberately introduced faults detected** | Tests fail when replay state is omitted from AppHash, staged state is exposed, or block persistence loses its transaction. Only those three mutations were assessed. |

Raw output is in `evidence/v03/python-tests.txt`, `js-tests.tap`, `abci-processes.json`, and `regression-sensitivity.json`. Application process logs are included. Private test account keys were generated in memory; disposable process data was removed after testing.

The four-process run executes a signed owner grant and an agent payment at scripted height 1, then an owner authority fence at height 2. It kills a process before commit, restarts and replays it, kills another after commit, verifies replay protection and stale-authority rejection, compares full committed state and checks the 100 DEV fixture supply. **These are application heights, not evidence of CometBFT blocks.**

The unit suite also kills a child process inside the database transaction and after a successful commit. This is process-crash testing, not a physical disk/power-loss guarantee.

## Unassessed, with recorded reasons

| Gate | Status | Evidence |
|---|---|---|
| Build CometBFT v0.38.25 | **Failed to obtain dependency** | `comet-build-attempt.txt`: Go module proxy DNS/network access failed; exit 1. |
| Official upstream Go codec | **Unassessed** | `upstream-wire.json`: `go mod tidy` could not retrieve the pinned module; exit 2. The Go source was formatted but not compiled successfully. |
| Four actual validator processes | **Unassessed** | `devnet.json`: required binary absent; no engine checks executed; exit 2. |
| Remote GitHub CI | **Not run** | Workflow authored locally. No remote repository publication. |

The local protobuf tests use the inspected schema subset and golden byte vectors. They must not be described as successful interoperability with the official binary. The real-engine runner has no fake-engine or simulated-vote fallback.

## Corrections made while testing

The first local wire run had one failing test caused by an incorrect declared length in a handcrafted unknown-field fixture. That fixture was corrected; the full suite was rerun. It was not counted as a successful first run.

The adapter was designed to close two integration gaps before claiming consensus readiness: receipt/replay state participates in AppHash, and authoritative staged execution is not durable or publicly visible until the commit boundary. The previous standalone native core remains byte-for-byte unchanged.

## Not claimed

No working public or private CometBFT chain; no demonstrated quorum behavior, Byzantine resistance, validator independence, measured TPS, authenticated light-client proof, public issuance, dollar reserve, cash conversion, live wallet/backend integration, bank account, card program, exchange listing or independent audit.

The website/account preview is inherited unchanged from v0.2. Its previous browser results are historical, not new browser-to-chain integration evidence.

## GitHub and external state

The connected request for `xnuonux/layer1-foundation` returned 404 in this continuation. The exposed GitHub connector can edit accessible repositories but has no repository-creation action. No existing Eternities, Luna2 or canon branch was changed. The release carries local source history and reproducible gate scripts rather than a fabricated remote repository URL.

## Reproduction

Local checks: `python scripts/run_tests.py`, `python scripts/check_abci_processes.py`, `python scripts/check_regressions.py`, and `node --test reference/kernel.test.mjs`.

Network-enabled Linux/WSL gate, with Go and Python installed: `bash scripts/verify_network.sh`. Only its actual returned results may replace the unassessed engine/codec statuses. Resolve failures instead of weakening tests or substituting mocks.
