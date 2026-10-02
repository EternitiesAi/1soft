# Eternities Native Finance — v0.4 development

**Original native-coin application, block processing, and independent signed-receipt verification. CometBFT v0.38.25 remains the integration target. No actual consensus engine has run in the recorded environment.**

The coin remains the primary project. Branding, public supply, security economics and any dollar issuance remain open. The 100 DEV fixture is not public tokenomics or real money. This is not a bank, exchange, issued card, public cryptocurrency or production wallet.

## What changed

The proposal builder now accounts for protobuf transaction framing rather than only raw transaction bytes. Regression tests first failed against v0.3 and then passed with the fix.

A separate verifier checks canonical block-header hashes, Ed25519 validator signatures, strict voting-power quorum, transaction inclusion, and full application-state witnesses against a separately pinned genesis. State after block h must be authenticated by the signed header at h+1. The command-line verifier requires the caller's expected transaction IDs; a packet cannot omit a requested payment and still satisfy that request.

The actual-engine runner now requires these cryptographic checks in addition to its pre-existing native transfer, delegation, revocation, quorum loss/restoration and four-state comparison checks. Those actual-engine paths have not run. Local synthetic certificates must never be described as engine output.

Read [verification](docs/VERIFICATION.md), [receipt verification](docs/RECEIPT_VERIFICATION.md), [ABCI architecture](docs/ABCI_INTEGRATION.md), and [handoff](docs/HANDOFF.md).

## Recorded gates

| Gate | Result | Boundary |
|---|---|---|
| Python tests | 192 passed | 122 inherited tests plus 70 new tests; includes narrow source-derived golden vectors. |
| Separate JavaScript budget model | 30 passed | Unchanged; not integrated into the native ledger. |
| Four application processes | 39 checks passed | Scripted ABCI delivery, sockets and process crashes; not validator voting. |
| Standalone certificate CLI | 6 cases passed | Synthetic signed fixture and five rejection cases; not network execution. |
| Single-field certificate mutation sweep | 1,307 rejected | All enumerated mutations rejected; not broad fuzzing or a security audit. |
| Targeted regression sensitivity | 7 new and 3 inherited faults detected | The exact deliberate code defects are documented in raw evidence. |
| Official Go codec runtime | Unassessed | Dependency retrieval failed; Go source formatted, not successfully compiled. |
| Actual four-validator CometBFT integration | Unassessed | No engine binary available; no simulated-success fallback. |
| Remote CI | Not run | Workflow authored, no remote repository published. |

## Reproduce local checks

Use Python 3.11+, the pinned Python dependencies, and Node.js for the separate reference tests. The socket server and process gates require Linux/WSL. No customer funds, credentials or paid resources are required.

```sh
python -m pip install -r requirements.txt
python scripts/run_tests.py
python scripts/check_abci_processes.py
python scripts/check_regressions.py
python scripts/check_v04_regressions.py
python scripts/check_certificates.py
python scripts/check_certificate_mutations.py
node --test reference/kernel.test.mjs
```

Current evidence is in `evidence/v04/`. Evidence in `evidence/v03/` and older documents is historical, not an additional current test count. Current verification, architecture and roadmap supersede the archived v0.3 versions.

## Actual engine gate

On a network-enabled Linux/WSL machine with Go >= 1.22.11, Python and Node installed:

```sh
bash scripts/verify_network.sh
```

The script creates a virtual environment, fetches dependencies, runs the official upstream codec probe, builds the version-pinned engine, and runs a disposable four-validator test. Listeners are loopback-only. Test runtime and disposable keys are removed afterwards. It does not create cloud resources, issue assets to customers or publish a network.

A successful engine run must additionally produce public genesis evidence, a genesis-file SHA-256 pin, a signed receipt packet, and independent verification results. A missing engine returns `unassessed` and a nonzero exit. A local fixture pass never turns the engine gate green.

## Entrypoints

`src/native_core.py` contains the unchanged signed monetary model. `src/block_application.py` supplies isolated proposal evaluation, staging and atomic commit. `src/abci_server.py` is a privileged private Unix-socket interface, not a wallet API. `src/commit_verifier.py` and `scripts/verify_certificate.py` verify static-set development certificates without calling RPC. `scripts/run_devnet.py` requires the actual engine. `tools/upstream-wireprobe/` compares encodings with official Go types when dependencies are available.

`web/index.html` is the inherited account-design concept, not a live chain-connected wallet. The separate settlement journal and JavaScript budget-tree reference have not been atomically integrated with the native ledger.

## Limits that remain

The state store clones and hashes full snapshots. The verifier reads full state and full transaction lists, not compact query proofs. It supports only an unchanged, genesis-pinned Ed25519 validator set and does not establish freshness, continuous ancestry, operator independence or engine provenance. It is not a production light client.

Still absent: production signing and recovery, dynamic account registration, staking and validator changes, general smart contracts, state sync, final fee economics, public issuance, bank/custody/card partners, live cash or multi-asset conversion, independent security review and public-network readiness. Dependency versions are pinned, but a fully hash-locked offline supply chain and reproducible toolchain audit are not complete.

No remote GitHub repository was created or modified. Local history is included in the release bundle. Do not repurpose another Eternities repository to bypass missing repository-creation support.
