# Eternities Native Finance — v0.5 development

**Original native-coin application with signed account onboarding, continuity-preserving key rotation, and independent receipt verification. CometBFT v0.38.25 remains the adapter target. No actual consensus engine has run in the recorded environment.**

The independent coin remains primary. Branding, public supply, allocations, validator economics and dollar issuance remain open. DEV balances are disposable fixtures, not public tokenomics or real money. This is not a bank, exchange, issued card, public cryptocurrency or production wallet.

## What changed

A fresh native **protocol-2 genesis** enables two new operations. `open_account` transfers existing funds from a signing sponsor to a new account whose incoming key signs the same bounded intention. `rotate_key` requires both current- and incoming-key signatures, preserves the original account ID and its financial history, and invalidates the account's older native agent grants. It is controlled key rotation, **not lost-key recovery**.

Protocol 2 also scopes native grant labels to their owner. Two different accounts may each use `raven` without colliding; revocation remains owner-scoped. Previously spent allowances are not reset, and old labels cannot be reused to silently refill a grant. Distinct grants still have distinct caps; a cross-route/common parent budget is not implemented.

Protocol 1 remains supported unchanged. A missing `protocol_version` in genesis means 1. The genesis digest pins the execution version; this release does not upgrade or migrate existing chains. `Info` reports the pinned version. The independent receipt verifier now checks the incoming key's additional signature for protocol-2 lifecycle operations.

Read [account lifecycle](docs/ACCOUNT_LIFECYCLE.md), [verification](docs/VERIFICATION.md), [protocol semantics](docs/PROTOCOL_DRAFT.md), [receipt verification](docs/RECEIPT_VERIFICATION.md), and [handoff](docs/HANDOFF.md).

## Recorded gates

| Gate | Result | Boundary |
|---|---|---|
| Python suite | **287 passed** | 192 inherited tests plus 95 new tests. |
| Separate JavaScript budget reference | **30 passed** | Unchanged; not integrated with the native ledger. |
| Legacy four-process application gate | **39 checks passed** | Scripted ABCI, not validator voting. |
| New four-process lifecycle gate | **65 checks passed** | Real process crashes/replay over private sockets; no consensus engine. |
| Certificate CLI | **6 legacy + 6 lifecycle cases passed** | Synthetic validator certificates, not network output. |
| Legacy certificate mutation sweep | **1,307 rejected** | Unchanged legacy fixture; not comprehensive fuzzing of protocol 2. |
| Deliberate code-fault sensitivity | **7 new + 10 inherited faults detected** | Bounded regression checks, not an independent audit. |
| Official upstream Go codec | **Unassessed** | Dependency download failed. |
| Actual four-validator networks, protocols 1 and 2 | **Unassessed** | Engine absent; each runner reports zero checks, no simulated fallback. |
| Remote CI | **Not run** | No dedicated remote repository was published. |

## Reproduce local checks

Use Python 3.11+, the pinned dependencies, and Node.js for the separate reference. Linux/WSL is required for the Unix-socket and process gates. The captured run used Python 3.13.5, Node 22.16.0 and the exact pinned dependency versions; Python 3.11 is not a separately tested environment.

```sh
python -m pip install -r requirements.txt
python scripts/run_tests.py
python scripts/check_abci_processes.py
python scripts/check_account_processes.py
python scripts/check_regressions.py
python scripts/check_v04_regressions.py
python scripts/check_v05_regressions.py
python scripts/check_certificates.py
python scripts/check_lifecycle_certificates.py
python scripts/check_certificate_mutations.py
node --test reference/kernel.test.mjs
```

Current evidence is in `evidence/v05/`; earlier directories and archived documents are historical. Current documentation supersedes those old release reports. Rerunning scripts updates their current evidence paths and may change random public fixture keys and hashes.

## Actual engine gate — not yet passed

In a dependency-enabled Linux/WSL environment with Go >= 1.22.11, Python and Node:

```sh
bash scripts/verify_network.sh
```

This installs dependencies, runs local gates and the upstream-codec probe, builds the pinned engine, then runs **two separate fresh development networks**, one for each native protocol. It creates no cloud resources, public issuance or value-bearing assets. Listeners are loopback-only; disposable runtime keys are removed after the test.

Both networks retain native transfer, restricted agent spending, revocation, quorum loss/restoration, replay and independently authenticated receipt requirements. The protocol-2 plan additionally requires onboarding, owner-scoped grant labels, key rotation, old-key/old-grant rejection and new-key execution. Missing dependencies are errors, not permission to substitute a scripted consensus pass.

## Entrypoints

`src/native_core.py` implements the version-pinned monetary rules. `src/block_application.py` supplies isolated proposal evaluation, staging and atomic commit. `src/abci_server.py` is a **privileged private engine interface**, not an agent or wallet API. `src/commit_verifier.py` and `scripts/verify_certificate.py` verify static-set development certificates offline. `scripts/run_devnet.py` requires the actual engine. `tools/upstream-wireprobe/` requires the official Go dependency tree.

`web/index.html` remains the inherited, disconnected account-design preview. Its wallet/card controls are simulations. The native ledger, external-payment journal and JavaScript budget tree remain separate systems with no shared atomic budget.

## Remaining limits

Account creation and key rotation are now executable development features, not production onboarding or custody. Missing: protected signers, human-readable trusted consent, lost-key recovery, social/hardware recovery, final addresses, privacy protections, stake/validator lifecycle, general contracts, state sync, scalable authenticated storage, final fees, public issuance, reserve/custody/card partners and live cash/multi-asset conversion.

The application copies and hashes full snapshots. The verifier consumes full state and transaction lists, supports only an unchanged genesis-pinned Ed25519 validator set, and does not establish freshness, full ancestry, independent operators or actual consensus provenance. It is not a production light client. Dependency versions are pinned but the complete dependency supply chain is not hash-locked or independently audited.

No remote repository was created or modified. The target `xnuonux/layer1-foundation` returned 404 to the connected read; repository creation is not exposed by that connector. Local source history is bundled. Do not repurpose unrelated Eternities repositories.
