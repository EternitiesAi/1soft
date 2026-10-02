# Continuation handoff — native coin v0.5

24 September 2026

## Standing lane

Continue the independent Layer 1/native coin first. Agent-native accounts, continuity, simple intake and eventual cash/multi-asset/card integration support it; they must not replace building the coin. Branding, public supply, allocations, economics and dollar issuance remain open. No customer funds, public deployment, issuer relationship, remote repository or remote CI run exists in this lane's recorded work.

## This release

v0.5 adds native protocol 2, explicitly selected by a fresh genesis. It implements sponsor-funded `open_account`, two-sided `rotate_key`, and owner-scoped grant labels. Incoming-key consent binds the complete transaction intention and is independently checked in receipts. Rotation preserves the stable ID, history and monotonic nonce; it increments the authority epoch and invalidates older native grants without resetting their spending records. Both old and incoming keys are required: this is not lost-key recovery.

Protocol 1 remains supported unchanged. A missing genesis protocol field means 1. Never rewrite a protocol-1 genesis or migrate its grant labels silently. The outer envelope signing domain remains v1; the signed body and genesis pin select the execution version. State row shape and full-snapshot commitment format remain unchanged.

## Evidence

287 Python tests pass (192 inherited + 95 new), as do 30 unchanged JS tests. The legacy scripted application-process gate has 39 checks; the new lifecycle process gate has 65 and executes 11 native operations. Two six-case CLI exercises use synthetic certificates. The legacy 1,307-mutation sweep and seven new plus ten inherited deliberate code-fault checks pass within their stated scope.

Raw current evidence is `evidence/v05/`. Archived old docs and evidence are historical. Do not add intermediate suite counts together or call constructed signatures live validator evidence.

## Critical gate remains unassessed

The Go module download still fails in this environment. No CometBFT binary ran. The official Go probe and both actual network runners return unassessed with zero checks. The Firecrawl alternative was credit-blocked; no purchase was made. The target `xnuonux/layer1-foundation` returned 404, and available GitHub actions do not include repository creation. No unrelated repo was used.

The runner now covers both native versions. `build_native_case` generates public signed plans; private fixture keys are not returned. v1 has four accepted operations plus a stale-authority rejection. v2 has ten accepted operations and four rejection cases, including onboarding, duplicate grant labels across owners, rotation, old-key/grant rejection and continued transfers to the stable ID. Unit-testing these plans is not engine testing.

## Next work in order

1. In a dependency-enabled Linux/WSL environment run `bash scripts/verify_network.sh`. Inspect the upstream-wire probe first, then actual engine results for **both** protocols. Preserve failures and fix genuine compatibility issues; do not remove gates or relabel scripted requests as consensus.
2. Require actual native transfers, scoped agent spending, revocation, onboarding/rotation for v2, progress with 3/4 validators, measured halt at 2/4, restored progress/replay, matching committed state and independently checked live receipts. Record actual engine hash/version and public genesis digest. Do not export private fixture keys.
3. Exercise engine/application crash-order cases and partitions, not only application-process termination. Validate handshake version semantics and RPC JSON behavior against the exact engine; those paths remain unassessed.
4. Design protected signing and human-readable transaction consent. Define lost-key recovery, key compromise response, recovery ordering and external-card/session revocation before claiming resilient custody. The new signing helper is a development primitive only.
5. Replace full-state copies/hashes and linear active-key lookups with a bounded authenticated design; define account growth, execution cost, pruning, history, compact proofs and state sync.
6. Extend static-genesis certificate trust only through a deliberate design for authenticated distribution, freshness, ancestry, validator/key changes and equivocation. Current verifier is not a production light client.
7. Design a single accounting/authority boundary across native grants, JS hierarchy and external payment holds before saying they share a budget. The current models remain separate; distinct native grants have distinct caps.
8. Publish a dedicated private repository when an actual creation action or the exact new target is available. Do not race or repurpose Eternities/Luna2 branches.

## Entrypoints

`src/native_core.py`; `src/block_application.py`; `src/commit_verifier.py`; `tests/test_account_lifecycle.py`; `tests/test_lifecycle_blocks.py`; `tests/test_lifecycle_signatures.py`; `scripts/check_account_processes.py`; `scripts/check_lifecycle_certificates.py`; `scripts/check_v05_regressions.py`; `scripts/run_devnet.py`; `docs/ACCOUNT_LIFECYCLE.md`.

`RELEASE.json` identifies the final source commit. `history.bundle` preserves earlier commits. Local build/test keys are disposable; no public value, reserves, issuer partnership, card capability, validator independence or security certification has been established.

## Invariants

Delegation does not authorize account administration. Incoming key consent is scoped, not generic. Rotation changes authority, not identity or existing obligations. Spent caps and root nonces never reset. New protocol semantics require explicit genesis selection. Pending is not committed. A claimed payment proof must match the caller's original transaction intention. Header h+1 authenticates post-state h. Synthetic signatures are not consensus evidence. ABCI is privileged and must never be exposed to agents.
