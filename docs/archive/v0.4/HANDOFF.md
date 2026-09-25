# Continuation handoff — native coin v0.4

## Standing lane

Continue the independent Layer 1/native coin first. Its eventual agent-native account, multi-asset/cash integration and card experience are supporting products, not a substitute for a real chain. Branding, public supply, allocations, security economics and dollar issuance remain open. No customer funds, issuer applications, public deployment or remote repository writes occurred.

## Proven in this continuation

The 122-test inherited baseline passed. v0.4 fixes raw-only block transaction sizing, adds independent static-genesis certificate verification, a strict payment-intent-bound CLI, and committed-block metadata queries. Current evidence records **192 passing Python tests**, **30 separate unchanged JavaScript tests**, **39 scripted ABCI-process checks**, **six verifier CLI cases**, **1,307 rejected single-field packet mutations**, and **seven new plus three inherited targeted code-fault detections**.

Source-derived fixed header-hash and five canonical vote vectors agree with upstream v0.38.25 tests. This is not a successful execution of the upstream Go codec. Locally generated certificates are explicitly synthetic, use fixture keys, and do not demonstrate validator voting.

## Critical gate remains unassessed

CometBFT v0.38.25 could not be downloaded/built. The official Go probe could not resolve modules. The real engine runner returned unassessed with zero checks. A browser alternate route was unsupported/credit-blocked; no credits were purchased. An inspected upstream e2e run exposed no binary artifact. **No CometBFT consensus engine ran.**

The real-network runner now requires signed transaction/block certificates and post-state anchoring at h+1, checked independently against its fresh genesis and the originally intended transaction IDs. Its new integration branches, like its original quorum branches, remain unexecuted. Do not weaken or bypass them to manufacture a pass.

## Next work, in order

1. In a dependency-enabled Linux/WSL environment run `bash scripts/verify_network.sh`. Review the official Go probe first, then actual validator results. Preserve raw failures and add regression tests for genuine incompatibilities. The Go source is formatted but has not been compiled successfully.
2. Require native transfer, constrained agent spend, authority revocation, progress with 3/4 validators, measured halt with 2/4, restoration/replay, matching committed records, independently authenticated transaction inclusion and post-state. Record binary version/hash and public genesis digest. Never export disposable private keys as evidence.
3. Exercise actual engine/application crash-order permutations and partitions. The existing application-process crash checks are not substitutes. Validate RPC JSON details and lifecycle semantics empirically.
4. Before calling the verifier a production light client, design trusted genesis distribution, key rotation/dynamic validator tracking, freshness/trusting periods, fork/equivocation handling and complete ancestry policy. Current support is deliberately static and rejects changes.
5. Replace full-state cloning/hashing with an authenticated, bounded-cost state design; specify pruning, historical receipts and state sync. Address dynamic account registration, protected signer custody, key recovery, execution cost and fee economics.
6. Integrate native and external-payment budgets only under a deliberate atomic/reservation/reconciliation protocol. The native ledger, settlement journal and JavaScript budget tree remain separate models.
7. Publish a dedicated private repository when a genuine create action or exact fresh repo is available. The current connector has no create-repository action; `xnuonux/layer1-foundation` returned 404. Do not repurpose unrelated repositories or race other Eternities work.

## Entrypoints

`src/block_application.py`; `src/commit_verifier.py`; `scripts/verify_certificate.py`; `scripts/check_certificates.py`; `scripts/check_certificate_mutations.py`; `scripts/check_v04_regressions.py`; `scripts/run_devnet.py`; `tools/upstream-wireprobe/`; `docs/RECEIPT_VERIFICATION.md`; `docs/VERIFICATION.md`.

The local history bundle preserves the previous v0.3 and v0.2 commits. `RELEASE.json` identifies the final v0.4 commit without a self-referential tracked-file hash. Raw current evidence lives in `evidence/v04/`; earlier evidence remains historical.

## Invariants and claims discipline

A model cannot expand its own authority. Delegation cannot multiply a budget. Pending is not settled. Receipt-based replay state belongs in AppHash. Only committed data is query-visible. Header h+1 authenticates state after h. More than two-thirds means strictly more, not equal. Validate all supplied signature slots, including those after quorum. Nil votes do not commit the block.

A payment proof must match IDs from the caller's original intent, not IDs selected by the proof provider. The genesis digest must come from a trusted channel, not the same untrusted packet. Synthetic signatures are not network evidence. A state witness is not a compact Merkle query proof, proof of freshness or independent reexecution.

ABCI is privileged engine-to-application control and must never be exposed to agents. All fixtures and units are disposable. No reserve, bank relationship, issuer partnership, audit, native market value, performance metric, validator independence or public-network security has been established.
