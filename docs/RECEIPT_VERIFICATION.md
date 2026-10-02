# Independently checkable native-coin receipts

v0.5 development design · 24 September 2026

## Purpose

A future wallet or agent must not treat an RPC server's “paid” response as sufficient evidence. This release adds an offline verifier for a narrow development configuration: the unchanged Ed25519 validator set in a separately pinned CometBFT genesis.

It does not create a chain. A valid signature is not proof that a live consensus network produced it. The delivered examples are synthetic, locally signed fixtures.

## Inputs and trust

The caller provides a trusted SHA-256 digest of the exact public engine-genesis bytes, the corresponding genesis file, a certificate packet, and the native transaction IDs from the caller's original payment intent. Optionally the caller also specifies the required state height.

The tool refuses to substitute a validator list supplied by an RPC response. It checks the address derived from each validator public key, unique membership, positive bounded power, and canonical validator ordering before reconstructing the validator-set hash. Only the fixed genesis set is supported. Any next-validator-set change is rejected.

A copied genesis plus an attacker-provided digest is not a trust anchor. The eventual application needs independently authenticated genesis distribution and key lifecycle rules. The command-line arguments demonstrate the boundary; they do not solve that operational problem.

## Checks performed

1. Reconstruct every signed header from its 14 protocol fields and compare its hash with the complete committed block ID.
2. Recreate canonical length-delimited precommit sign bytes, retaining nanosecond timestamps and the block-part-set binding.
3. Verify every non-absent Ed25519 signature in its expected validator slot. Duplicate/reordered slots fail. Nil votes are authenticated but do not count as votes to commit this block. Do not stop checking after reaching quorum.
4. Require strictly more than two-thirds of the trusted voting power. Exactly two-thirds fails; signer headcount cannot substitute for power.
5. Reconstruct each block's transaction-data hash from the full transaction list and require the target transaction exactly once.
6. Authenticate the complete post-execution state at height h using the signed header at h+1. Recompute the application hash independently of the application's implementation.
7. Match included transactions to their native execution receipts in that state, check the receipt digest and native signature, and compare the exact set of witnessed IDs with the caller's requested IDs.

The verifier does not independently replay the entire chain's authorization history. It verifies the stated receipt under the assumed correct operation of the pinned validator quorum.

## Why height h+1 matters

The header of block h contains the previous application hash; it cannot authenticate the state produced by executing h. A packet claiming the post-state must carry the next signed header. A dedicated regression test constructs a signed same-height header carrying the desired hash and still requires rejection.

## Incoming-key signatures in protocol 2

The genesis witness selects native protocol 1 or 2; every authenticated receipt's transaction body must match it. For `open_account` and `rotate_key`, the verifier independently checks the extra incoming-key acceptance signature after the outer signature. It reconstructs the exact payload without the acceptance field and applies the separate protocol-2 consent domain. Its implementation does not import the native signing helper.

A successful lifecycle transaction proof includes `incoming_key_consent_verified: true`. Ordinary payments report false because no incoming-key consent is required; false does not mean their root/agent signature was ignored. Signature verification is not independent reexecution of every nonce, allowance or balance transition, and does not prove a human approved the action or that keys are securely held.

`scripts/check_lifecycle_certificates.py` creates explicitly `SYNTHETIC` onboarding and rotation evidence under `evidence/v05/lifecycle-certificates/` and exercises six CLI acceptance/rejection cases. These certificates are locally constructed, not live network output.

## Historical minimal synthetic demonstration

The following pin and transaction ID are **fixed test values**, not production trust material. The keys behind these examples are disposable and known to the fixture generator.

```sh
python scripts/verify_certificate.py \
  --genesis evidence/v04/certificates/SYNTHETIC-genesis.json \
  --genesis-sha256 6401049833eabfa33de829baec4a73fa51f68b10784d128dd9e9296f960de74a \
  --packet evidence/v04/certificates/SYNTHETIC-packet.json \
  --expect-txid ae0986954a013117ffd345adc25960f190ac1a515bc15222935c8ac6143a7a02 \
  --expected-state-height 1
```

Success is exit 0 with a JSON report. Invalid evidence exits 2. Supply `--expect-txid` repeatedly for multiple intended transactions. Omitting it is an argument error. Never derive the expected list solely from the untrusted packet itself; the CLI checks it against the caller's explicit request.

`python scripts/check_certificates.py` regenerates the legacy-protocol synthetic cases under the current `evidence/v05/certificates/` directory and tests valid evidence, a wrong genesis pin, wrong state height, an invalid signature after quorum, duplicate JSON keys, and an omitted requested payment.

## Packet shape and limits

`schema: 1` packets contain `state`, `state_commit`, and `transactions`. Each transaction witness includes the raw signed transaction, the complete block transaction list, and a signed header/commit. The state witness contains the native genesis, height, application hash and full snapshot, including receipts.

Input JSON is bounded at 16 MiB. Duplicate object keys and non-integer JSON numbers are rejected. Decoded transaction size is bounded at 16,384 bytes; up to 64 transaction witnesses and 256 fixed validators are supported by this verifier. These are development limits, not throughput claims or a replacement for a full resource-exhaustion review.

The CLI is read-only: it has no network calls, signer capability or access to the privileged ABCI socket. The library permits a state-only query when `expected_txids` is omitted, but labels the result `requested_transactions_bound: false`. The payment-verification CLI does not permit that omission.

## Integration and remaining boundaries

The real-network runner obtains its public genesis from its own fresh test initialization, records the exact digest, and supplies expected IDs from the originally authored transactions. It must verify actual RPC evidence with this module before reporting success. Both native protocol paths, including onboarding and rotation receipts for protocol 2, are authored but **unassessed** because the CometBFT binary was unavailable.

A full snapshot is not a compact balance proof. This verifier does not establish freshness, full chain ancestry, dynamic-validator continuity, independent operators, actual engine provenance, bank settlement, dollar redemption, or safety against a compromised quorum. It is not a production light client.

Static verification can be useful even before those broader features exist, but the interface must label its scope. Do not render “network verified” for the included synthetic fixtures.

## Provenance

Protocol field encodings and fixed vectors are attributed in `SOURCE_REVIEW.md`, `NOTICE.md`, and `third_party/COMETBFT-ATTRIBUTION.md`. Cryptography is delegated to the installed Ed25519 implementation; no custom signature algorithm or new consensus algorithm was introduced.
