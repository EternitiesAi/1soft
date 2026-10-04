# 1soft privacy proof-stack benchmarks

This isolated component runs actual zero-knowledge proofs for one frozen synthetic
one-input/two-output note relation on two independent experimental backends:

- gnark v0.16.3 with gnark-crypto v0.21.0, Groth16 over BN254 and Poseidon2;
- Zcash Halo2 0.4.0 with gadgets 0.6.0, Poseidon 0.2.0 and Pasta curves 0.6.0,
  using a PLONKish circuit, IPA commitments and Poseidon P128Pow5T3.

The component measures and attacks candidate proof stacks before any consensus,
wallet, browser, RPC, deployment, custody or real-funds integration. Neither
backend validates the other and neither is a production selection.

## Two separate cryptographic profiles

The Groth16 run generates fresh circuit-specific local setup keys and retains only
their hashes and sizes. That setup is not a ceremony or reusable production
parameter set.

The Halo2 run derives public IPA parameters deterministically for the recorded
power-of-two domain. It generates circuit-specific proving and verifying keys in
memory. No trusted ceremony is required, but parameter distribution, pinned
verifying-key identity, upgrade governance, circuit review and implementation
security remain production obligations. The pinned Halo2 API does not expose a
supported proving-key serialization, so that size is explicitly unassessed.

The profiles use different scalar fields, curves, hash permutations, fixed-length
domain encodings, transcripts, parameters and proof formats. Halo2 exposes
Poseidon P128Pow5T3 rather than Poseidon2. Their commitments, roots, nullifiers,
authorization digests and proof bytes are deliberately not byte-compatible.
"Same relation" means the same ordered fields and constraints, not the same
cryptographic output bytes.

## What both circuits bind

Both circuits prove one note opening and depth-four Merkle path, one derived
spend key and nullifier, two output commitments, unsigned 64-bit positive values,
strict expiry ordering, exact fee-inclusive conservation, distinct outputs and an
authorization digest over the complete ordered public transaction binding.

The public input order is version, genesis, asset, context, epoch, height,
transaction expiry, policy, accepted root, nullifier, output commitment 0, output
commitment 1, fee and authorization digest.

Neither proof can determine whether a chain accepts the supplied root, whether a
nullifier is globally fresh, whether outputs are inserted, or whether validators
apply the transition atomically. The transparent note lab remains the semantic
oracle for replay, receipts, state mutation and clone boundaries. Its SHA-256 and
Ed25519 bytes are not compatible with either proof profile.

## Verification

Populate the exact Go and Cargo caches once from the repository root:

```sh
cd tools/privacy-proof-benchmark/go
GOTOOLCHAIN=local go mod download

cd ../halo2
cargo fetch --locked
```

Then run the strict verifiers from a clean Git commit, writing evidence outside
the checkout:

```sh
python tools/privacy-proof-benchmark/tools/verify.py \
  --report /path/outside/repository/privacy-proof-groth16.json

python tools/privacy-proof-benchmark/tools/verify_halo2.py \
  --report /path/outside/repository/privacy-proof-halo2.json
```

Each verifier checks the exact component manifest and Git identity, runs the
closed Python contract tests, and launches its backend tests and benchmark inside
a new Linux user and network namespace. Module, registry, toolchain and VCS
network resolution are disabled. Missing cached dependencies fail instead of
silently going online. See [VERIFICATION.md](VERIFICATION.md).

The Halo2 backend also records serialized deterministic parameter size and hash,
a version-bound pinned-verifying-key binding, estimated and actual proof size,
canonical public-instance size and hash, key-generation/proving/verification
times, one accepted proof and the same nine rejection cases as the Groth16
backend. Proof, parameter, key and witness bytes are not retained in receipts.

## Evidence boundary

A pass is evidence of a source-bound local benchmark and its listed rejection
cases. It is not production privacy, independent cryptographic review, consensus
integration, network anonymity, production custody, public-network readiness,
exchange readiness, asset value or real-funds safety.

See the measured [profile comparison](COMPARISON.md),
[STACK_SELECTION.md](STACK_SELECTION.md), the
[original Groth16 design](../../docs/superpowers/specs/2026-10-04-privacy-proof-benchmark-design.md)
and the
[Halo2 comparison design](../../docs/superpowers/specs/2026-10-04-halo2-proof-benchmark-design.md).
