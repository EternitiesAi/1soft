# Privacy proof-stack benchmark — design

Date: 4 October 2026

Status: isolated research component. This design does not change Protocol 4,
consensus, genesis, wallets, browsers, RPC, public deployment, custody, monetary
rules, or any real-funds path.

## Decision

Build one actual, deliberately nonproduction proof benchmark for a frozen
one-input/two-output note statement with **gnark v0.16.3**, its published
compatible **gnark-crypto v0.21.0** dependency, Groth16 over BN254, and Poseidon2.
The installed Go 1.26 toolchain is compatible with gnark's Go 1.25.7 module
minimum. Use a fresh local Groth16 setup for every run and do not persist the
setup keys, witness, or proof; record only hashes, sizes, and timings. This setup
is not a ceremony, reusable parameter set, production artifact, or security
inheritance. In-memory zeroization is not claimed.

Keep Zcash Halo2/Pasta as the principal no-toxic-waste alternative. Do not add a
second backend until both can be tested against the same frozen statement and
adversarial inventory. Penumbra and Orchard remain complete note-system
references; Monero and Grin contribute benchmark and verifier-boundary patterns.
None is copied into this component.

The stock gnark pair is an experiment, not a blanket security-clean claim.
gnark v0.16.3 clears the published pre-0.16.2 `gnark/std` soundness advisory, but
gnark-crypto v0.22.0 contains later fixes and breaking changes and is not the
dependency declared by gnark v0.16.3. A production decision requires an
upstream-supported compatible release or reviewed backport assessment for the
exact exercised path.

## Frozen statement

The circuit proves knowledge of exactly one existing note opening and exactly
two output openings whose commitments must differ from each other. It does not
prove global output freshness. It uses a fixed depth-four Merkle path so
benchmark shape and cost cannot drift between runs.

Public inputs, in exact order, are:

1. version
2. genesis
3. asset
4. context
5. epoch
6. height
7. expiry
8. policy
9. accepted note root
10. nullifier
11. output commitment 0
12. output commitment 1
13. fee
14. authorization digest

The private witness contains the input value, spend secret, note secret,
blinding, expiry, position and authentication path, plus both output values,
recipient spend-key fields, note secrets, blindings and expiries. A fixed
Poseidon2 key domain derives the input spend-key field from the spend secret.
The payer does not receive an output recipient's spend secret. The witness is
synthetic and must never appear in the benchmark receipt or retained log.

The circuit must enforce:

- explicit domain-separated Poseidon2 spend-key, note, leaf, parent, nullifier
  and authorization hashes;
- one shared note-commitment formula for consumed and created notes, with the
  input spend-key field derived from the proven spend secret so a created output
  can later be consumed by the same relation;
- the input note commitment and its fixed-depth Merkle membership;
- a four-bit position bound and position binding in the nullifier;
- a domain-separated nullifier that also binds the hidden spend secret, note
  secret, input commitment and context, so a sender who knows an output opening
  cannot precompute the recipient's future nullifier from the public spend-key
  field;
- two output commitments in the same version/genesis/asset/epoch/policy domain;
- unsigned 64-bit input, output and fee values, positive note values, and exact
  integer conservation `input = output0 + output1 + fee`;
- unsigned 64-bit heights/expiries, transaction height before transaction expiry,
  and every consumed/created note unexpired at that height;
- an authorization digest over the complete ordered public transaction binding.

The proof does not by itself enforce that the root is accepted by consensus,
that a nullifier is globally fresh, that outputs are appended, or that validators
apply the state transition atomically. Those remain chain obligations.

This profile intentionally replaces the transparent lab's SHA-256 and Ed25519
mechanics with a circuit-friendly candidate profile. It preserves the semantic
obligations; it does not make proof bytes compatible with the existing lab or
select production cryptography.

## Required evidence

The owned verifier runs in a new Linux user and network namespace after Go
modules have been fetched. It disables Go proxy, sum-database, toolchain, and
VCS network resolution; requires a clean, exact Git source identity; verifies
the component source manifest; runs Python receipt-contract tests and Go circuit
tests; then owns one benchmark execution.

The Go receipt has a closed schema. It records exact backend versions, circuit
source digest and constraint count, commit and tree, ephemeral parameter hashes
and sizes, proof/public-witness hashes and sizes, positive compile/setup/prove/
verify timings, and the exact negative-case inventory. It records no private
witness or serialized proving key, verifying key, or proof.

One valid proof must verify. Each of these must be rejected independently:

- a mutated proof;
- changed public input;
- a proof checked under the wrong verifying key;
- invalid membership;
- invalid nullifier;
- invalid output commitment;
- invalid fee conservation;
- an out-of-range value;
- changed authorization digest.

The verifier refuses missing, extra, duplicated, nonfinite, weakly typed, stale,
or mismatched receipt evidence. Python `False` cannot be substituted with integer
zero, and a claimed pass cannot be synthesized from a mock or `actual_backend_run
= false` record.

## Completion condition

This phase completes when the exact component and whole repository pass from a
clean candidate commit, source-bound raw logs and machine-readable receipts are
preserved outside the checkout, and an independent review finds no blocking
defect. The release remains blocked and the following remain unassessed:

- global nullifier uniqueness and consensus ordering;
- production parameter ceremony;
- independent cryptographic review;
- wallet scanning and recovery;
- network anonymity and metadata resistance;
- production custody and side-channel resistance;
- public-network and real-funds safety.

No benchmark result can remove those boundaries.
