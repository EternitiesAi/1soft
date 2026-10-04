# Halo2/Pasta proof benchmark design

Date: 4 October 2026

Status: approved implementation specification for an isolated experimental benchmark. It is not a production proof-system selection, consensus change, wallet feature, deployment, security audit, or real-funds boundary.

## Objective

Implement the same frozen one-input/two-output note-spend semantics already measured by the gnark Groth16 benchmark using the current coherent Zcash Halo2 stack:

- `halo2_proofs` 0.4.0;
- `halo2_gadgets` 0.6.0;
- `halo2_poseidon` 0.2.0;
- `pasta_curves` 0.6.0;
- Rust 1.88 or newer, with the exact build toolchain and Cargo lock recorded.

These versions form one `ff`/`group` 0.14 type family. `pasta_curves` 0.5.2 is excluded because it belongs to the incompatible 0.13 family and cannot be mixed into this circuit merely to preserve an earlier candidate table.

The benchmark must use the Zcash Halo2 PLONKish proof system with its IPA polynomial commitment over the Pasta cycle and the Blake2b transcript. Public commitment parameters are deterministically derived by the pinned library and require no trusted ceremony. Circuit configuration, parameter distribution, pinned verifying-key identity, upgrades, governance, implementation soundness, and side-channel behavior remain separate production obligations.

## Parallel proof profiles

The Groth16 and Halo2 implementations are independent profiles of one semantic relation.

The Groth16 profile remains:

- BN254 scalar field;
- gnark Poseidon2;
- circuit-specific ephemeral local setup;
- its existing source digest, receipt, tests, and evidence.

The Halo2 profile is:

- Pallas base field with Vesta IPA commitments;
- Zcash Poseidon `P128Pow5T3` with fixed-length domain encoding;
- deterministic public `Params`, circuit-specific proving and verifying keys;
- its own source digest, receipt, tests, and evidence.

The fields, hash functions, constants, capacity encoding, transcripts, proofs, parameters, and cryptographic output bytes differ. A matching semantic fixture does not imply byte compatibility, mutual verification, equivalent security, or equivalent performance conditions.

## Frozen relation

The ordered public instance vector is:

1. version;
2. genesis;
3. asset;
4. context;
5. epoch;
6. height;
7. transaction expiry;
8. policy;
9. accepted root;
10. nullifier;
11. output commitment 0;
12. output commitment 1;
13. fee;
14. authorization digest.

The private witness contains the input position, value, note expiry, blinding, spend secret, note secret, a depth-four Merkle authentication path and position bits, plus two output values, expiries, recipient spend-key hashes, note secrets, and blindings.

The circuit must enforce:

- version 1;
- Boolean depth-four position bits and a matching position;
- unsigned 64-bit version, epoch, heights, expiries, values, and fee;
- strict transaction and note expiry after the current height;
- positive input and output values;
- exact `input = output0 + output1 + fee` conservation;
- a spend key derived from the hidden spend secret;
- an input note commitment shared with the output commitment formula;
- a domain-separated leaf and depth-four Merkle path to the public root;
- a nullifier bound to version, genesis, asset, epoch, policy, context, spend secret, note secret, input commitment, and position;
- both output commitments;
- distinct output commitments;
- an authorization digest over the complete ordered public transaction binding.

Poseidon calls must include explicit numeric application-domain fields in addition to the fixed-length Poseidon domain. Native fixture generation and circuit gadgets must agree for every used arity.

## Required proof and rejection cases

The owned backend must run a real parameter/key generation, proof creation, and proof verification. Its exact case inventory is:

| Case | Required observation |
| --- | --- |
| valid-proof | accept |
| mutated-proof | reject |
| changed-public-input | reject |
| wrong-verifying-key | reject |
| invalid-membership | reject |
| invalid-nullifier | reject |
| invalid-output-commitment | reject |
| invalid-fee-conservation | reject |
| out-of-range-value | reject |
| changed-authorization-digest | reject |

Constraint-specific invalid witnesses must reach either proof creation or proof verification and fail. Unit tests must also cover native-versus-circuit Poseidon agreement, public-instance ordering, output-to-input composability, duplicate outputs, and a wrong spend secret.

## Measurement and receipts

Record exact positive measurements for public-parameter generation, verifying-key generation, proving-key generation, proving, and verification. Record the circuit power `k`, domain rows, estimated proof bytes from the pinned library when available, actual proof bytes, serialized public-instance bytes, and serialized public-parameter bytes.

Retain only SHA-256 digests and sizes of proofs, public instances, parameters, and the pinned verifying-key representation. Halo2 0.4.0 does not expose a supported proving-key serialization API. The receipt must label proving-key serialized size as unassessed rather than estimating or treating process memory as a portable encoding. The pinned verifying-key debug representation is a version-bound identity input used by the upstream library, not a portable key file.

Never retain the synthetic opening, witness, proof bytes, serialized parameters, key material, or random coins in repository evidence.

## Source and execution boundary

The verifier must:

- require a clean non-shallow Git worktree;
- validate exact component membership, file sizes, SHA-256 digests, test identities, Cargo lock, and the Halo2 circuit-source digest;
- require stable Linux Rust 1.88 or newer;
- run Rust tests and the benchmark with `cargo --locked --offline`;
- use an external Cargo target directory;
- relaunch in a fresh Linux user and network namespace;
- disable Cargo network access and fail on a missing cached crate;
- exclusively create reports and logs outside the repository;
- bind independently observed commit, tree, manifest, dependency, circuit, log, and backend-receipt identities;
- recheck source identity after execution.

The existing Groth16 verifier and closed receipt remain independently required. Neither backend may substitute for the other.

## Evidence boundary

A pass establishes only that the exact local source generated and verified an actual proof for the exact synthetic relation and rejected the listed cases under the recorded toolchain. It does not establish:

- global nullifier uniqueness or consensus ordering;
- chain acceptance of roots or atomic insertion of outputs;
- production parameters, ceremony, or verifying-key governance;
- independent cryptographic review;
- wallet scanning, viewing keys, recovery, or usable private transfers;
- network anonymity or resistance to timing and metadata leakage;
- production custody or side-channel resistance;
- public-network readiness, exchange readiness, asset value, or real-funds safety.

The critical Orchard underconstraint advisory is a reason for exact circuit and verifying-key review. It is not evidence that this new circuit is safe or unsafe. Mock-prover success, local proof success, and two-backend agreement remain engineering evidence rather than security certification.
