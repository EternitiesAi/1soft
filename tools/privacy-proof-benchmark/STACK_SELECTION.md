# Proof-stack selection receipt

Evidence date: 4 October 2026. This is a source-backed engineering ranking for
an isolated 1soft prototype, not a cryptographic certification or production
selection.

## Selected first benchmark

**gnark v0.16.3 / gnark-crypto v0.21.0 / Groth16 / BN254 / Poseidon2** is the
first benchmark because it can express the complete frozen relation, integrates
with the installed Go toolchain, has maintained native prover/verifier APIs and
permits direct measurement without adopting another chain. The exact upstream
tags resolve to:

- gnark `cfc7b2f907cc4212ec152077e022c6d0b4805759`;
- gnark-crypto `0a975d747c416958f20ad4e785bcf102449a81c9`.

Both declare Apache-2.0. The component does not copy their source; Go module sums
and archive hashes are pinned in `DEPENDENCIES.json` and `go.sum`.

The selection is intentionally narrow. [gnark's security policy](https://github.com/Consensys-Incorporated/gnark/security)
lists prior compiler, gadget, proof-system and deserialization advisories. The
[v0.16.3 release](https://github.com/Consensys-Incorporated/gnark/releases/tag/v0.16.3)
clears the published pre-v0.16.2 `gnark/std` soundness version gate, but its
declared crypto v0.21.0 dependency predates the security and breaking changes in
[gnark-crypto v0.22.0](https://github.com/Consensys-Incorporated/gnark-crypto/blob/v0.22.0/CHANGELOG.md).
The benchmark therefore exercises only ordinary Groth16/BN254/Poseidon2 with no
Groth16 commitment extension, KZG, Vortex, BLS12-381 generator, EdDSA/ECDSA or
untrusted serialized-input path. Production work still requires a supported
upgrade/backport assessment and independent review.

Groth16 needs a circuit-specific setup. This component creates an ephemeral local
setup to measure mechanics. A production circuit would require a separately
designed multi-party ceremony, parameter distribution and verification process.

## Second implemented benchmark profile

The component now also contains an independent **Zcash Halo2 0.4.0 / halo2-gadgets 0.6.0 / halo2-poseidon 0.2.0 / pasta_curves 0.6.0** profile using the Pallas base field, Vesta IPA commitments, the official Poseidon gadget and deterministic public parameters. It is a semantic parallel of the frozen relation, not a byte-compatible port of Groth16/BN254/Poseidon2. The development receipt records 10 exact acceptance/rejection cases, with 3,136-byte proofs and 524,356-byte parameters, using synthetic identities; these remain provisional until clean-tree verification and the release gate pass.

Halo2 has no Groth16-style toxic-waste ceremony in this profile, but parameter distribution, verifying-key governance, circuit review, wallet scanning, anonymity and consensus enforcement remain open.

## Ranked alternatives

| Candidate | Decision for this phase | Primary reason |
| --- | --- | --- |
| [Zcash Halo2 0.4.0 / gadgets 0.6.0](https://github.com/zcash/halo2) and [Orchard 0.16.0](https://github.com/zcash/orchard/tree/0.16.0) | Implemented as the principal second benchmark; production selection deferred | Strong maintained note-system lineage and no toxic-waste ceremony, with higher circuit/integration burden. Never reuse the circuit/verifying key affected by the [Orchard underconstraint advisory](https://github.com/zcash/zcash/security/advisories/GHSA-ghc3-g8w4-whf9) or removed unstable SHA-256 gadget |
| [Penumbra 2.1.1](https://github.com/penumbra-zone/penumbra/releases) | Architecture and circuit reference | Complete spend/output/balance/viewing model, but modified 1soft Groth16 statements need new parameters and exact dependency review |
| [Noir 1.0.0-rc.2](https://github.com/noir-lang/noir/releases/tag/v1.0.0-rc.2) / Barretenberg 5.2.0 | Defer | Official pinned materials call Noir not fully audited/not recommended for production and Barretenberg highly experimental |
| [SP1 6.8.1](https://github.com/succinctlabs/sp1/releases/tag/v6.8.1) | Defer | Individual STARK proofs do not provide the required zero knowledge; wrapped proofs add setup and material hardware cost |
| [RISC Zero 3.0.6](https://github.com/risc0/risc0/releases/tag/v3.0.6) | Defer | Official security model urges caution for critical privacy; raw execution length and remote-prover witness exposure need explicit handling |
| arkworks Groth16 0.6.0 | Defer as standalone baseline | Official project describes the generic library as an academic prototype rather than a production-reviewed system |
| Circom 2.2.3 / snarkjs 0.7.6 | Browser experiment only | Useful browser tooling, GPL-3.0 integration obligations, ceremony requirements and no whole-stack audit/version mapping established here |
| Miden VM 0.35.0 | Defer | Official release is alpha, unaudited and not production-ready |
| Winterfell 0.13.1 | Reject for secret-note baseline | Official documentation states it lacks perfect zero knowledge and can disclose information about secret inputs |

## Local warehouse evidence

The canonical warehouse index contained 2,357 entries and no indexed general
backend from the candidate set. Its SHA-256 at inspection was
`3ab0594dd3e4fdb3845cdc758687106584656b7757678304764f55d49d99fba3`.

Monero's Bulletproofs+ source supplied useful patterns for separate prove/verify,
batch/individual measurements, scalar/shape checks and malformed/out-of-range
rejection. Grin supplied a clean commitment-plus-proof verifier boundary. Their
code and incomplete dependency graphs were not imported or executed. Monero's
working checkout was marked changed since inventory, so it is not claimed
pristine at its indexed commit. These are design references only.

## Next decision gate

Run the same frozen statement and mutations through a current Halo2/Pasta
prototype, then compare constraint coverage, proof size, setup/parameter model,
local prove/verify time, peak memory, exact advisory surface and mobile/browser
integration. No funds-bearing choice is allowed before independent circuit review,
multi-host state enforcement, custody, wallet recovery and metadata gates pass.
