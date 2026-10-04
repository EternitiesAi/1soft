# Proof profile comparison

This comparison is a development benchmark record for one frozen synthetic
one-input/two-output relation. It does not select a production proof system.
The profiles are semantically parallel, not byte-compatible: they use different
fields, curves, hashes, proof formats and parameter models.

| Property | Groth16 profile | Halo2 profile |
|---|---|---|
| Stack | gnark v0.16.3 / gnark-crypto v0.21.0 | halo2_proofs 0.4.0 / gadgets 0.6.0 / poseidon 0.2.0 / pasta_curves 0.6.0 |
| Curve/commitment | BN254, Groth16 | Pasta (Pallas/Vesta), IPA |
| Hash profile | Poseidon2 | Official Halo2 Poseidon P128Pow5T3 |
| Setup/parameters | Circuit-specific ephemeral setup | Deterministic public Halo2 parameters; VK governance remains open |
| Evidence | Exact-source offline verifier and mutation matrix | Development receipt with 10 exact cases; clean-tree verifier and release gate pending |
| Production status | Not selected | Not selected |

The current Halo2 receipt measured 3,136-byte proofs, 524,356-byte parameters,
about 0.646 seconds proving and about 0.0084 seconds verification in one local
run. It used synthetic identities and is provisional evidence, not a capacity,
security, anonymity, wallet, consensus or custody result. Do not compare these
numbers as an economic or production benchmark until both profiles have the
same clean-tree evidence contract and independent review.
