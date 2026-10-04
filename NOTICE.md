# Research and reuse notice

The Python models and HTML/CSS interface in this package were written for this project. No cryptocurrency consensus engine, MetaMask, Chime or card-provider implementation was copied wholesale into them. Protocol identifiers and transcribed upstream test vectors are specifically attributed below. A source review is not legal clearance or a claim of patentable novelty.

The `reference` JavaScript files are the unchanged prototype from the preceding conversation package. They are supplied to preserve project continuity, not as a newly integrated subsystem.

No new open-source license is granted by this document. The project owner should choose the intended licensing and publication model before distribution. Third-party dependencies retain their own license terms and notices; their code is not vendored here. Any future upstream incorporation needs exact-version license, notice and dependency review.

All names of external projects and providers identify research subjects only. No affiliation, endorsement, issuer relationship, card-network license or audit is implied. The provisional Eternities coin/card treatments are not finalized branding or issued instruments.

## v0.3 integration additions

The new application wrapper, server, tests and runners are original project code. ABCI field identifiers and meanings are drawn from the public CometBFT v0.38.25 protocol schema. The optional CometBFT engine and upstream wire probe depend on third-party code under its own upstream terms; the engine source/binary and its dependency tree are not bundled here. No claim of an independent consensus invention or completed upstream security audit is made.

The account concept and earlier research are inherited from v0.2, not recreated or revalidated as a bank integration in v0.3. No fonts, production credentials or real validator keys are packaged.

## v0.4 receipt verification additions

The new verifier, encoded-size fix, CLI, metadata query, mutation/regression harnesses and integration changes are project-authored code. Fixed expected header-hash and canonical vote-byte vectors were transcribed from CometBFT v0.38.25 tests. Protocol field encodings derive from the corresponding public schemas. Those values and upstream contributions are not represented as proprietary inventions. See `third_party/COMETBFT-ATTRIBUTION.md` and the included Apache 2.0 license terms.

Only synthetic test signatures are delivered. No CometBFT binary is included. The current implementation depends on third-party cryptography and protobuf libraries, under their own terms; it does not invent a cryptographic primitive or a new consensus algorithm.

## v0.13 compact-state work

The sparse map, compact proof/client format, tests, byte-size experiment and second
JavaScript implementation are project-authored. SHA-256, binary Merkle commitments,
proof compression and positional membership/absence are established techniques,
not proprietary cryptographic inventions. No ICS23/IBC compatibility is claimed.
The upstream CometBFT/ICS23 materials cited in COMPACT_STATE.md are architectural
references; their code was not copied wholesale into these new modules. Synthetic
committee evidence is labelled as such and is not a live-network attestation.

## Privacy proof-stack benchmark

The 1soft circuit, synthetic fixture, adversarial cases, evidence contract and
offline benchmark harness are project-authored research code. They use the
third-party Go modules `github.com/consensys/gnark` v0.16.3 and
`github.com/consensys/gnark-crypto` v0.21.0 under Apache-2.0, plus their locked
transitive dependencies under their respective licenses. Third-party source is
resolved by Go modules and is not vendored in this repository. Exact module sums,
source pins and inspected license hashes are recorded under
`tools/privacy-proof-benchmark`.

The second profile uses `halo2_proofs` v0.4.0, `halo2_gadgets` v0.6.0,
`halo2_poseidon` v0.2.0 and `pasta_curves` v0.6.0 under their declared
MIT or Apache-2.0 terms, plus a locked Rust dependency graph under each crate's
own terms. Crate source is resolved through Cargo and is not vendored here.
`tools/privacy-proof-benchmark/DEPENDENCIES_HALO2.json` records exact crate
checksums and declared license expressions; that inventory is not legal
clearance, a source audit or a security certification.

Groth16, BN254, Halo2 PLONKish proofs, Pasta IPA commitments, Poseidon,
Poseidon2, Merkle membership proofs, nullifiers and range checks are established
cryptographic techniques and are not represented as proprietary inventions.
Neither the local ephemeral Groth16 setup nor the deterministic public Halo2
parameters and passing synthetic proofs inherit upstream audits or certify
privacy, consensus, custody, anonymity, public-network behavior or real-funds
safety.
