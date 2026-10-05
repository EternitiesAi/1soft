# Private authority proof lab v1

This isolated experiment proves hidden, fee-inclusive debits against two enrolled
agent grants sharing one parent allowance. It uses actual Halo2 0.4.0 proofs,
Pasta IPA, Poseidon P128Pow5T3, K=13 and 3,136-byte proof transcripts.

The twenty ordered public inputs and frozen parameter/verifying-key hashes are
in [PROFILE_V1.json](PROFILE_V1.json). Arithmetic counters are constrained to
64 bits. The old and exact successor parent/grant commitments bind immutable
caps, agent secret, recipient, grant expiry, mission, identity, asset and epoch.
A payment commitment binds the hidden amount and selected recipient to a request.
The authorization digest is a binding hash, not an owner signature.

One trusted local `Context` selects current enrolled authority outside the circuit.
Both orders of two overlapping 6-unit debits against a 10-unit parent accept only
one original proof. Refreshing the other agent's context permits exactly the
remaining 4-unit debit. Replay and further positive debits fail. Ordered operator
revocation rejects the old prepared proof, while a refreshed surviving grant can
continue. Duplicate grant identities are refused.

## Reproduce locally

From a clean committed checkout, with the pinned Rust toolchain and dependencies
already available, choose fresh external output and build directories:

```sh
python3 tools/private-authority-proof-lab/scripts/qualify.py \
  --cargo /path/to/cargo --target-dir /private/build-authority \
  --output /private/evidence/authority.json
python3 tools/private-authority-proof-lab/scripts/qualify.py \
  --check /private/evidence/authority.json
```

The qualifier runs eight tests with five actual proof constructions and verifications,
requires an exact test roster and cryptographic fingerprints, rejects altered
receipt/source/log identities, and retains a sanitized execution log. Its accepted
status is `qualified-local-proof-lab`, with every production/integration claim false.
These are automated local tests and an AI code review, not an independent security
or cryptographic audit.

## Boundaries and next integration

No wallet, merchant, value-note transition, validator or consensus application calls
this lab. A context commit is an allowance experiment, not an executed payment.
Enrollment and revocation are trusted operator seams. No owner-key lifecycle,
authenticated current-state certificate, durable journal, hostile-host rollback,
cross-device coordination, real funds or production custody is implemented here.
Caps, counters, amount and recipient openings are private circuit witnesses;
stable parent/grant IDs, fee, epoch, validity and commitments remain public. This
does not establish relationship-graph privacy, anonymity or network-metadata privacy.
Deterministic synthetic seeds are for testing only.

The arithmetic/Poseidon gadget is adapted from 1soft's existing experimental
`tools/shielded-consensus/halo2/src/circuit.rs`; its field/hash helpers are reused
through a path dependency with default features disabled. Protocols 1-5 and their
profile/KAT/worker remain unchanged. Declared dependency licenses belong in the
dependency receipt; that inventory is neither legal clearance nor a security review.

The next protocol must atomically compose authority with value-note conservation,
authenticate current authority through validator consensus, and connect exact
transactions to durable wallet obligations. Passing this lab is evidence for that
design, never evidence that it is already integrated. See the [bounded design](../../docs/superpowers/specs/2026-10-04-private-authority-proof-lab-design.md).
