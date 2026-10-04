# Shielded privacy foundation

1soft's current ledger and authority attack model are transparent. Reduced
application receipts omit fields, but they do not hide ledger activity. A future
privacy system must preserve the current economic and failure invariants while
changing the state representation and proof boundary. It must not be assembled
from unrelated fragments of several privacy protocols.

## First experimental slice

A first implementation now lives in the separate
[shielded-note lab](../tools/shielded-note-lab/README.md). Its source is under
qualification against the
[4 October transition specification](superpowers/specs/2026-10-04-shielded-note-lab-design.md).
It is a deterministic transparent-witness laboratory using synthetic keys and
values under an exact development-genesis binding. No live caller imports it;
Protocol 4, native transaction bytes, wallets, browsers and validators remain
outside this component.

The lab makes note commitment, authenticated membership, nullifier derivation,
spending authorization and integer conservation executable before choosing a
proof system. SHA-256 domain-separated hashes and Ed25519 authorization support
that model; they do not provide zero knowledge or select a production privacy
stack. A checker receives the complete witness rather than a zero-knowledge proof.

Qualification must establish that one accepted input creates only the exact
ordered outputs plus fee, a refused transition leaves serialized state unchanged,
and an exact replay or lost reply recovers the original retained receipt without
a second transition. Export/reopen must preserve the tree, consumed nullifiers,
transactions and receipts. Selected-output disclosure must bind to retained
execution evidence and label its linkability while excluding spending keys,
note secrets, full viewing authority and unrelated openings.

These rules are valuable because a future circuit, wallet and consensus adapter
need one precise semantic target. One shared lab state can refuse competing
spends; two independent cloned states can each accept a different spend because
there is no shared consensus. The separate
[private authority attack model](PRIVATE_AUTHORITY_ATTACK_MODEL.md) remains the
oracle for shared-parent budgets, revocation and unresolved obligations; this
note lab does not implement those private authority successors.

The lab provides no zero-knowledge privacy, anonymity, production readiness,
public deployment or real-funds support. No production proof system has been selected
for the chain.
Source presence and local test success do not establish independent review,
consensus integration or a private ledger.

## Experimental proof benchmark

The separate [privacy-proof benchmark](../tools/privacy-proof-benchmark/README.md)
is an experimental first benchmark candidate using gnark v0.16.3,
gnark-crypto v0.21.0, Groth16 over BN254 and Poseidon2. It exercises a synthetic
one-input/two-output relation with ephemeral setup and offline exact-source
verification, including the listed rejection cases. Its status remains source
under qualification unless a successful exact receipt exists. It is not a
production proof-system selection, production privacy, consensus integration,
network anonymity, custody, independent review, public-network readiness or
real-funds safety.

## Requirements for a privacy successor

A later privacy implementation still needs one coherent cryptographic stack and
these versioned concepts:

1. A note commitment binding asset, value, recipient spending authority,
   recipient viewing material, authority epoch and fresh note blinding.
2. A private nullifier derived from note-specific secret material and a unique
   note position or commitment. It must not reveal a public payer, grant or
   budget identifier.
3. Separate spending, incoming-viewing, outgoing-viewing and transaction-scoped
   disclosure authority. A full viewing key is not a routine merchant receipt.
4. A fixed-depth authenticated note tree and a consumed-nullifier set.
5. One spend transition proving membership, nullifier uniqueness, value range,
   input equality to outputs plus fee, exact recipient/output/fee binding, and an
   atomic authority-fragment successor.
6. A verifier that rejects unknown versions, parameters, curves, proof systems,
   transcript domains and encodings before parsing proof-controlled values.

The existing Penumbra reference pinned in
[the private-payments architecture](PRIVATE_PAYMENTS_ARCHITECTURE.md) is useful
for studying key separation, note commitments, nullifiers and selective
disclosure. It is not a drop-in dependency. Its curve, serialization, Poseidon,
key-agreement, proof and parameter choices form one protocol system. Types copied
without that system would create an unsafe imitation.

## Economic invariants that survive the privacy transition

A shielded successor still has to prove:

- grant spend plus payment plus fee never exceeds the grant cap;
- parent-budget spend plus payment plus fee never exceeds the parent cap;
- parent lifetime spend equals the linked grants' lifetime spend;
- one current parent authority fragment is consumed and exactly one authorized
  successor is created;
- revocation cannot refill, reset or erase prior spend;
- a losing or ambiguous proved obligation stays held until authenticated evidence
  resolves it;
- two copies of a wallet cannot produce two independently valid successors;
- transaction bytes, accepted root, epoch, asset, fee, recipient commitment and
  proof commitments are bound together.

The transparent
[private authority attack model](PRIVATE_AUTHORITY_ATTACK_MODEL.md) is the
executable semantic oracle for these rules. It is not the privacy implementation.

## Required adversarial tests

The transparent-witness lab must qualify fixed vectors, bound-field mutations,
malformed and noncanonical inputs, wrong roots/paths/secrets, spending-key binding,
altered output order/fees, invalid authorization, range overflow, duplicate
nullifiers, stale roots, replay and failed-apply invariance. Its exact-source
verifier must retain test identities, source hashes and dependency pins; no skips
or expected failures substitute for acceptance.

Before consensus integration, a proving successor must additionally reject
malformed proofs, stale private authority, parameter substitution and two
competing spends of the same private budget fragment. It also needs crash/restart,
copied-device, lost reply and authenticated reconciliation tests around proof
generation and submission.

Any proving implementation needs independent cryptographic review, reproducible
parameters, bounded verification cost, explicit side-channel assumptions and
license review. FROST or another threshold signature scheme may later improve
treasury custody, but it does not provide hidden amounts, note membership,
nullifiers or selective disclosure and is not the first privacy slice.

## Integration gate

No shielded state enters the chain until one complete stack has been selected and
the experimental transition passes its invariant and malformed-proof suites under
independent review. Until then 1soft must not claim anonymity, unlinkability,
shielded balances, shielded counterparties, secure proving, production custody or
mainnet privacy.
