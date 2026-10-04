# Shielded privacy foundation

1soft's current ledger and authority attack model are transparent. Reduced
application receipts omit fields, but they do not hide ledger activity. A future
privacy system must preserve the current economic and failure invariants while
changing the state representation and proof boundary. It must not be assembled
from unrelated fragments of several privacy protocols.

## First experimental slice

The smallest meaningful implementation is a separate test-only shielded note
transition package. It must use synthetic keys and a fresh development genesis and
must not alter Protocol 4 or the current wire format.

The package needs one coherent cryptographic stack and these versioned concepts:

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

Before consensus integration, the laboratory must reject duplicate nullifiers,
wrong roots, altered recipients or fees, altered epochs, range overflow, malformed
proofs, stale authority, parameter substitution and two competing spends of the
same private budget fragment. It also needs crash/restart, copied-device, lost
reply and authenticated reconciliation tests around proof generation and
submission.

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
