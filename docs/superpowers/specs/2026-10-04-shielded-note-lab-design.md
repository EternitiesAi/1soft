# Isolated shielded-note transition laboratory

Date: 4 October 2026

## Decision

Build the first 1soft shielded-value implementation as a new, self-contained
tools/shielded-note-lab component. It is a deterministic transparent-witness
laboratory. It does not change Protocol 4, native transaction bytes, genesis,
wallet behavior, validators, receipts, the browser, or private-payments runtime.

The lab exists to settle note commitment, nullifier, authenticated-tree,
authorization, conservation, replay, failure-continuity, and scoped-disclosure
semantics before a proof system or consensus integration is selected. SHA-256
and Ed25519 are used only for versioned commitments, deterministic state, and
authorization in this model. They do not create zero knowledge.

## Security and product boundary

The current product remains a transparent development network. The lab must
always report:

- production_privacy: false;
- zero_knowledge: false;
- consensus_integrated: false;
- public_network: false;
- real_funds: false.

No live caller imports the package. No public RPC, browser route, wallet adapter,
mint, burn, bridge, faucet, validator rule, deployment, or key-generation flow is
added. Synthetic test keys and values are the only permitted inputs.

A successful local transition proves only that this executable model preserved
its declared invariants. It does not prove anonymity, unlinkability, hiding
against a capable observer, proof-system soundness, network privacy, production
custody, public-chain acceptance, or global double-spend prevention.

## Versioned note model

A note opening binds one exact development genesis and contains bounded,
canonically encoded fields for:

- protocol/schema version;
- asset identifier;
- positive integer value;
- recipient spending public key;
- recipient incoming- and outgoing-viewing public material;
- authority epoch;
- expiry or policy boundary;
- policy commitment;
- a commitment to note-specific nullifier material;
- fresh note blinding.

Secrets and blindings stay in the witness during ordinary execution. Public
transactions, receipts, and state must not contain a private key, note secret,
note blinding, witness path, full viewing key, or unrelated note opening. A
deliberately generated selected-output disclosure may reveal that output's
non-secret opening fields and blinding so a verifier can recompute its exact
commitment. The bundle must label the resulting linkability and must never
include the note secret, spending private key, full viewing authority,
unselected output, or unrelated history.

All hashes use explicit, immutable domain prefixes. Changing the genesis,
version, asset, action, position, accepted root, authority epoch, validity
window, fee, recipient, output order, output commitment, or spend context must
change the corresponding authorization or derived value.

## Authenticated state and spend transition

The lab maintains a bounded fixed-depth authenticated note tree and a consumed
nullifier set. It supports one semantic spend:

1. authenticate one input note commitment under the exact accepted root;
2. derive the one nullifier bound to its committed secret, position, genesis,
   and spend context;
3. check that the nullifier is unique in the request and absent from prior
   state;
4. verify the input opening and spending authorization;
5. verify every output opening against the public ordered output commitments;
6. enforce exact integer conservation: input value equals ordered output values
   plus the explicit fee;
7. enforce asset, authority epoch, policy, expiry, range, version, and encoding
   rules;
8. atomically consume the nullifier, append outputs, advance the authenticated
   root, and retain one exact public receipt.

Every validation completes before state mutation. A refused transition leaves
the exact state serialization unchanged. An exact replay returns the original
receipt only if the complete transaction identity is already retained; it never
creates a second state transition. A different transaction using the same
nullifier is refused.

Two independent cloned lab states may each accept competing spends because this
lab has no shared consensus. One shared state accepts at most one. The receipt
must state that distinction instead of turning a local result into a global
claim.

## Failure continuity and disclosure

State export and reopen must retain the authenticated tree, consumed
nullifiers, exact public transactions, and original receipts. A lost return
after commit is recovered by transaction identity without creating a new
signature, nullifier, output set, or randomness.

The first disclosure format is transaction-scoped. It may reveal an explicitly
selected output opening and the minimum public execution evidence needed to
verify that output against the retained transaction and root. It must not export
spending authority, note/nullifier secrets, a full viewing key, wallet history,
unselected outputs, or a stable relationship graph. Disclosure replay is
verification of the same retained fact, not new execution authority.

## Adversarial qualification

The component must include fixed vectors and mutation tests for:

- commitment reproducibility and sensitivity to every bound field;
- nullifier reproducibility, scope binding, and one-time use;
- wrong roots, positions, paths, secrets, genesis, versions, assets, epochs,
  policies, expiry, spend context, fees, output values, recipients and order;
- malformed, oversized, ambiguous, noncanonical, Boolean-as-integer, negative,
  zero, overflow, duplicate and unknown inputs;
- altered, truncated and wrong-key Ed25519 authorization;
- duplicate nullifiers within one request and across state;
- replay, competing spends, cloned states and stale roots;
- caller-owned input mutation during validation and retention;
- failed-apply state invariance;
- stable export/reopen and lost-reply receipt recovery;
- scoped disclosure tampering and secret-field absence;
- process-level deterministic fixed vectors;
- absence of network access.

The component verifier validates its exact inventory and dependency versions,
runs every isolated test with no skips or expected failures, emits stable test
identities and source hashes, and repeats the nonclaims above. The repository
current checker must cover the new test directory exactly once as a distinct
group.

## Promotion gate

This lab may inform a later protocol design only after its source, vectors,
failure semantics, and disclosures pass review. A native privacy proposal still
requires one complete selected proof and commitment stack, exact parameter and
dependency provenance, circuit and verifier definitions, side-channel
assumptions, measured proving and verification costs, wallet scanning and
witness recovery, consensus state/AppHash integration, supply and
shield/unshield accounting, protected custody, independent cryptographic review,
and separately authorized multi-host qualification.

Until those gates exist, the accurate claim is: **an isolated transparent-witness
shielded-note transition laboratory proves local semantic invariants; 1soft's
ledger remains public.**
