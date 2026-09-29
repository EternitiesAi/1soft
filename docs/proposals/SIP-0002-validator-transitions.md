# SIP-0002 — Validator-set evolution, verification before activation

Status: Draft; bounded read-side reference implementation only.
Date: 28 September 2026. Base: PR #23 / 289a78056b86ebdd5878d285027f5c78562e0767.

## Problem and explicit scope

The current node never emits validator updates. Its certificate verifier accepts
only the genesis validator set and rejects a changed NextValidatorsHash. Changing
that verifier in place would silently broaden the wallet's trust contract. This
proposal instead introduces a separate validator-history witness and an unsigned
transition planner. Neither is imported by a production-path node or wallet.

Implemented here: bounded set validation/hashes, deterministic add/remove/reweight
updates, H-through-H+3 planning, sequential signed-header verification across set
changes, fixed external trust expiry, immutable proof-file continuation, timeline
audit and a pinned upstream compatibility probe. These are not an authorized
validator registry, a governance transaction, state migration, a general light
client, a changing-validator CometBFT run or an activated protocol upgrade.

## Timing under the pinned engine

CometBFT v0.38.25 applies an update emitted by FinalizeBlock H as follows. Header
H+1 commits the updated next set. The updated set validates block H+2. Last-commit
information passed to the application uses that set at H+3. AppHash in header H+1
commits application state after H. Updates use zero voting power to remove a key;
a complete active roster contains positive powers only. These offsets must not be
collapsed into an immediate change at H or H+1.

The planner describes one isolated transition, and the timeline audit requires
coverage through H+3 with no overlapping update during that short window. The
header verifier itself permits multiple sequentially committed roster changes.
The audit does not see the actual FinalizeBlock response or the application's
last-commit payload; those fields remain explicitly unverified in its result.

## Proposed wire/read contracts

Full rosters are ordered by decreasing power then increasing CometBFT address.
Each entry is exactly public_key (lowercase Ed25519 hex) and power (positive JSON
integer, not a boolean, string or float). At most 256 validators; total power is
bounded by the existing verifier's ((2^63)-1)/8 limit. Set hashes use the existing
SimpleValidator protobuf and RFC-6962 Merkle primitives. Update rows are sorted by
address and include only changed keys; removed keys have power zero. The wire
probe encodes only field 3 of ResponseFinalizeBlock, not a usable node response.

A policy separately pins engine-genesis bytes by SHA-256, a trusted anchor header
hash/height/time, expected block/application versions, a fixed trust interval and
clock-drift bound. A witness contains the policy digest and consecutive header
entries, each with current and next rosters. Both roster hashes must match the
ORIGINAL signed header. The next entry must use the previous signed next-set hash,
its complete preceding block identity, and a strictly later timestamp. Every
signature slot is verified, including nil votes and votes after a quorum was
reached. Only committing power counts; exactly two-thirds is insufficient.

There is no skip verification or trust refresh. Every extension re-verifies the
preserved path from the external anchor and refuses at expiry. An operator must
choose a defensible trust period relative to the future chain's security model;
the development bound of 31 days is not a recommended secure period. The proof's
last observed local clock cannot move backward within that proof lineage. This is
not protection against malicious clocks, malicious quorum, deleted files, copied
workspaces or whole-workspace rollback. Hashes alone do not establish the
independence or credibility of the original trust source.

A first-height anchor must also use the genesis validator-set hash. A later
out-of-band anchor may already be after historical changes; that pin explicitly
trusts its checkpoint and does not establish earlier chain history. Header-level
AppHash is exposed as an authenticated commitment but no native state, transaction
inclusion or execution receipt is verified by this module.

Limits: 64 added headers per call, 256 retained headers, 8 MiB documents. Exhaustion
refuses rather than pruning, skipping or changing anchors. The CLI writes a new
private proof file with explicit expected parent digest, leaving the prior file
unchanged. There is no competing fork selection or cross-device coordinator.

## Activation work still required

Before a changing-validator chain can be enabled, a separate protocol version or
explicitly reviewed migration must commit the validator registry, current/next
epoch, queued update and activation metadata in native state/AppHash. The state
transition must derive ABCI updates deterministically from authenticated authority,
not a local file or RPC validator list. CheckTx and proposal validation cannot
activate the set; durable block commit must preserve the state needed to reproduce
responses after interruption. Validator updates must be coordinated with proposer
priority and engine height semantics, not replayed merely because a process opens.

Who may authorize changes is UNDECIDED. The planner accepts no approval and emits
no signature. A future testnet mechanism could use explicitly pinned separate
administrative keys; staking or token-holder governance is a different design.
Do not ask consensus signing keys to sign arbitrary governance bytes. The exact
policy, epochs/nonces, delay/cancellation rules, key rotation, conflicting proposals,
minimum operational set, power concentration and takeover/liveness risk require
an explicit decision and review. No governance choice is installed by this draft.

Wallet, explorer and receipt verification need versioned adapters to the new
native commitment/evidence, keeping reservations and old receipt identities intact.
The new witness is not a substitute for the current wallet TrustAnchor. During
state sync, registry and queued changes must match the trusted AppHash and the
engine's separately verified validator history. Reject unknown snapshots/protocols;
do not treat peer-supplied rosters or unavailable old history as authorization.

## Required actual-engine acceptance

Use a disposable separately versioned test chain: one add, one removal, one power
change, overlapping update policy, unauthorized/stale/replayed proposals, delayed
activation, absent new validator, quorum loss/restoration, restart before/after
emission and activation, fresh observer across the boundary, and preserved wallet
receipt/hold behavior. Verify old clients fail safely, and compare hashes/protobuf
with the pinned upstream Go implementation. None of those changing-validator engine
results exists in this candidate. PR #23's static-validator results remain bound
to their own revision; source ancestry does not extend their qualification.

## Primary upstream references

- CometBFT v0.38.25 ABCI methods, FinalizeBlock and ValidatorUpdate:
  https://github.com/cometbft/cometbft/blob/v0.38.25/spec/abci/abci%2B%2B_methods.md
- CometBFT v0.38.25 adjacent light verification:
  https://github.com/cometbft/cometbft/blob/v0.38.25/light/verifier.go
- Existing 1soft static verifier (unchanged): src/commit_verifier.py at the base above.

No public network, staking program, bank/issuer promise, new coin supply, production
custody, external audit, deployment or real-funds readiness is implied.
