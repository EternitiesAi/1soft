# SIP-0003 — Authenticated development registry before native activation

Status: Draft; registry-only reference plus a separate opt-in P4 development integration.
Date: 28 September 2026 (America/Chicago).
Base: 7d860457fa85950f81aaa67f7cd3c98a979d5bbc / SIP-0002.

## Decision for this isolated experiment

SIP-0002 intentionally did not select governance. This follow-on implements one
explicit, opt-in DEVELOPMENT policy: separately pinned Ed25519 administrative
keys authorize delayed roster changes with a threshold greater than two-thirds.
These are not the validator consensus keys, token votes, agent budgets or arbitrary
wallet owners. No hidden key, default master key or production administrative
policy is inserted into P1/P2/P3. Users selecting this development genesis must
understand that its administrative threshold controls future validator membership.

The registry-only reference remains under `tools/validator-registry`. Its pure
rules also live in `src/registry_rules_core.py` for a separate fresh-genesis P4
development application. The P1/P2/P3 node and static clients reject P4. The
registry app version 4001 is distinct from monetary protocol version 4. See
[P4 development scope](../PROTOCOL4_DEVELOPMENT.md).

## Authorization

Canonical body fields bind schema/format, chain, canonical genesis hash, policy
hash, next administrative sequence, expected active epoch/hash, inclusion validity
and operation. Signatures use the separate byte prefix
`1soft/validator-registry/authorization/v1\0` followed by canonical body bytes.
Every distinct provided signature is verified; sorted signing keys make the packet
format deterministic. Another valid signature subset for the same action does not
bypass its sequence. The exact submitted envelope digest enters the action receipt.

Genesis fixes key count, threshold, minimum delay, cooldown, minimum roster and
maximum per-key power. Mutable policy updates, admin key rotation/recovery,
proof-of-possession enrollment, bonded stake, slashing, supply and fees are outside
this slice. Loss of enough admin keys can freeze governance; collusion can take
over the validator roster. Distinct keys do not prove independent operators.
There is no claim this is the correct eventual public governance system.

## State and progression

Committed state contains the genesis/policy commitments, height, administrative
sequence/receipt-chain head, active and next rosters/hashes, epoch, optional pending
proposal with its exact signed-wire digest, and last activation height. Successful
schedule/cancel actions extend the receipt chain. Invalid actions leave these
fields unchanged except for ordinary height-driven transitions when their block
is committed.

A scheduled update emitted at E appears in the H+1 next-validator commitment and
activates at E+2. The application advances epoch at that activation; at E+3 its
last-commit context uses the changed set. Emission runs before actions at E;
cancellation at E is refused. Queue cancellation before E needs equal authority
and cannot reuse a sequence. There is one pending update and a post-activation
cooldown to avoid overlapping transition windows.

CheckTx and proposal validation do not persist. FinalizeBlock returns a repeatable
candidate response; Commit persists exact response, input wires and registry state
in one SQLite transaction. Restart replays every block and validates all admin
signatures and results. A finalized-but-uncommitted update remains uncommitted; an
already committed emission is available for response recovery but is not emitted
again during an empty Commit retry or process startup.

## Evidence and compatibility

Registry snapshots require externally supplied expected hash/height and exact
signed-action replay. The combined evidence adapter additionally checks the
existing dynamic header witness, exact signed-block inclusion and authorized roster
timing. It does not interpret a valid committee signature as administrative approval.
Both signature systems have to agree with the same executed registry history.

The registry state hash is domain-separated. It does not replace the legacy
`application_hash` or reinterpret `smt-v1`. Bare registry snapshots have no native
money state. The current wallet's static verifier continues rejecting changing
sets, and its pending obligations/old receipts are unchanged. No archive absence
claim becomes release-of-funds authority.

## Native integration and remaining activation gates

The separate P4 development implementation establishes one versioned state and
atomic commit for registry plus monetary execution. It binds the initial engine
set and full genesis, checks next-set and last-commit context, and keeps
administrative and payment authority separate. This does not activate P1/P2/P3.

Any migration of a running network still needs its own activation height,
legacy-client refusal, proof schema and rollback rules. Dynamic validators also
need versioned wallet/explorer/receipt verifiers. P4 format-2 state sync restores
registry and queued updates against CometBFT's authenticated AppHash while
refusing unverified historical block evidence. Static checks remain in place.

Test actual CometBFT additions, removals, reweighting and full replacement; a new
validator absent at activation; no quorum before/after transition; restart around
emission and H+2; response replay after Commit; observer state sync across an
emitted update; and the same native receipt/hold behavior as the current money
chain. Compare the new full FinalizeBlock bytes with the pinned Go implementation.
The separate P4 runner covers a subset on one disposable host; remaining
scenarios are unassessed in this candidate.

## Primary reference

CometBFT v0.38.25 `spec/abci/abci++_methods.md`, FinalizeBlock field3 and the
E/E+1/E+2/E+3 schedule, blob `ca4614069cff735c24b20c3d015be874ed21cc4c`:
https://github.com/cometbft/cometbft/blob/v0.38.25/spec/abci/abci%2B%2B_methods.md

The source-bound validator-transition module implements the predecessor
next-set checks. Its spec/probe is a reference, not a completed upstream or network
qualification. This draft does not authorize public deployment, real funds or
changes to existing production paths.
