# State-sync checkpoint verification — 27 September 2026

## Exact baseline

Development starts from the source and evidence published as PR #12 head
`dd096271f24e704d27f39d551d5f16986934481d`, tree
`5e1e7385033bdfa1f5e31821c7be8d1b101a2a40`. The owner-supplied refreshed handoff
ZIP was independently hashed in this runtime as
`8395c131a62166dbcf57812b4c07f8a24c77fb118c1b182f71179e7b477576ee`;
its package inventory and source tree matched. PR #11 remains a separate line.

This continuation also includes the already-tested receipt-order recovery that
confirms an older exact receipt as `already_recorded` when the wallet has already
advanced through a later state. That behavior is documented separately in
`tools/wallet-delivery/RECEIPT_ORDER.md`. It does not change native monetary rules.

## New node behavior

The application now implements CometBFT v0.38.25 ABCI snapshot serving and restore:
ListSnapshots, OfferSnapshot, LoadSnapshotChunk and ApplySnapshotChunk. Format 1
contains bounded canonical complete native state; an offered snapshot can initialize
only a fresh application pinned to the expected genesis. Before durable install the
application checks descriptor metadata, domain-separated snapshot hash, full native
receipt/invariant restoration and the application commitment against the externally
supplied trusted AppHash.

SMT nodes initialize/audit their persistent proof index in the same restore
transaction. A successful restore writes a local state-sync marker but no synthetic
block record at the snapshot height. Later normal block commits preserve that marker
while recording only blocks this application actually executes.

## Executed local tests

The complete root Python test inventory was run in completed bounded groups because
one mixed group exceeded the tool deadline. The incomplete invocation is excluded.
The completed groups reconcile to **999 distinct Python tests**, all passing with
zero skips/failures/errors. The state-sync/ABCI/node/index focused final rerun passed
158 cases.

The decision-delivery add-on was run separately in eight bounded partitions. One
aggregate attempt and one earlier partition invocation hit the execution deadline
and are excluded; the completed/retried partitions reconcile exactly to **71/71
distinct delivery tests**, all passing. The separate JavaScript reference passed
30/30 tests.

The root required-source inventory now contains 108 files and matches exactly; its
final manifest SHA-256 is
`87571801d9ff4bc3c064f8bd6d05d37b5d41dfd26447a4212ce7c2e20ce7d705`.
The delivery add-on inventory contains eight files and matches exactly; its
manifest SHA-256 is
`b3704fe5716c6eb977a0774f71dcea6448b48098f5dc0c0dc71e791e1f240e65`.

State-sync tests cover flat and `smt-v1` restoration, persistent proof-index audit,
next-block deterministic continuation, wrong genesis/format/AppHash, canonical and
size bounds, corrupted final payload, duplicate and out-of-order chunks, retained
served snapshot bytes as the source advances, process-local partial chunks and
restart, local marker tamper detection, and atomic rollback on an injected database
install failure.

The real-engine state-sync runner has nine local unit tests, including bounded
sanitized log retention on child failure, exact post-snapshot transaction-ID
matching, and SMT proof verification against the matched recomputed state root.
The five-node acceptance has four source validators plus one fresh non-validator.
The target must
state-sync, retain its exact marker, then execute a transaction committed *after*
the snapshot through normal block sync and converge with the frozen source head.

## Upstream wire and engine status

The Python protobuf mapping was checked against the pinned upstream
`proto/tendermint/abci/types.proto` state-sync fields. The official-Go wire probe was
extended with OfferSnapshot, LoadSnapshotChunk, ApplySnapshotChunk, ListSnapshots
and corresponding response fixtures.

At original handoff authoring, offline Go module resolution failed and the pinned
CometBFT binary was absent. Those attempts were UNASSESSED with zero engine
checks. This file records that handoff; later Codex results must be read from a
validation receipt tied to the exact source commit and engine hash. No simulated
engine substitutes for a real-engine gate.

PR #12's saved 22/39/62/67 real-validator results were independently reviewed from
the supplied archive, but they apply to dd096. They do **not** qualify these new
ABCI/state-persistence bytes.

## Remaining acceptance

For each source revision called engine-qualified:

1. run the extended official-Go wire probe on the exact checkout;
2. run `scripts/run_state_sync.py` with CometBFT v0.38.25 for protocol 1/flat;
3. run it again for protocol 3/`smt-v1`;
4. retain the runner-owned capped app/engine log bundle and exact source/binary hashes;
5. repeat bootstrap between independently operated machines before public testnet.

Complete receipt history still grows with chain history and snapshots are capped at
16 MiB. Snapshot pruning/history policy, dynamic validator trust, hostile peer tests,
production recovery, public economics and independent review are not complete.
No public network or real-funds readiness is claimed.
