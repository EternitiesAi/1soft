# Bounded ABCI state sync — development checkpoint

27 September 2026. This is a local node-bootstrap mechanism for the native 1soft
application. It is not a public testnet, remote backup service, validator recovery
ceremony, pruning policy, or proof that an arbitrary peer is trustworthy.

## Why this exists

A new node should not have to replay every historical block merely to reconstruct
current application state. CometBFT v0.38.25 exposes the ABCI snapshot methods
`ListSnapshots`, `OfferSnapshot`, `LoadSnapshotChunk` and `ApplySnapshotChunk`.
Its state-sync implementation independently obtains the trusted AppHash through
its light-client state provider and, after restoration, checks the application's
reported height and AppHash. 1soft now implements the application half of that
contract with deliberately bounded, complete-state snapshots.

The state-sync AppHash is not learned from snapshot metadata. The offer contains
CometBFT's light-client-verified AppHash; all peer-supplied metadata and chunks stay
untrusted until reconstruction and native validation succeed.

## Snapshot format

Current application snapshot format: **1**.

A snapshot is canonical JSON under domain `1soft/state-sync/v1` containing:

- exact native genesis,
- application height,
- expected application hash,
- every native table required by that genesis, including execution receipts.

The descriptor uses a domain-separated SHA-256 over the exact payload. Metadata
binds format, height, chunk count, chunk size, total encoded bytes, native-genesis
digest and AppHash. The current development bounds are:

- 262,144 bytes per chunk,
- at most 64 chunks,
- at most 16 MiB encoded state,
- at most 4,096 bytes of metadata,
- at most two recently listed snapshots cached in one application process.

These limits make work finite. They do **not** make complete receipt history a
scalable final state-sync design. An oversized chain advertises no application
snapshot instead of silently truncating state.

## Serving

Only a committed application above height zero advertises a snapshot. A listed
snapshot's bytes are frozen in a small process-local cache, so a peer can continue
loading the exact descriptor it was given even if this application commits later
blocks while the transfer is in progress.

`LoadSnapshotChunk` cannot select arbitrary files. It serves only a cached/current
format-1 application snapshot and rejects unsupported heights/formats/indexes by
returning no chunk.

## Restoration trust boundary

A snapshot can be offered to either:

1. an uninitialized application started with an explicit expected native genesis,
   or
2. an untouched installed checkpoint whose state-sync marker and committed
   height/AppHash match and whose local block table is empty.

The second case recovers the narrow crash window where the application committed
a complete snapshot but CometBFT stopped before bootstrapping its own state store.
Recovery accepts only a same-height or newer snapshot, still pinned to the expected
genesis and CometBFT's trusted AppHash. A valid but lower-height offer is rejected
so CometBFT can try another snapshot; it must not roll the application backward.
A fresh application without an expected genesis aborts, and an initialized
application with ordinary block history remains ineligible.
Before accepting an offer, the application requires exact descriptor/metadata
agreement, its expected genesis digest, and the light-client AppHash supplied in
`RequestOfferSnapshot`. Chunk application then enforces the declared ordering,
size and count. Identical duplicate chunks are idempotent; a changed duplicate
rejects the snapshot; a future chunk requests the exact missing index.

After the last chunk the application:

1. verifies exact payload length and domain-separated snapshot hash,
2. parses only canonical bounded JSON,
3. verifies the expected genesis again,
4. restores the native ledger and validates receipts/invariants,
5. recomputes the application commitment at the offered height,
6. requires equality with the trusted AppHash,
7. initializes the compact proof index, or rebuilds it from the newly validated
   state during checkpoint recovery, atomically when SMT mode is enabled,
8. commits the restored/recovered state and local state-sync marker in one SQLite
   transaction,
9. only then exposes the restored state to the running application.

An internal database failure rolls the restore transaction back. Partially received
chunks are process-local; a process restart starts snapshot reception over rather
than treating partial bytes as application state.

Whole-snapshot/hash failure does not automatically blame the sender of the final
chunk because different peers may have supplied different chunks.

## The local marker is not consensus state

A successful restore writes `state_sync_marker(height, app_hash)` into the local
application database. It is deliberately outside the AppHash and exists to retain
where this particular application was bootstrapped.

State sync does not invent `/block/<snapshot-height>` metadata: that block record
was not executed locally. Later normally executed blocks are recorded as usual,
and the marker remains as a local provenance/recovery receipt. A restart at the
snapshot height requires the marker to match the committed checkpoint if no local
block record exists.

While the committed height/AppHash still exactly match this marker and no block
rows exist, it also identifies the narrow checkpoint-only recovery case above.
Once ordinary blocks are committed, recovery is closed; the marker stays only as
provenance.

The marker is not a remote proof, a validator vote, or an authority source.

## Actual-engine acceptance gate

`scripts/run_state_sync.py` is the new opt-in real-engine gate. It requires a real
pinned CometBFT v0.38.25 binary and creates:

- four local validator nodes serving a real chain,
- one fresh local non-validator configured for CometBFT state sync,
- two loopback RPC servers used by CometBFT's light client,
- a separately expected native genesis for the fresh application.

The runner first commits a native payment, captures a trusted height/hash, and
starts the fifth node from empty application state. A state-sync marker must appear.
Only after that marker is durable does the source chain commit another native
payment. The runner then removes validator quorum to freeze the head while leaving
source peers online. The restored node must continue through ordinary block sync
to that frozen head.

Acceptance requires:

- marker AppHash equals the source application block AppHash at the exact restored
  height,
- no local block metadata is invented at the restored height,
- target block metadata begins strictly after the snapshot,
- the exact post-snapshot native transaction ID appears in target receipts,
- target and source full application states/checkpoints agree at the frozen head,
- the original state-sync marker survives later block execution,
- the SMT variant can serve an account proof whose witness, requested account,
  height and AppHash verify against the recomputed matched full-state root.

The runner supports protocol 1/flat state and protocol 3/`smt-v1`. Missing engine
is **UNASSESSED**, never replaced by a fixture. For a report named `run.json`, the
runner retains the ten source/target app and engine logs plus a runner log in
`run.json.logs/` beside the report on pass and failure. Each log is capped at
1 MiB; named secret values are redacted, and the bundle contains no node homes,
databases or key files. Its manifest records hashes, sizes, truncation and run
status. Reusing the same report path replaces that report's prior log bundle.

This new gate has not been executed in the current runtime because the pinned
CometBFT binary is unavailable here.

## Evidence so far

Local application tests cover flat and SMT restore, exact proof-index restoration,
continuation into another block, process restart, crash after durable snapshot
install but before the apply response, same-height retry, recovery from a newer
snapshot after the source restarts/advances, lower-height rejection, and refusal
after local block history exists. They also cover wrong genesis/AppHash/format,
noncanonical/oversized metadata, corrupted final payload, duplicate/out-of-order
chunks, retained served snapshots, process-local partial chunks, local marker
integrity, transactional database failure, and closing restored ledgers on
post-restore AppHash mismatch.

The Python ABCI tests exercise all four snapshot calls through the application
wire dispatcher. The official-Go wire probe has also been extended with upstream
v0.38.25 snapshot request/response fixtures. Its new fixture run requires Go
module availability and remains a separate gate in this runtime.

The existing PR #12 four-validator delivery evidence remains valid for its exact
`dd096` source. It does **not** validate these new state-sync changes because this
checkpoint changes ABCI and application persistence code.

## Still required for public testnet

This implementation deliberately leaves several larger jobs open:

- execute the new real-engine state-sync gate and retain its raw logs,
- run state sync between independently operated machines, not five processes on
  one host,
- define snapshot availability/pruning/history policy,
- remove complete receipt-history growth from the long-term bootstrap design,
- define validator-set evolution and production light-client trust periods,
- independent security review and restore drills,
- public peer/RPC hardening, monitoring, incident response and release procedures.

No real funds should depend on this development checkpoint.
