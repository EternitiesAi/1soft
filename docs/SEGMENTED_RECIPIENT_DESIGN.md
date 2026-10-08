# Segmented recipient ledger development design

7 October 2026. Scope: a separately versioned, private, one-host development
application using the frozen P8 recipient proof relation. This is not a public
network, production custody, P8 migration, or an independent cryptographic review.
Dom's standing authorization covers local implementation and verification;
public deployment, paid compute, real funds, and production keys remain excluded.

## Decision

A larger circuit would change proof and verifier identities and require new
cryptographic qualification. Raising P8 constants cannot change its four-level
membership relation. Use a fresh protocol-9 consensus genesis and bootstrap,
keeping the exact relation-version-8 wire and verifier frozen. A note belongs to
one append-only segment containing at most sixteen commitments. Register every
native root produced by a segment prefix. Once full, begin a fresh segment.
Any registered root may authorize a proof, while nullifiers, request identities,
and output uniqueness are global across all segments. Segments are not epochs:
crossing a boundary never resets spending authority or revives consumed notes.

## Durable state and bounded work

SQLite retains indexed commitments, native roots, nullifiers, requests, and
complete decided block records. A small checkpoint retains only the active
segment, counts, collected fees, and an incremental history digest. Each block
has at most two wires of at most 4096 bytes. Heights are signed 64-bit CometBFT
heights; accumulated fees refuse unsigned 64-bit overflow. No application cap at
64 blocks or 32 attempts exists. Disk usage grows; pruning and state sync are
explicitly unsupported in this first implementation.

An AppHash commits the external full-genesis digest, height, compact checkpoint,
and domain-separated digest of the entire ordered block history. The digest is
not a replacement for executing proofs. Reopening streams every stored block
into a fresh temporary replay database, verifies native proofs and exact retained
FinalizeBlock requests/responses, and compares every derived index and checkpoint.
Restart cost remains linear in history; current-block memory does not contain
that history. No full-state certificate or wallet compatibility is claimed.

## Lifecycle and trust

Prepare/Process/Check use rolled-back SQLite savepoints and cannot reserve notes.
Finalize stages a bounded request; Commit atomically installs the monetary delta,
checkpoint, and exact response. Failed commits roll back. An exception after
durable commit closes the application so it cannot serve stale memory. The
private owner-controlled ABCI socket is trusted engine control. Four static,
equal-power validators and external genesis authorization remain assumptions.
No TCP application endpoint, dynamic validator management, or autonomous signer
authority is introduced. AI operation is a later constrained operator interface.

## Acceptance

Unit tests use a clearly labeled fake verifier to exercise segment boundaries,
global double-spend protection, proposal isolation, capacity/overflow refusal,
commit faults, corrupt history/index refusal, and reopen behavior. Separately,
the real pinned CometBFT 0.38.25 engine and native verifier/prover/helper must
commit at least eight synthetic payments, exceed sixteen notes and height64,
agree across four validators, restart, and refuse a cryptographically valid
competing spend anchored in an older segment. A separate direct-application probe
must retain more than32 decided attempts. These scopes must remain distinct.
Raw sanitized logs, clean source identity, public proof artifacts, process
identities, and exact passed/failed/unassessed outcomes are retained.

## Remaining launch gates

Independent hosts/operators, protected signers and double-sign fencing, compact
authenticated wallet witnesses, scalable custody/discovery/recovery, pruning,
state sync, dynamic validator governance, hostile-network testing, long-duration
measurement, external review, and economics are not established by this gate.
