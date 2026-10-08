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

Segments retain the circuit's at-most-sixteen-note input set; public anchors
identify a segment prefix. This is not a new anonymity or metadata-privacy
qualification. Disk usage and restart audit cost grow with retained history.
The extension removes the old development caps; it does not establish general
production scalability or replace the separate wallet/custody design.

## Registered local execution

Clean source `3fed399b4f98b34cc1e220068c86fec8c51ac327` passed all 16 checks
in [ledger02](../evidence/protocol9-ledger/20261007/ledger-02.json). Four actual
pinned CometBFT 0.38.25 validators committed 10 genuine synthetic payments and 21
notes. The tenth payment committed after height 64 (observed application height 67).
All four agreed at height 83, authenticated by signed header 84. A validator
restarted its same stores and rejoined; a separate fresh worker streamed the
stopped node's full native replay at height 84. A valid competing spend of the
original input was refused at every validator after segment rollover.

The direct application probe retained 50 attempts (10 accepted/40 malformed refusals)
at height 51 and reopened through native history replay. This is separate from
the actual-engine result, which did not commit those malformed transactions.
The [separate public check](../evidence/protocol9-ledger/20261007/public-check-01.json)
reverified 11 native proofs and the static-quorum signed checkpoint; it does not replay
public full history or establish freshness. All owned processes stopped.

The 21 ledger tests use a labeled fake verifier for transition/storage boundaries.
The full unit run executed 1,757 methods: 1,597 passed and 160 skipped because their
older pinned proof/origin/worker inputs were not supplied. Skips are unassessed,
not cryptographic passes. The initial actual run's pre-block1 admission refusal
is retained as [ledger01](../evidence/protocol9-ledger/20261007/ledger-01.json).
The runner now waits for a committed first block, preserving validity checks.
Post-execution changes register docs, evidence, the additional tested boundary
file, and the separately executed verifier; original executed runtime bytes stay
unchanged. [Review/reproduction](../evidence/protocol9-ledger/20261007/REPRODUCE.md)
records the exact scope and source distinction. This is not independent external
security review, a wallet alpha, an independent-host trial, or a public release.
