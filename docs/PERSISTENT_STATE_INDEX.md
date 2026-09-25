# Persistent authenticated proof index — 1soft v0.14

## Purpose

The v0.13 application rebuilt a sparse Merkle tree from the complete committed
snapshot each time a client asked for an account or transaction proof. The new
index persists the tree's compressed branches and leaves and reads just the
requested paths. Clients receive exactly the same root, proof format and bytes.
No new monetary protocol, asset, genesis option or cryptographic primitive is
introduced. It applies to the existing explicitly selected protocol-3 `smt-v1`
chains. Legacy commitment modes retain their previous behavior.

## Implementation

`src/state_index.py` stores a compressed binary tree in two tables within the
application's existing SQLite database: `proof_nodes` and `proof_checkpoint`.
A node locator binds its depth and canonical 256-bit path prefix. A nonempty
leaf binds the original state table, logical key and canonical row bytes. Branch
hashes and default-path expansion use the unchanged v0.13 SHA-256 construction.
There are exactly **2n-1 stored nodes for n nonempty records**, or zero for an
empty map. Unary paths are not stored as 256 database rows per record.

Insertion splits at the first divergent bit. Replacing a row updates that leaf
and its ancestors. Removal collapses a now-unary parent. The algorithm rejects
key/path collisions and validates parent-child direction/depth. An update checks
the previous affected row against the indexed root rather than trusting the
caller's claimed old value. The resulting root must match the application hash
already computed during finalization by the reference implementation.

The current application scans the previous and pending snapshots to discover
changed rows. Therefore only *tree writes and subsequent proof reads* are
incremental. Native transaction replay, snapshot serialization, finalization's
reference-root calculation and startup validation still process the full state.
This is not a replacement production execution/storage engine or a TPS claim.

## Atomicity and recovery

The index shares the application's database and transaction boundary. Committed
snapshot, index checkpoint and block execution record update in one transaction.
There is no second database commit that could leave balances at one height and
proofs at another. The index's own savepoint rolls back failed edits without
committing or discarding unrelated work in the caller's transaction.

Prepared and finalized-but-uncommitted proposals cannot leak into public proofs.
A crash after index updates but before commit reopens the old state and root. A
crash after commit reopens the new state and root. These exact process-termination
cases ran in tests; they do not simulate every OS, disk, filesystem or power-loss
failure. WAL and FULL synchronous settings remain the existing local-store policy.

A previously initialized v0.13 SMT database with no index can receive a one-time
derived index after the original snapshot and receipts validate. Native history,
block records and application hashes are not rewritten. An existing corrupt,
stale or incomplete index is refused rather than silently cleared or rebuilt.
Startup audits every reachable node and detects orphaned nodes. Proof generation
also validates its traversed paths and runs the unchanged verifier before serving
its response. No automatic repair command or downgrade migration is delivered.

The reference option `BlockApplication(..., proof_index=False)` remains available
for a new index-free comparison database. It refuses to disable an existing
initialized index, avoiding stale index state after later commits. An older
application version would not understand these local safeguards: do not downgrade
an indexed node without an explicit reviewed migration.

## Limits and threat model

This is a derived local index, not consensus. It cannot authenticate a genesis,
prove independent validator operation or authorize spending. The existing
20,000-native-record prototype bound is unchanged. The index uses additional disk
space and imposes additional work on block commits; the benefit measured here is
proof-read cost. Whole-state storage, pruning policy, distributed synchronization,
production resource economics and a dynamic-validator light client are unfinished.

The same application writer lock and trusted local filesystem assumptions apply.
Cryptographic consistency checks do not prevent a malicious operator from restoring
an older *complete* node database, changing trusted software or controlling the
validator majority. This is not hardware rollback protection or an independent audit.
The JSON proof format remains project-specific, not ICS23/IBC/ABCI ProofOps.

## Observed measurement

A reproducible run executed **1,024 signed native owner transfers in 16 local
application blocks**. The map then contained 1,030 records and 2,059 stored nodes.
After warming both paths, 12 reads per method alternated their measurement order.

| One account proof | Median in this run |
|---|---:|
| Whole-tree reference rebuild | 159.567029 ms |
| Persistent-index read, including server-side proof verification | 1.303690 ms |

The ratio in this run was **122.40x**. Every returned proof was byte-for-byte
identical, at 1,624 serialized bytes (without a signed header). Each indexed read
performed 24 node fetches and zero node writes. One subsequent signed native
transfer changed 5 records and performed 59 node writes, not a full-tree rewrite.
The after-update index contained 1,031 records and 2,061 nodes and passed its audit.

This is Python 3.13.5 / SQLite 3.46.1 on one development Linux environment with
warm local caches. There was no HTTP server, live validator, network bandwidth,
fee or transaction-throughput measurement. Timings will vary. The benchmark does
not establish that total block execution became 122 times faster.

## Reproduction

With the repository's pinned Python dependencies installed, no Actions are needed:

```sh
python scripts/check_index.py
python scripts/check_index.py --application
python scripts/check_index_guards.py --output evidence/my-index-guards
python scripts/measure_indexed_proofs.py --output evidence/my-index-measurement
```

The first command checks the standalone index module's five-file inventory and
runs 31 tests. The second requires the complete local package and runs all 55 new
index/application tests. Neither is the full 760-case cryptocurrency suite.
The measurement creates disposable native state and refuses existing output
folders. It uses publicly known fixture keys, never real funds.

## Primary architectural references

The implementation is original project code using the existing project tree format.
SQLite's transaction/WAL documents explain the local atomicity model. Their stated
filesystem and synchronization assumptions still apply. CometBFT's application
hash is the externally verified commitment; a locally consistent index is not
itself an independently trusted chain state.

- https://www.sqlite.org/wal.html
- https://www.sqlite.org/lang_transaction.html
- https://www.sqlite.org/atomiccommit.html
- https://github.com/cometbft/cometbft/blob/main/spec/core/data_structures.md
