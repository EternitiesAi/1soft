# Local block-result retention — first history-bounding stage

27 September 2026. Candidate based on PR #14 at
`12436b9fd47b09a471b327da927263b568370d75` (tree
`17fd2b4939e6f1cd5d55e87229604c97795566e0`). This changes local application
storage, not the native monetary protocol. PR #11 is not a source dependency.

## What is bounded, and what is not

An operator can retain only the most recent N rows in the application database's
`blocks` table. These rows contain the locally executed block hash, transaction
list digest, AppHash and transaction results. They are outside consensus state.
The default on a never-configured database retains all rows.

**Native receipt history is NOT pruned.** Every native receipt remains in the
committed state, state-sync snapshots, authenticated full-state witnesses and
sparse-Merkle commitments. This preserves existing replay detection, historical
signature checks and the wallet's complete-history absence rules. The current
16 MiB state-sync snapshot limit, 20,000-record SMT bound and receipt growth remain.
This stage does not solve them or permit silently increasing those bounds.

CometBFT's own blocks, consensus state, evidence and validator last-sign records
are untouched. ABCI Commit still returns retain_height=0. A block-result row being
unavailable locally is not a missing transaction, a failed payment or a released
wallet reservation. SQLite may reuse freed pages without shrinking its file.
There is no total disk, total memory, throughput or public-network claim.

## Opt-in configuration

On the existing trusted local development host:

```sh
python scripts/serve_abci.py --db /private/app.sqlite \
  --socket /private/app.sock --genesis /private/native-genesis.json \
  --block-history-keep 256
```

The explicit value must be an integer in [2, 1000000]. At least the last two
locally executed blocks are retained when two exist; latest-commit replay and
startup checks remain available. This is not a promise about arbitrary deep
engine/application recovery. Engine and signing-state recovery still require the
existing coordinated operating procedures.

The selected policy persists in a node-local `block_history_policy` table, outside
AppHash. Omitting the flag when reopening REUSES the saved policy. Supplying a
different explicit value refuses startup rather than silently changing retention.
There is no endpoint or automatic path that disables a prior pruning frontier or
relabels the node as an archive. Removing local policy records is not a supported
reset procedure.

Enabling the policy on an existing retain-all store first checks its complete
local range, accounting for any state-sync bootstrap marker. Startup does not
prune. The next successful ordinary block commit enforces the window. An old
node with more than N rows may therefore temporarily exceed the window before
that next commit; /history explicitly reports within_configured_window=false.

## Atomicity and state sync

Deletion of the oldest local block-result prefix, its pruning frontier, the new
block result, native committed state and derived proof-index update share the
same SQLite transaction. Proposal/CheckTx/FinalizeBlock alone never prune.
A failed commit rolls everything back. Repeating Commit without a pending block
is not an independent pruning operation.

Startup audits the persisted policy, committed height/hash, bootstrap marker,
expected contiguous retained range and latest block hash. An unexplained gap,
extra old row, missing policy row or conflicting checkpoint is refused rather
than silently discarded. This detects normal storage inconsistencies, not
malicious same-user modification or restoration of an entire old workspace.

A state-sync target keeps its own local retention policy. The incoming snapshot
contains no history policy and never changes that policy. Installing the target's
bootstrap boundary joins the existing atomic snapshot/index transaction. An
untouched snapshot-only checkpoint can still use PR #14's bounded lost-final-reply
recovery. Once ordinary blocks exist, retained rows prevent pruning from making
the application appear fresh again. No source block records at or before the
snapshot are invented.

## Read interface

The unauthenticated current-state `/history` query reports the configured window,
bootstrap height, pruned-through height, retained range/count and receipt count.
It explicitly includes:

```json
{
  "native_receipts_pruned": false,
  "engine_history_pruning_requested": false,
  "historical_transaction_absence_proven": false,
  "total_storage_bounded": false
}
```

Existing `/block/H` queries for retained records are unchanged. With retention
enabled, an unavailable old record returns code 2 and a bounded JSON status:
`pruned_local_block_results` for deliberately removed local rows, or
`not_retained_by_state_sync` for heights the target never executed. A future block
or unexplained gap does not receive either explanation. Neither status is a
transaction non-membership proof; clients must not release holds from it.

`/state`, `/receipt/<txid>`, account queries, compact witnesses, snapshot bytes,
transaction encodings, monetary rules, grants and shared budgets are unchanged.
The feature cannot sign or broadcast. There is no public API deployment here.

## Executed comparison

The disposable measurement executes the same 512 application blocks and 32 signed
protocol-3 SMT transfers on retain-all and keep-16 applications. It checks equal
native state and AppHash at EVERY height, equal execution results, and exact
snapshot bytes/account proof at the end. Local block rows fall from 512 to 16;
their logical text payload falls from 102304 to 3197 bytes. All 32 native receipts
remain, including the oldest exact receipt. Snapshot size is unchanged by design.
This is not total database size, compression, validator traffic or TPS.

```sh
python scripts/measure_block_history.py --blocks 512 --keep 16 \
  --output /private/new-history-comparison.json
```

The deterministic seeds are public disposable test material. Do not use the
measurement's fixtures or development genesis for funds.

## Next stage: native history requires a versioned contract

Removing consensus receipts is a separate protocol change. Before it can replace
complete receipt history, the design must specify replay prevention after removal,
authenticated historical inclusion/absence, permanent preservation of accepted
receipt identity, wallet recovery when archival evidence is unavailable, and
state-sync validation without trusting a peer's claim of a complete archive.

In particular, "not in the retained window" must never become "never executed".
The current wallet's expired-and-absent retirement must not run against a partial
receipt table. Any future receipt accumulator or archival proof protocol needs an
explicit version/genesis boundary, format limits, adversarial tests and real-engine
acceptance; legacy protocol 1/2/3 commitments cannot be silently rewritten.

The present candidate therefore bounds a safe local layer first. Dynamic validator
sets, multi-host operations, custody and value-bearing release remain separate work.
