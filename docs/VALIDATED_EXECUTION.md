# Validated execution snapshots — 1soft v0.15

This change is in the cryptocurrency node, not the Resident, identity, website or banking lanes. No new consensus, monetary rule, genesis version, address format, signature domain or proof format is introduced.

## The repeated cost removed

Previously every `CheckTx`, `PrepareProposal`, `ProcessProposal` and `FinalizeBlock` rebuilt an in-memory ledger from the application's complete committed snapshot. Restoring that ledger rechecked its entire saved receipt chain, including historical signatures. Repeating that process for each proposed transaction made even a rejected signature expensive as receipt history grew.

The new default retains one process-local, read-only SQLite image of validated committed native state. A trial obtains a separate database through SQLite's backup API. The native transaction implementation is unchanged: it still checks the new signature, current nonce, expiration, recipient, grant, parent budget, fees, funds and accounting invariants.

This is an execution optimization, not a remote state cache. No peer can upload an execution image, select its source, or mark its data trusted. The image is derived only inside the local application lifecycle.

## Validation and commitment boundaries

On startup, the node checks the stored application's hash, restores and validates all native records and historical receipts, checks the last committed block, and audits the persistent proof index when enabled. Only then does it create an execution image. It does not deserialize an unaudited cache from a second disk file.

On genesis initialization, it constructs and validates the native ledger normally, computes the application hash and prepares an image before committing initialization.

Checks and proposals always fork the **committed** image. Each fork is independent; successful or failed trial transactions cannot spend the committed balance or consume a different proposal's allowance. Each operation creates its own connection in its calling thread. The shared read-only source is protected by a lock and supports the application's actual cross-thread ABCI handlers.

Finalization constructs a separate candidate image from its own executed ledger. Its genesis, height and application-hash checkpoint must match the staged block. The candidate does not become visible to checks, queries or proposals while the block remains uncommitted.

Commit first persists the native snapshot, block metadata and persistent proof-index update in the existing atomic database transaction. After that commit succeeds, it promotes the candidate image and closes the old one. An exception before commit retains the old image and the candidate for an explicit retry. A process exit after disk commit reconstructs the new image from revalidated disk state when the node restarts.

A missing image or inconsistent checkpoint raises an internal fault rather than silently selecting another state or reporting an ordinary invalid transaction. There is no fallback that hides cache corruption. `execution_cache=False` explicitly selects the previous slow reference path at process construction for testing; it is not peer-controllable or an automatic error recovery route.

## Read-only source and isolation

The cached source is a dedicated SQLite connection with `query_only=ON` and a read-only SQL authorizer. Its checkpoint is immutable metadata. Before cloning, the implementation checks the expected genesis/height/hash, that the source is still query-only, and that its change counter is unchanged.

The backup goes into a newly constructed, separate `NativeLedger` database. Its connection remains writable for the proposed execution; source connection settings do not become consensus state. Mutating or closing a trial cannot alter the source. The source can also be closed while an already-created trial remains valid.

These are trusted-process integrity controls, not protection against arbitrary Python code, memory corruption, a malicious OS, or an attacker who can replace the full program. The image's claimed hash is supplied by the application that already computed and validated it; the helper is not a standalone proof verifier. Use authenticated client proofs for remote trust.

## What stays expensive

Each trial still copies database pages. Native invariants and state-hash generation still scan state. Finalization still calculates the reference commitment, serializes a full snapshot and persists it. Startup retains full historical validation. The committed image and, during finalization, a second candidate image consume additional RAM alongside transient trials. The measurement reports SQLite page allocation, not total process memory.

This is not a zero-copy state machine, history pruning, a transaction-per-second benchmark, a fee policy change or a general solution to denial of service. Untrusted transaction admission, resource pricing and production storage require further work.

## Reproduce locally

With the complete source and installed pinned dependencies:

```sh
python scripts/verify_checkout.py
PYTHONPATH=src:tests python -m unittest test_execution_snapshot -v
python scripts/measure_execution_trials.py --output NEW_MEASUREMENT_DIRECTORY --transfers 1024 --repeats 12
python scripts/check_execution_guards.py --output NEW_GUARD_DIRECTORY
```

The measurement first executes 1,024 signed native transfers in 16 local blocks. It opens two nodes over copies of the same persisted state, with the cache on and off. It alternates 12 admission checks per path for a valid new transaction and an invalid signature. Responses must match and the committed state must remain unchanged. Historical-validation call counts are collected separately from timing samples.

The original run measured 138.875402 ms versus 1.506432 ms for a valid payment (about 92.19x) and 154.958627 ms versus 1.227046 ms for an invalid signature (about 126.29x). These are local measurements, not promised service performance. Each reference check scanned 1,024 old receipts; the cached checks scanned zero old receipts and still validated the incoming transaction. The execution image occupied 1,560,576 SQLite page bytes in that dataset.

## Primary API basis

SQLite's backup API and Python's connection API are upstream facilities, not new cryptography or a proprietary database primitive:

- https://www.sqlite.org/backup.html
- https://docs.python.org/3/library/sqlite3.html#sqlite3.Connection.backup
- https://docs.python.org/3/library/sqlite3.html#sqlite3.connect

Our checkpoint/promotion/isolation code and tests are project-specific. Native protocol and committee assumptions are unchanged. No actual CometBFT engine, independent validator operator, public network, real funds, or security audit is claimed.
