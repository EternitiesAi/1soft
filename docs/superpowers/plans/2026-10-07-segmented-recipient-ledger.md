# Segmented recipient ledger implementation plan

> **For agentic workers:** Execute dependent tasks inline with executing-plans.
> Standing autonomous approval covers local implementation and bounded tests.

**Goal:** Qualify a durable, separately versioned recipient ledger beyond P8's
height, note, and decided-attempt limits without changing its proof circuit.

**Architecture:** Protocol9 owns new genesis/network/AppHash/storage identities.
The frozen relation8 proves membership in one registered sixteen-note segment.
Global SQL indexes prevent cross-segment replay; compact checkpoints and a
streamed full-history restart audit preserve execution authority.

**Tech stack:** Existing Python POSIX runtime, SQLite, pinned Halo2 recipient
bridge/helper/prover, CometBFT0.38.25, existing protobuf wire definitions.

**Spec:** `docs/SEGMENTED_RECIPIENT_DESIGN.md`

## Global constraints

- No P1-P8 runtime/profile/wire modifications or automatic migration.
- No public deployment, paid compute, GitHub Actions, real funds/production keys.
- At most two wires/block,4096bytes/wire,32768bytes/private FinalizeBlock request.
- Static four equal-power validators; full external genesis pin required.
- Full replay remains required on reopen; no pruning/state-sync claim.
- Fake-verifier unit results and actual native/engine execution stay distinct.

## Task1: Durable transition and lifecycle

Files: `src/protocol9_consensus.py`, `src/protocol9_store.py`,
`src/protocol9_application.py`, `tests/test_protocol9_ledger.py`.
Consumes existing `protocol8_worker.Worker`, `protocol8_transfer.parse`,
`protocol5_encoding.comet_validator_set`, and exact protobuf definitions.
Produces `genesis_document(raw,worker)`, `Store(db,g,worker).advance(txs,height)`,
and an ABCI-compatible `Application(path,worker,expected_genesis=raw)`.

- [x] Write failing tests for9 accepted payments/19 notes,80heights,40refused
  attempts,old-root replay rejection,and savepoint isolation.
- [x] Run `PYTHONPATH=src python -B -m unittest discover -s tests -p test_protocol9_ledger.py -v`.
- [x] Implement exact genesis,segmented roots/global indexes,compact history
  commitment,streaming restart audit,atomic Commit,and exact response recovery.
- [x] Add tests injecting failed block insertion and post-commit refresh failure;
  corrupt retained wires,responses,checkpoint,and global indexes must refuse.
- [x] Run the same test command and existing `test_protocol8_consensus.py`.

## Task2: Actual proof and engine qualification

Files: `src/protocol9_notes.py`, `src/protocol9_abci_server.py`,
`scripts/serve_abci_p9.py`, `scripts/run_protocol9_engine.py`.
Consumes Task1 Application and measured existing native binaries.
Produces a closed execution report and sanitized public artifact directory.

- [x] Reuse protected native process mechanics with a protocol9 bootstrap adapter;
  compare every returned public statement with the requested statement.
- [x] Bind only an owner-only Unix ABCI socket; explicitly decline snapshots.
- [x] Generate at least8 accepted native payments and a valid competing spend.
  Run four pinned engines through >64heights,>16notes,and a same-store restart.
- [x] Separately commit >32 decided refusals through the direct application.
- [x] Verify static-quorum signed header against the final AppHash,retain public
  proofs/logs/source/process receipts,and reap every owned process.

## Task3: Review and registration

Files: `docs/SEGMENTED_RECIPIENT_DESIGN.md`, `docs/CURRENT_QUALIFICATION.md`,
new `evidence/protocol9-ledger/20261007/`,private output result/continuity.

- [x] Audit segment rollover/global uniqueness and crash/replay boundaries.
- [x] Run a separate fresh Application replay against the actual retained store
  before discarding its owned temporary runtime.
- [x] Record exact source SHA,gate result,and source/binary/artifact hashes.
- [x] Check all P1-P8 historical/runtime bytes unchanged;check source whitespace.
- [x] Register only demonstrated results;retain multi-host,custody,state sync,
  pruning,long-duration load,freshness,and external review as unassessed.
