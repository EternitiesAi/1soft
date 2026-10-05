# Protocol 6 treasury implementation plan

> **For agentic workers:** Use `executing-plans` inline; delegate read-only independent reviews. Root owns all edits because the preferred MiMo coding route requires paid compute excluded from this task.

**Goal:** Commit a combined private treasury payment through real local validators with exact current authority and durable recovery.

**Architecture:** A new pure P6 state machine stages ordered execution before an atomic SQLite checkpoint. A pinned verifier-only Rust bridge reuses the frozen relation, while an independent static-validator certificate checks the full genesis-bound state against H+1.

**Tech Stack:** Python 3, SQLite WAL, Halo2/Pasta, Rust 1.97.1, CometBFT 0.38.25 and existing bounded protobuf transport.

**Spec:** `docs/superpowers/specs/2026-10-04-protocol6-treasury-design.md`

## Global constraints

- Existing P1-P5 and both proof labs remain byte-identical.
- No Actions, paid/public compute, public deployment, DNS, other project work, real funds, production keys or force pushes.
- Fresh exact pinned genesis; fixed four equal-power validators; no unsigned owner lifecycle, snapshots or old wallet integration.
- K14/25 fields/3200 proof bytes/4008 transaction bytes; 64 heights, 2 transactions per block, 8 candidates, 64 history transactions, 16 notes, 7 accepted payments, 256KiB state.
- Invalid proof is a transaction reject. Missing/failed verifier is fatal and cannot be cached as a proof reject.

### Task 1: State, genesis and verifier contract
Create `src/protocol6_treasury.py`, `src/protocol6_worker.py`, `scripts/protocol6_worker_exec.py` and `tools/treasury-consensus-bridge/`. Create `tests/test_protocol6_treasury.py` first. Consumers use `genesis_document(raw)->dict`, `initial_state(g,worker)->dict`, `execute_block(g,state,txs,height,worker)->(dict,list)` and `Worker(binary,sha,kat)->worker`; no caller can select a profile dynamically.

- [ ] Run the failing tests with the new module absent; failure names the missing feature.
- [ ] Implement closed canonical genesis, independently derived transitions and receipt fields. Test real fixtures with literal accepted count=2, fees=4, note count=6 after a+after_a_b; stale b and duplicate_request are nonzero.
- [ ] Build the verifier-only bridge release/locked/offline, pin the measured binary and KAT, run real valid/corrupt/boundary requests. Missing binary and changed binary must raise unavailable, not return an invalid-proof code.

### Task 2: Durable ABCI application
Create `src/protocol6_application.py`, `src/protocol6_abci_server.py`, `scripts/serve_abci_p6.py` and `tests/test_protocol6_application.py`. Preserve generic protobuf wire fields. `Application(path,worker,expected_genesis=bytes)` requires its genesis pin. All lifecycle signatures match the engine adapter; query returns committed state only.

- [ ] Test staged payment remains invisible until Commit, replay identity, immutable validator hash, changed genesis, schema corruption, SQL-trigger rollback and abrupt process death before/after SQLite commit.
- [ ] Implement atomic checkpoint plus exact retained block response. Reconstruct all state/results through replay on reopen and compare canonical bytes and AppHash.
- [ ] Verify snapshots/revocation are refused and old protocol inputs cannot enter the new state machine.

### Task 3: Actual validators and signed evidence
Create `scripts/run_protocol6_engine.py`, `src/protocol6_certificate.py`, `tests/test_protocol6_certificate.py`, `tools/release/check_protocol6.py`, and `docs/PROTOCOL6_TREASURY.md`. `verify_state(value,signed_header,raw_genesis)->dict` authenticates state H through signed H+1 with exact static genesis.

- [ ] Write certificate mutation tests, then require signatures, strict quorum, next-height AppHash, chain/validator identity and exact witness fields.
- [ ] Run a finite four-validator fresh loopback network using the exact engine SHA. Stage both conflicting proofs without quorum; resume quorum, verify one accepted and stale loser refused. Submit the appropriate refreshed proof; verify two payments, fees=4 and all authority/value transitions agree. Restart one node with unchanged engine WAL/application store and converge again.
- [ ] Bind source commit/tree, binary hashes, fixture hashes, exact check roster, sanitized raw log hashes, certificate and receipts into an external report. Reject altered, incomplete or failed reports. Preserve failed candidates.

### Task 4: Integration and private delivery
- [ ] Independently review state/worker/recovery/evidence, fix defects and rerun affected gates.
- [ ] Extend the root source manifest, run checkout gate and targeted P5 regression checks. Commit qualified source before the final real-engine run.
- [ ] Register exact evidence, push a normal private branch, open/attach PR, merge the verified head under standing authorization and verify the merge tree.
- [ ] Deliver complete source plus sanitized raw execution logs and CODEX_RESULT.md/json in one ZIP. State static-grant, single-host, no seccomp, finite history and unsupported wallet/redemption limits explicitly.
