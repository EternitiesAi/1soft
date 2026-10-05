# Atomic Private Treasury Implementation Plan

> **For agentic workers:** Use `dispatching-parallel-agents` for genuinely independent tasks or `executing-plans` for inline task-by-task execution. Steps use checkbox syntax for tracking.

**Goal:** Execute conserved private note payments and shared allowance successors
atomically, and preserve exact unresolved obligations across interruption.

**Architecture:** A new isolated Halo2 profile shares cells for the full monetary
and allowance relation. A trusted local SQLite ledger selects current authority
and atomically commits the combined transition. The durable outbox preserves
original bytes without automatic replacement or retry.

**Tech Stack:** Rust1.97.1, pinned Halo2/Pasta/Poseidon, Python3/SQLite, WSL.

**Spec:** `docs/superpowers/specs/2026-10-04-atomic-private-treasury-design.md`

## Global Constraints

No paid compute, Actions, public deployment, DNS/site changes, Resident/Luna/Psyche
work, real funds, production keys or force pushes. Preserve all P1-P5 and prior
authority lab bytes. Trusted local scope only; no validator or production claim.

### Task 1: Combined proof

Create `tools/private-treasury-payment-lab/halo2/src/{relation,circuit,proof,wire}.rs`
and `halo2/tests/{relation,proof}.rs`. Assignment public has25 fields; witness
contains old private counters and restricted input/merchant/change openings.
`validate(&Assignment)` enforces integer conservation; `derived(&mut Assignment)`
binds notes/nullifiers/request; `Profile.prove` and `Profile.verify` use one circuit.

- [x] Write adversarial note-value/change-key tests and run them against the
      authority-only relation: `cargo test --offline --test relation` must fail.
- [x] Constrain shared amount/recipient/secret cells and exact positive64-bit
      conservation. Run native and MockProver attacks, e.g. input9/payment4/
      change4/fee2 must fail both; input10/payment4/change4/fee2 must pass.
- [x] Generate actual proofs; mutate public bindings/corrupt/truncate/append and
      require rejection. Emit pinned measurement/profile identities.

### Task 2: Atomic execution and obligation continuity

Create `scripts/ledger.py`, `scripts/test_ledger.py` and Rust bounded verifier/
fixture commands. Binary transaction =25 canonical fields followed by exact proof.
`Ledger.apply(raw,height)` returns exact transaction identity after one atomic
commit. `Outbox.retain(raw)` and `claim(txid)` preserve bytes and claim once.

- [x] Write tests against missing implementation for atomic rollback, old-current
      rejection and exact-byte outbox recovery; record failing behavior.
- [x] Implement strict parsing and one serialized SQLite transaction containing
      state, authority, note outputs, nullifiers, fees and receipt.
- [x] Run real proof races in both orders, refreshed exact parent exhaustion,
      revoked stale/refreshed survivor, before/after commit interruption and
      process restart. Assert concrete note/fee counts and unchanged failure state.

### Task 3: Exact qualification and delivery

Create `PROFILE_V1.json`, scripts/qualify.py, component/dependency receipts and
README. Add product evidence doc and source inventory. No accepted-runtime edits.

- [ ] Commit tested source, then run clean offline release tests and local ledger
      scenarios with actual verifier. Pin source/tree, test roster, binary and
      sanitized log hashes; reject altered/duplicate-key/claim/source receipts.
- [ ] Read-only review the relation and failure boundaries; resolve defects and
      rerun affected checks. Prepare source+logs ZIP and CODEX_RESULT.md/json.
- [ ] Publish branch, PR and merge using supported authenticated access and
      existing authority; verify exact merged tree and preserve raw failures.

Execution checks are recorded in the component qualification receipt. Publication and final source delivery are verified in the external CODEX_RESULT, not inferred from these checkboxes.
