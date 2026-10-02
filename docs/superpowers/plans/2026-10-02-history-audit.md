# Wallet history audit implementation plan

> **For agentic workers:** Root implements sequentially; reviewers inspect independently without changing source or running shared workloads.

**Goal:** Remove measured repeated full proof replay within one canonical wallet audit while preserving all original-time and financial checks.

**Architecture:** A private one-entry evaluator lives in `p4_wallet.py` and is instantiated inside `_load`, including custody's read-only facade. It freezes policy/genesis, keys by complete canonical observation bytes, fully verifies every miss and rechecks fixed trust and authenticated header time on each hit. Proof/report outputs are isolated copies; no cache survives the operation.

**Tech stack:** Existing Python, SQLite, Ed25519 and pinned local dependencies. No new dependency or engine change.

**Spec:** `docs/P4_HISTORY_AUDIT.md`.

## Global constraints

No native, protocol, snapshot, journal or wire format changes. No pruning, eviction of saved evidence, height/cap increases, persistent caches, trust renewal, delivery changes, installs, Actions, paid compute, public deployment, real funds or merges.

## Task 1: Measure and protect the audit boundary

Files: `tools/protocol4-wallet/scripts/profile_history.py`, `tests/test_history_audit.py`, `src/p4_wallet.py`.

- [ ] Freeze bounded synthetic workloads, timing policy and acceptance rule before measuring. Generate actual native execution with synthetic quorum signatures and public disposable fixture keys. Use exact same journal bytes for baseline and candidate.
- [ ] Measure baseline full-verifier calls for a status audit containing different saved signing times at one observation. Record raw status, unchanged database bytes, elapsed/CPU time and process peak RSS.
- [ ] Write and run a failing real-wallet regression asserting one full replay for two saved decisions plus current status, with unchanged holds and original recovered wires. Wrap the real verifier only to count executed calls; never return a fake report.
- [ ] Add evaluator rejection/isolation cases: past future-header time after later successful verification; exact trust expiry; invalid time types; mutated proof/report; frozen pins; changed full bytes; failed misses; one-entry replacement; fresh evaluator revalidation.
- [ ] Implement `_EvidenceAudit(genesis, policy).verify(raw, now_ns=...) -> (evidence, report)` and replace only `_load`'s local `(proof_id, at)` cache. Every call retains source existence/original observation time checks. Misses require canonical encoding and unchanged full verification. Hits recheck clock and authenticated final-header time, and stamp a copied report with the exact requested time.
- [ ] Run wallet, read-client, delivery, custody, receipt and native-lifecycle regressions. Reconcile discovered/successful IDs without skips; refresh current additive source/dependency inventories without changing historical receipts.

## Task 2: Qualify, review and deliver

Files: `docs/P4_HISTORY_AUDIT.md`, profile script, verification inventories and private result/measurement artifacts.

- [ ] Run the frozen counterbalanced comparison on baseline and candidate with identical inputs, per-process warm-up and no cross-operation reuse. Compare full status hashes and complete database bytes before/after every sample.
- [ ] Require no functional failures, one full replay per same-proof candidate audit, at least 40% median latency reduction on both repeated-decision workloads, no >20% regression on the small workload and latency spread within the declared variance rule. Report failure or inconclusive honestly.
- [ ] Obtain independent source and disposable reproduction review. Fix findings and rerun only affected gates.
- [ ] Document measurements separately from production capacity, native-history scalability, custody size, independent operators and launch readiness.
- [ ] Commit the isolated source, publish a draft PR stacked on PR41 using existing supported access, verify remote identity, and return a source/evidence ZIP with all Git file modes and a machine-readable member manifest. No merge or Actions.
