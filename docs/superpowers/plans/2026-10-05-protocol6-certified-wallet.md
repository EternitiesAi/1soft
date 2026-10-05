# Protocol 6 Certified Treasury Wallet Implementation Plan

> **For agentic workers:** Use `dispatching-parallel-agents` for genuinely independent tasks or `executing-plans` for inline task-by-task execution. Steps use checkbox (`- [x]`) syntax for tracking.

**Goal:** Retain one exact treasury obligation and resolve it only from independently checked validator inclusion.
**Architecture:** New controller-only journal and bounded certificate/replay resolver reuse unchanged P6. No consensus migration.
**Tech Stack:** Python3.14, SQLite FULL-sync WAL, cryptography Ed25519, pinned treasury worker and CometBFT0.38.25.
**Spec:** docs/superpowers/specs/2026-10-05-protocol6-certified-wallet-design.md

## Global Constraints

- Preserve P1-P6 runtime/proof bytes and historical receipts.
- No public/paid compute, deployment/Actions/DNS/other projects/real funds/force pushes.
- One canonical journal; no expiry release/retry/refreshed replacement.
-8 obligations,65 observations,1MiB encoded observation ceiling.

## Task 1: Exact certified resolver and durable journal

Files: create src/protocol6_wallet.py and tests/test_protocol6_wallet.py.
Consumes: verify_state(witness,header,raw_genesis), replay(g,state,height,worker), parse(raw), txid(raw).
Produces: CertifiedTreasuryJournal(path,expected_genesis=raw,worker=w) interface from spec.

- [x] Write real proof/signature tests first; example:
```python
ident=journal.retain(a)
assert journal.claim(ident)==a
journal.observe(witness_with_a,signed_h_plus_1)
assert journal.status(ident)['status']=='recorded-certified'
assert journal.export(ident)==a
```
- [x] Run unittest test_protocol6_wallet with explicit P6_WORKER/hash/fixtures; absent implementation must fail assertions.
- [x] Implement schema, private paths, replay/continuation checks, exact inclusion, typed holds and atomic one-attempt transition.
- [x] Verify corruption, lost return, absence/expiry, same-height conflict, concurrency and SQL/process-death behavior.
- [x] Commit tested source and refresh SOURCE_MANIFEST.json.

## Task 2: Real validator wallet execution and report gate

Files: create scripts/run_protocol6_wallet.py, tools/release/check_protocol6_wallet.py and tests/test_protocol6_wallet_report.py.
Consumes: unchanged run_protocol6_engine.Network and new journal, five public qualified proof fixtures.
Produces: closed source-bound report with a fixed check roster, exact startup/source/binary/process/artifact identities and signed state plus exported exact journal receipt. Private keys/databases/openings excluded.

- [x] Write report rejection tests before checker; mutate source/checks/certificate/exact wire/claims and require refusal.
- [x] Run real wallet runner on clean committed source using fresh owned loopback validators. Retain a, claim once, submit once, discard transport response, authenticate its committed signed state and observe; reopen exact completion and refuse another attempt. Retain b in a separate synthetic losing-controller fixture and require held conflict with no exported completion. Explain journals are test actors, not globally coordinated funds.
- [x] Independently gate the exact roster/raw logs/source/receipt/signature before qualification.
- [x] Preserve failed candidates, then register successful scoped receipt and source manifest.

## Task 3: Release readiness and integrated delivery

Files: docs/PROTOCOL6_CERTIFIED_WALLET.md, docs/DEPLOYMENT_READINESS.md, component manifest and README/ROADMAP links.
Produces: acceptance map separating local development qualification from owner/merchant/custody/scale/independent review/deployment gates.

- [x] Run manifest-checked default suite once, focused real-input checks and affected checker tests.
- [ ] Private branch/PR/merge using exact verified head; recheck unchanged runtime and merged tree.
- [ ] ZIP full source/patch/sanitized logs/CODEX_RESULT.md/json; verify CRC, all source bytes and external Windows hash.
- [ ] Record checkpoint, choose next independently executable readiness milestone under standing autonomy. Stop only for external review/operator/economic decisions or authority/resources actually required.
