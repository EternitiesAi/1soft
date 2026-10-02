# P4 journal custody and recovery implementation plan

> **For agentic workers:** Use dispatching-parallel-agents for independent review
> or executing-plans for inline task-by-task execution. Parent implements; the
> Sol6.1 reviewer is read-only. No paid MiMo spending scope is authorized.

**Goal:** Preserve both P4 journals in an encrypted backup with recovery-only restore.

**Architecture:** Capture under existing wallet-to-delivery lock order. Authenticate
the envelope and audit original records in memory; publish a distinct archive that
can inspect and export original evidence without signing or dispatch.

**Tech stack:** Existing Python3.14.4, SQLite, cryptography46.0.4 and protobuf6.33.6.

**Spec:** `docs/superpowers/specs/2026-10-01-custody-recovery-design.md`.

## Global constraints

- Canonical source checkpointdc5fed6 remains in its original worktree.
- New branch `development/custody-recovery-20261001`; no consensus/dependency changes.
- Journal payload7MiB, plaintext16MiB, encrypted envelope23MiB, archive17MiB.
- Scrypt32768/8/1/32, salt32bytes; AES-256-GCM nonce12bytes; password16-1024bytes.
- Recovery-only archive; no key backup, signing, transport, trust renewal or activation.
- All existing engineering exclusions and original semantic gates remain.

## Task1: Encrypted custody and recovery core

Create `tools/protocol4-custody/src/p4_custody.py` and
`tools/protocol4-custody/tests/test_custody.py`.

Interfaces: backup(delivery, output, password); restore_backup(backup, output,
genesis, policy, password); RecoveryArchive(path, genesis, policy) with inspect,
recover and export_receipt. Existing P4Wallet/P4Delivery remain unchanged.

- [ ] Write meaningful fixture tests before implementation; for example:
  ```python
  original = wallet.recover(raven, payer=chain.payer, grant_id='raven')
  backup(delivery, backup_path, PASSWORD)
  restore_backup(backup_path, archive_path, chain.genesis, chain.policy, PASSWORD)
  with RecoveryArchive(archive_path, chain.genesis, chain.policy) as archive:
      assert archive.inspect()['pending_debit_units'] == '100'
      assert archive.recover(raven, payer=chain.payer, grant_id='raven') == original
  ```
- [ ] Run those tests with the installed pinned interpreter; retain the expected
  missing-feature failure outside source. No other failure is an accepted red gate.
- [ ] Implement fixed typed-row schema capture and bounded in-memory audit facades;
  no persisted ordinary journal or inherited signing/send API.
- [ ] Implement fixed-parameter authenticated encryption and exclusive durable
  publication. Decrypt/authenticate/audit completely before creating output.
- [ ] Run the tests and meaningful wallet/delivery regression groups. Repair
  failures without changing existing semantics or weakening assertions.
- [ ] Request read-only independent review of the actual diff and execute any
  reproduced repairs with new regression tests.

## Task2: CLI, documentation and complete delivery

Create `tools/protocol4-custody/scripts/p4_custody_cli.py`, CLI tests and README;
add a short current feature entry to the main README and ROADMAP.

- [ ] Add backup/restore/status/recover/export-receipt commands using the exact
  core interfaces. Passwords come only from non-echo terminal prompts, with
  confirmation on backup. No password argument or environment fallback.
- [ ] Test a real PTY backup/restore, nonterminal refusal, output failure, and
  wrong role. Assert real artifacts and preserved source rows, never source text.
- [ ] Document actual guarantees, scope, caps and exclusion of private keys;
  describe required future fencing rather than calling a cloned wallet safe.
- [ ] Commit only selected new/modified files. Verify source diff and clean state.
- [ ] Deliver source changes and sanitized raw tests/review logs with exact result
  MD/JSON, source inventory and archive receipt. Open a draft PR through supported
  existing authorized GitHub access if that can occur without Actions. No merge.
- [ ] Retain current state, SHAs, ownership and unresolved gates in the local
  handoff and a meaningful Keel checkpoint.
