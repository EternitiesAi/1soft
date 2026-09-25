# 1soft v0.14 — cryptocurrency storage checkpoint

This is a record of completed LOCAL work, not publication of its implementation.
The native application still lacks a verified actual CometBFT run. This checkpoint
does not change main, PR #2, the Resident PR, Luna/Psyche repos, DNS or the deployed
website. No GitHub Actions, paid compute, production keys or real funds were used.

## What was developed

A persistent compressed sparse-Merkle proof index for the complete local v0.13
native application. Branches and leaves persist in the SAME SQLite database as
committed state and block records. A commit updates all three atomically. Selected
proof reads traverse the persisted paths instead of rebuilding the whole tree.
The index authenticates old values before applying changes and requires its new
root to match the reference application hash. Existing roots, proof bytes, native
monetary rules and signature domains remain unchanged. This is not a new protocol.

The application builds an absent index once from a validated old SMT snapshot.
It rejects a corrupt or incomplete index instead of silently replacing it. Tests
terminate real processes after index updates before commit and after commit;
reopening recovers old or new state consistently. Proposal state is not exposed.
The advertised application name is 1soft-native-dev in this local release.

## Actual evidence

760 Python tests passed across 16 completed batches, zero skips/failures/errors,
with exact unique-ID reconciliation. The 55 new tests are included: 31 index
algorithm and 24 native application integration. An interrupted first attempt of
batch 13 is preserved and not counted; its separate completed retry passed.
Four intentionally weakened controls produced assertion failures. The separate
JS budget reference passed 30 tests. The existing bottom-up JS proof comparison
agreed on 6 roots and 39 proofs and rejected 39 altered roots.

The reproducible measurement executed 1,024 signed local native transfers in 16
application blocks. At 1,030 records / 2,059 stored index nodes, twelve alternating
account-proof measurements returned identical 1,624-byte evidence. Median reference
rebuild: 159.567029 ms; indexed read including server-side verification: 1.303690 ms
(122.40x ratio IN THIS RUN). Each query read 24 nodes and wrote none. One further
transfer changed 5 records with 59 node writes. There was no HTTP, validator or TPS
benchmark. Full-state execution, snapshot serialization, finalization and startup
validation remain; the index costs additional disk space.

## Publication and next gate

The normal create_tree attempt for the new state_index.py was blocked by a platform
indeterminate safety-status check. No tree, commit or branch was returned for that
attempt. No source retry, encoding, splitting or alternate upload was performed.
This documentation update contains no blocked implementation. The full v0.14
source, tests, benchmark and history are delivered in the project conversation.
The local package continues fdd4387, not remote main's separate wallet lineage.

The local engine gate verified all 85 required source files, then reported
unassessed with zero engine steps because the pinned executable is absent. The
ordinary Go dependency host still fails DNS here. Run the supplied actual-engine
acceptance suite from the complete package in a supported local/Codex environment;
do not replace it with scripted application calls, synthetic signatures or a
website deployment. More local tests do not establish real consensus or an audit.

The complete release's VERIFICATION.md, PERSISTENT_STATE_INDEX.md and release-check
JSON distinguish source, verification, publication and packaging scopes. No ticker,
public supply, reserve backing, issuance policy or production launch was decided.
