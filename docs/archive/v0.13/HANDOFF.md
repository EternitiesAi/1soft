# 1soft continuation handoff — v0.13

Owner direction: genuine independent native Layer 1 and human/agent accounts.
No GitHub Actions, paid compute, live money, public issuance or DNS changes.
1soft.org/Cloudflare stays in the separate owner/Codex lane. Preserve remote main,
PR #2 and both local/remote wallet lineages; do not force-replace either.

Read COMPACT_STATE.md and VERIFICATION.md. This release adds the explicit fresh
protocol-3 genesis field `state_commitment: smt-v1`. Default protocols 1/2/3 keep
previous commitments; golden vectors verify that. No protocol-4, chain migration,
supply change or public monetary policy is introduced.

New state_tree.py builds a compressed SHA-256 sparse Merkle map over all native
rows. AppHash binds its root, native genesis digest and state height. Node queries
at /proof/TABLE/HEX_ASCII_KEY return committed-record proofs in custom JSON, not
standard ABCI ProofOps or ICS23. Pending state must remain invisible. The native
execution transaction enforces a 20,000-record capacity guard before commit, not
after a proposer has already accepted an overflowing transaction.

New compact_verifier.py and verify_compact.py independently verify selected
records against an h+1 signed header, transfer preflight with owner/grant/budget
records, and exact native execution receipts. The preflight does NOT sign or
apply freshness policy, and the automated collector still uses whole snapshots.
Do not treat compact preflight as a replacement for the certified signing wallet.
No public-network provenance follows from synthetic signed fixtures.

Node storage/restore still uses whole snapshots; the map is rebuilt. Next storage
work should be incremental and authenticated, with crash-safe root persistence,
explicit resource accounting and independently testable proofs. Do not claim this
release solved node scalability or made public transactions private.

Executed: 705 Python tests across 16 completed batches, 82 new; one timed-out
batch attempt preserved, successful retry counted. Separate JS budget 30 passed.
Second JS proof implementation agreed on 6 roots/39 proofs and rejected 39 altered
roots. Five weakened guards were caught by actual assertion failures. A test with
1,024 signed local transfers measured 1,212,982 versus 3,961 bytes for an account
witness using the same synthetic signed root. Not a live network benchmark.

The actual runner accepts --protocol-version 3 --state-commitment smt-v1. The local
network command now requires original 1/2/3 plus the compact-v3 engine scenario.
Both engine attempts remain unassessed with no executable and no checks; normal
module-host DNS fails. Do not substitute scripted application calls or a different
consensus implementation for real upstream execution.

Parent local commit: cd8b1fb31eca762ce33717aa2f1cc5dd15041db0. Observed main:
941c6241d89761f2074c121af29539c354f6cdcd. Observed PR #2 head:
29705061c3cbb8b09ac18001c2b980d3183215a1. Recheck before writes.
This source was NOT uploaded. Prior platform-blocked native-core, ABCI and job
uploads must not be retried via encoding, fragments or another path. A status
comment is not source publication. The complete local package is the artifact.

Full required source: 79 files. There are zero active Actions workflows. Keep all
historical evidence; exact current release/bundle hashes live in RELEASE.json and
the companion release-check. The complete archive is not a mirror of remote main.
