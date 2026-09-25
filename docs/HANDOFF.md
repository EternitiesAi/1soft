# 1soft cryptocurrency handoff — v0.16

Owner direction: continue 1soft, the native cryptocurrency. No Resident/Luna/Psyche,
DNS/site changes, Actions, paid compute or real-fund work. Codex is not a development
requirement; this implementation and its tests were executed in the current local
runtime. The engine download remains the separate environment limitation.

Start with NODE_ADMISSION.md and VERIFICATION.md. The parent is complete local
v0.15 ff6f085; this archive is not a clone of remote main's separate wallet.
Source and release identities are in RELEASE.json and history.bundle.

New: src/admission_cache.py, src/node_io.py, their integration in block_application
and abci_server, server CLI settings, 65 tests, bounded work-count measurement and
six fault-injection checks. Native monetary code and abci_wire.py were not changed.

CheckTx answers are immutable exact-byte results under committed genesis/height/hash.
Always verify execution-image health before a hit. Commit clears only after disk
success; pending execution never enters the cache. ProcessProposal and FinalizeBlock
MUST execute native transactions, never use individually valid cached results.
Default bounds: 512 entries, 4 MiB charged payload, 24 KiB per entry. The proposer
scans at most 1,024 entries and 4 MiB payload, without changing peer block validity.

Private Unix ABCI gating is before thread creation. Default 16 connections, 5-second
started-frame and reply deadlines. Idle channels are not timed out. Healthy and
stalled-client tests run on real sockets. Metrics are local accessors, not public
endpoints. Native execution has no forced CPU deadline; operator/private-user trust
still matters. No mempool ownership, public-P2P protection or new protocol was built.

862 Python cases passed in 19 completed batches with exact ID reconciliation. 65
new cases are included. Scripted application processes passed 39/65 checks. Separate
JS budget tests and second-structure Merkle tests passed. The native 1/2/3/SMT golden
and equivalence checks remain in the full suite. Incomplete attempts and the first
fault-harness error are preserved rather than relabelled passes.

The supported engine build attempted go install and failed DNS before compilation.
The actual-engine acceptance runner returned unassessed with zero steps. It is NOT
acceptable to replace this result with scripted ABCI, synthetic signatures, a mock
engine or a public website. Continue resource/state/operational correctness when
engine execution is unavailable, but do not announce a running Layer 1.

Previous native/ABCI/job/index source uploads were blocked. Do not retry by encoding,
splitting or alternate routes. No implementation publication was attempted in this
turn; status-only updates do not mean code was published. Preserve remote refs,
parallel work and private visibility; never force-push the local bundle over main.

Run complete-source checks with installed dependencies. Targeted command:
PYTHONPATH=src:tests python -m unittest test_admission_cache test_node_limits -v
Full: python scripts/run_tests.py (on a runtime with a sufficient execution window).
Actual engine: python scripts/local_dev.py network --engine PATH_TO_PINNED_ENGINE.
Do not start public services, issuer/card integrations or real wallets from fixtures.
