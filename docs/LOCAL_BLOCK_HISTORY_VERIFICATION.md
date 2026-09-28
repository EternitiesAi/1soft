# Local block history — verification scope

## Source custody

The source baseline is accessible PR #14 head
12436b9fd47b09a471b327da927263b568370d75, tree
17fd2b4939e6f1cd5d55e87229604c97795566e0. The available earlier source package
reconstructed tree390023c707e6967914253381c67c2edf53252d27. Its state_sync.py was
reconciled to the final published PR #14 bytes. The resulting entire `src` subtree
matched PR #14's b35fb9ad56a6b487e556ec460c9bcf9df6accb45 before these new edits.

The three changed pre-existing runtime/CLI files and the original 108-entry source
manifest were individually matched. That original manifest's SHA-256 is
5553c15d8fd45e19426c3cd55cfbb93ae8a7bca0d90b473b4461a616bccac4b5.
All selected inherited tests/helpers and unchanged runtime dependencies were matched
to its entries. See the package's evidence/source-scope.json for exact identities.

The local source store is NOT a reconstruction of the full final PR #14 checkout:
its old run_state_sync.py, test_state_sync.py and test_state_sync_runner.py were
neither used nor represented as current. The delivery is an exact-file OVERLAY and
patch for true PR #14, not a complete node archive. Unrelated parent files must
come from the published PR. The updated root manifest preserves every existing
entry, updates the three changed runtime/CLI files, and adds four files (112 total).
No missing source was dropped to obtain an inventory pass.

## Completed checks

- 48 distinct new tests: 43 retention/application/wallet/crash cases and five
  subprocess CLI/Unix-ABCI cases. Zero skipped, failed or errored.
- 128 existing wire/block/execution/index regression cases passed.
- 114 existing certified-wallet/obligation/budget regression cases passed.
- 180 existing native/account-lifecycle/state-tree/compact-proof cases passed.
- Total: 470 distinct Python cases, with exact successful IDs reconciled.
- Separate JavaScript reference: 30 passed.
- Deterministic 512-block/32-transfer comparison reproduced identical execution,
  state, commitments, snapshots and compact proof while retaining 16 local rows.

The existing 1007-case full native suite was NOT rerun. PR #14's CometBFT and
five-node results are inherited evidence for its unchanged source, not this new
storage integration. No new CometBFT process or upstream-Go wire run occurred.
The runtime has no pinned CometBFT executable. Its absence is not a failed network
test; that new exact-source qualification is unassessed.

The new tests cover persisted policy/restart, disabling or conflicting policy,
late opt-in, contiguous ranges, missing/corrupt metadata, exact byte compatibility
for protocols1/2/3 and SMT, retained latest blocks, aborted commit, process death
after deletion before commit and after durable commit, marker-aware state sync,
snapshot-only recovery, preserved native receipt/replay, and wallet reservations
before/after execution and pruning. No private key or wallet belonging to a real
person was used. Committee signatures in wallet tests are synthetic fixtures.

The crash cases are actual local child-process exits at instrumented SQLite/block
boundaries. They are NOT power-loss tests and do not qualify the separately pending
CometBFT final-Apply kill/restart window.

## Initial failures preserved

The first 42-case new test run contained a test-only import error: it attempted to
import an absent abci_wire.request helper. It was corrected to construct the actual
Request message; no production check was weakened. The initial log is retained.

The first 128-case inherited run had five child-process failures because the new
local orchestration script omitted the repository PYTHONPATH. Those subprocesses
could not import block_application. The harness environment/cwd was corrected and
the exact selected suite passed. Initial logs/JSON are retained and excluded from
the passing result. These errors were not relabeled as caught security defects.

## Operating boundary

No native receipt pruning, engine block/evidence pruning, archive service, public
network, new authority, key rotation policy, production custody, economics,
Actions, paid compute, site/DNS, Resident/Luna/Psyche operation, merge or force-push.
No independent security audit or global data-availability guarantee is claimed.

Before release, run the exact candidate with the pinned real engine in both default
and bounded-history modes, including ordinary block continuation, restart, receipt
collection, and fresh-node state sync. The current state-sync acceptance runner
expects old source block metadata at a restored height; its bounded-history mode
must explicitly account for that availability instead of treating pruned local
metadata as a failed or absent native payment. This candidate does not modify or
claim to have executed that runner.
