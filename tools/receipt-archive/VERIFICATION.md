# Receipt archive verification — 27 September 2026

## Exact source boundary

Parent is published PR #15 at `072ebe6a6850c80044a5ad1b0496c6f3a1ffebe0`.
The local parent manifest matches Git blob
`31b2ed807887efe1aba921c926aa035a53302550` and SHA-256
`e621222ca58d514beb1b6f6fe6bc84b743f629ff361239b181ede84bd36af017`.
All 23 native runtime modules, the dependency file, and the two imported native
fixture modules match that manifest (26 files). The add-on's own manifest covers
its runtime, commands, test fixtures, tests and test runner.

The local test checkout was reconstructed from the earlier source delivery plus
PR #15's exact overlay. Three inherited files do not match the final parent:
`scripts/run_state_sync.py`, `tests/test_state_sync.py`, and
`tests/test_state_sync_runner.py`. They were NOT used, counted as checked, silently
removed from the parent inventory, or represented as qualified. The portable
archive add-on requires the real published checkout for a full node; it does not
include this partial local test checkout. The published parent remains intact.

## Tests executed

The final add-on suite has 62 distinct tests, zero skips/failures/errors. It covers
P1/P2/P3 flat certificates and P3 SMT selected proofs, exact external pins,
transaction/signature binding, block/receipt/ancestry agreement, omitted/reordered
headers, validly signed competing branches, forged signatures, changed proofs,
refusal to archive absence, malformed/oversized inputs, and mutation of a caller's
input object between verification and insertion.

Storage tests include no-op duplicates, conflicting receipt preservation in either
arrival order, conflicting signed headers, missing evidence, corrupted indexes,
no wallet-database initialization, missing policy, limited capacity without
eviction, read-only inspection, private files and sidecars, two actual concurrent
writers, failed insertion/output, and actual child-process exits immediately before
and after SQLite commit. CLI tests run the complete pack/init/import/lookup/export
sequence, offline verification, missing ancestry, wrong pins and output overwrite
refusal. No private user key or account is used.

114 inherited certified-wallet/obligation/budget tests and 154 inherited
certificate/compact-proof/local-retention tests also passed. These are distinct
from the 62 add-on cases: 330 Python cases across those completed runs. The separate
JavaScript reference passed 30. No full native suite, CometBFT process, new
five-node gate or multi-host network was run. Existing validator results apply to
their original exact revisions and are not relabelled as archive validation.

The first development run passed 49 tests. A later review tightened input custody:
`put` now freezes the caller object once and stores those verified bytes; the new
mutation regression is included in the final suite. There was no production use,
reported fund loss or successful on-chain attack.

## Executed storage example

256 actual local native payments were committed on the P3 SMT application; its
committee headers were synthetic fixture signatures. The last payment's receipt
was packed at state height 256 with signed header 257. After six more blocks, the
node was at height 262 and its old `/block/256` result was explicitly pruned.
The source application was then closed.

Full certificate: 311,619 bytes. Portable capsule: 9,909 bytes, with one receipt
proof and no unrelated native state. An archive import, duplicate import, reopen,
lookup, exact export and offline verification all succeeded. The source state
still contained all 256 native receipts. Snapshot size was not reduced. This is
serialized evidence size, not total database disk usage, transaction throughput,
network bandwidth benchmarking or native-history pruning.

## Fault controls and reproducibility

The accompanying evidence package records controlled weaker-code checks separately
from passing tests. They are tests of this author-written implementation, not an
independent adversarial audit. Private archive operations use SQLite transactions;
SQLite documents that only one writer proceeds at a time and that a successful
transaction commits together. Actual process tests here do not qualify hardware
power-loss durability or a malicious local host.

Primary implementation background: https://www.sqlite.org/lang_transaction.html
The 1soft proof/verifier implementations are the exact parent source, not an
invented identity/credential/cryptographic standard.

No source-node receipt deletion, wallet hold release, policy renewal, signing,
broadcast, public endpoint, deployment, Actions, paid compute, real funds,
Resident/Luna/Psyche operation, merge or force-push is included.
