# v0.16 source reconciliation — local review branch

This branch starts from private `xnuonux/1soft` main
`f4201151e27e44466d9ff6fafc7a69e1acc39e34`. The complete v0.16 source was
verified from the handoff payload (commit identity
`546616e310064c1a59cb085c4d5a450efcacc357`) before copying. These are
different Git histories; no history was force-replaced. Open payment PR #2 was
observed at `29705061c3cbb8b09ac18001c2b980d3183215a1` and left untouched.

The v0.16 `src`, `scripts`, `tests`, `tools`, `reference`, third-party notices and
project docs were brought into a new local branch. Original `1soft` placeholder,
remote-only `state_wallet.py`, `wallet_state.py`, their tests and docs, and the
remote checkpoint document remain. The 95 v0.16 required files and five
remote-only required files are retained in one manifest; a new integration test
and pinned Go checksum file make 102 required entries. Historical execution logs,
the ZIP's `history.bundle`, website assets, and original `RELEASE.json` were not
added to Git. They remain in the handoff archive; the website is out of scope.

The remote wallet's snapshot restore omitted v0.16 protocol-3 budget tables. It
now delegates state reconstruction to the node's version-aware restore path, with
bounds and a regression test. Its signing outbox cannot reserve shared budgets
across multiple grants, so it explicitly refuses protocol-3 genesis. The older
v1/2 wallet behavior remains available. The source package also contains a
separate `certified_wallet`; these signing journals are not unified. A single
canonical signing and reservation path needs design and POSIX integration tests
before this branch is suitable for release or financial use.

Source integrity verification on the combined checkout passes (102/102 files).
On Ubuntu 26.04 under WSL2, the pinned CometBFT v0.38.25 binary built from Go
modules (Linux SHA-256
`218628da07bed5d27e178d38d0bef9ecf46f21b214c8e9fea402fd215fccc024`).
The upstream codec probe passed 9/9 checks. The final integrated checkout passed
919/919 Python tests with no skips and 30/30 JavaScript reference tests. A
historical receipt CLI fixture initially failed because its dispatch deadline
had passed; the fixture now gives that real-clock subprocess a current policy,
while production expiry enforcement and the separate expiry regressions remain.

The final-tree local network gate passed all four actual four-validator CometBFT
scenarios: protocol 1 (22 checks), protocol 2 (39), protocol 3 (32), and protocol
3 with `smt-v1` (37). Saved public genesis, signed commitments, inclusion proofs,
execution receipts, read-only client collection, engine logs, and quorum-loss and
recovery checks were retained. A separate evidence pass reverified the saved
certificates against each public genesis and the exact transfer IDs. This is a
one-host development network with a static genesis validator set, not independent
operator, public-network security, or production-custody evidence. See the
accompanying CODEX_RESULT and sanitized raw logs.

Earlier platform review had blocked upload of the ABCI wire source. After the
owner explicitly requested publication, the same GitHub connector accepted the
exact source and created [draft PR #5](https://github.com/xnuonux/1soft/pull/5)
on `integration/1soft-real-engine-v016`. The published tree matched the tested
local tree byte-for-byte; no alternate upload channel was used. A future platform
denial still stops that action and must not be bypassed.
