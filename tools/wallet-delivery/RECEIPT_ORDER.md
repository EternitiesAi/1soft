# Receipt-order recovery — 27 September 2026

## Exact baseline and purpose

This change starts from PR #12 commit
`dd096271f24e704d27f39d551d5f16986934481d`, tree
`5e1e7385033bdfa1f5e31821c7be8d1b101a2a40`. It is NOT based on PR #11.
The owner-supplied sanitized ZIP matched SHA-256
`8395c131a62166dbcf57812b4c07f8a24c77fb118c1b182f71179e7b477576ee`.
Its 294 manifest entries matched and its 219 source files reproduced the exact
published Git tree. Its raw results remain evidence for dd096, not this change.

Before this change, revisiting an earlier saved receipt after the wallet had
advanced tried to import the older state. The wallet correctly rejected rollback,
but the delivery API could not recognize that the exact payment was already
recorded. The baseline regression failure is retained in the delivery package.
No successful double spend or corruption was demonstrated by that failure.

## Two explicit outcomes

`DecisionDelivery.reconcile` retains its existing arguments and returns an added
`reconciliation_outcome` field:

* `state_synchronized`: the payment was not yet recorded in the selected wallet
  snapshot. The unchanged CertifiedWallet.sync verified/imported the receipt's
  full state. All existing policy, freshness, ancestry and hold checks apply.
  `wallet_sync_performed` and `state_witness_imported` are true.
* `already_recorded`: the wallet's independently reverified full state already
  contains the exact immutable receipt also verified in the dispatch store.
  No account state, checkpoint, reservation or transport event is rewritten.
  `wallet_sync_performed` and `state_witness_imported` are false.

`receipt_state_height` identifies the packet's state checkpoint; the existing
`wallet_state_height` identifies the independently checked wallet snapshot.
They may differ. Neither is guaranteed to be the latest chain state.

The complete receipt row must match, not only its transaction ID or payment body.
Execution height, sequence, previous receipt hash, state hash, signer and exact
signed envelope participate through that row. Two valid synthetic attestations
of different executions of the same transaction are refused as a conflict.
This check is not evidence of safety under a compromised validator quorum.

Proof remains mandatory. A wallet label alone, a missing dispatcher proof, a
modified signature or rehashed corrupted proof cannot produce already_recorded.
The account and grant must still match the explicitly selected wallet decision.
The existing sidecar/configuration safety fixes remain unchanged.

## Late receipts and interruptions

A full state obtained while reconciling payment B may already contain payment A.
Revisiting A's earlier receipt now confirms that history without attempting to
roll back the wallet or release the budget a second time. The no-op does not
advance other decisions or opportunistically refresh unrelated account state,
even if the supplied packet is newer than the wallet.

An already-recorded result can be inspected after local trust expiry or when
saved evidence is stale. It is historical verification, NOT fresh signing
permission. Existing time/frontier warnings remain present in the report.
Pending payments cannot use this branch to bypass expiry or ancestry checks.
Supplied continuation headers are not imported on a historical no-op; they are
used only if the existing wallet performs a genuine state synchronization.

The first read and later wallet sync are not one transaction. If sync raises a
native Reject because a competing wallet connection advanced, the adapter rereads
and verifies the current wallet ONCE. It returns already_recorded only when that
current state contains the same complete receipt. Otherwise it preserves rejection.
It does not retry sync or catch SQLite/I/O failures as success. A crash after a
wallet commit can be recovered by reopening and reconciling the same decision.
The process-exit test is not a hardware power-loss durability test.

## Test and acceptance commands

With the repository's existing dependencies installed:

```sh
python tools/wallet-delivery/tools/verify.py --native-root .
# Bounded alternative: run ALL 12 partitions, 0 through 11.
python tools/wallet-delivery/tools/verify.py --native-root . --parts 12 --part 0
PYTHONPATH=src:tests python -m unittest test_devnet_runner -v
```

This revision passed 71 delivery tests (the original 51 plus 20 new), 16 runner
tests (14 plus two), and 114 inherited wallet/obligation/budget tests: 201 distinct
candidate cases. The original 51 also passed on the untouched returned baseline.
The separate JavaScript reference passed 30. No complete native suite is claimed.
Three weakened disposable code controls were caught by assertion failures; these
are author checks, not an independent security audit. Exact IDs and raw logs are
in the accompanying delivery package, including incomplete early tool attempts.

The executable local HTTP example sends two exact signatures once each, collects
both receipts, reconciles the LATER receipt first, and then reopens the EARLIER
receipt. Pending/spent progresses 100/0 -> 0/100 and stays 0/100. There are exactly
two submissions. The supplied example uses actual local application execution
and synthetic committee signatures, not new validator voting.

The original validator gate remains available unchanged unless the new flag is
selected. A NEW optional gate reopens the journals and revisits the first older
receipt after both payments have reconciled. It requires a verified no-op and
unchanged logical wallet/dispatch data and RPC counts:

```sh
python scripts/run_devnet.py --cometbft /trusted/cometbft \
  --protocol-version 3 --decision-delivery --receipt-convergence \
  --output /private/new-flat/devnet.json
python scripts/run_devnet.py --cometbft /trusted/cometbft \
  --protocol-version 3 --state-commitment smt-v1 --decision-delivery \
  --receipt-convergence --output /private/new-smt/devnet.json
```

That new actual-validator gate was NOT executed here: the binary is absent and
the normal module-host lookup failed DNS. Its missing-engine behavior was tested
as unassessed, not as a pass. The original dd096 22/39/62/67 validator checks are
preserved in the supplied return and are not attributed to this revision.

## Scope not expanded

No native monetary rule, signature format, signer, reservation schema, account
renderer, catch-up module or dependency is changed. No PR #11 code is imported.
This is neither task/invoice deduplication nor a network-wide exactly-once claim.
Separate devices/journals, raw keys, malicious hosts, whole-workspace rollback,
dynamic validators and pruned state remain outside these development guarantees.
No Actions, paid compute, public deployment, real funds, production keys,
DNS/site changes, Resident/Luna work, force push or merge occurred.
