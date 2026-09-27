# 1soft decision-bound payment delivery

Deliver a transfer that the existing shared `CertifiedWallet` has already signed.
The client accepts a recorded decision ID and explicit payer/grant, not an arbitrary
transaction file, private key, browser balance or replacement payment. It uses the
existing dispatcher and receipt verifier without adding a signer or reservation store.

This follow-up is based on PR #12 commit
`dd096271f24e704d27f39d551d5f16986934481d`, tree
`5e1e7385033bdfa1f5e31821c7be8d1b101a2a40`. The normal core/account dependencies are
fully present in that source. No unpublished catch-up or transfer-preparation module
is required. PR #11 remains a different, unmerged implementation; its results are
not verification of this source. See [ATTEMPT_CONSENT.md](ATTEMPT_CONSENT.md) for the
new interface, exact evidence scopes, tests and compatibility changes.

## One payment, explicit submission attempts

A wallet signature creates the existing pending obligation. A dispatch attempt
records that the same signed bytes may have been sent. A verified receipt proves
recorded native execution under the pinned committee assumption. These are distinct:
receipt collection does not clear the wallet's hold. Explicit reconciliation passes
the receipt's full state and signed ancestry through the original wallet's checks.

The version-2 delivery confirmation binds the original decision, payer/grant,
signed bytes and local route, plus first-send versus replay, next attempt number,
transport status, verified wallet checkpoint and complete obligation inventory.
A changed checkpoint or inventory requires review of the unchanged payment again.
An attempted send consumes that review's scope even when the reply disappears.
This confirmation is a content binding, not a new signature, a secret password or
proof that a person approved it. Trusted application callers remain responsible
for presenting the review and obtaining appropriate approval.

`queue` stages the existing payment without network activity. For an unattempted
queue it also returns a first-send review. Requeueing after an attempt never resets
that attempt or supplies replay consent. `review` obtains a current first-send
review; `review --replay` explicitly reviews one repeat attempt. `status` is
historical inspection and returns no fresh confirmation. No command unlocks keys.
Old version-1 confirmation strings are refused, without changing old signatures
or migrating either journal.

## Commands

Use the existing independently selected genesis, policy, private journals and
explicit account/grant. These are templates, not public network configuration:

```sh
umask 077
export PYTHONPATH="$PWD/src"
base=(--genesis /private/genesis.json --policy /private/policy.json
      --wallet /private/wallet.sqlite --delivery-journal /private/delivery.sqlite
      --endpoint http://127.0.0.1:26657/ --account ACCOUNT_ID
      --grant-id raven --decision-id EXISTING_DECISION_ID)
python tools/wallet-delivery/scripts/deliver.py "${base[@]}" queue
python tools/wallet-delivery/scripts/deliver.py "${base[@]}" review
python tools/wallet-delivery/scripts/deliver.py "${base[@]}" send --confirm REVIEW_CONFIRMATION
python tools/wallet-delivery/scripts/deliver.py "${base[@]}" status
python tools/wallet-delivery/scripts/deliver.py "${base[@]}" refresh
python tools/wallet-delivery/scripts/deliver.py "${base[@]}" reconcile \
  --continuation /private/intermediate-signed-headers.json
```

An unresolved result never triggers an automatic resend. An explicitly chosen
repeat uses `review --replay`, then `replay --confirm NEW_REVIEW_CONFIRMATION`.
The new review identifies its next attempt; the previous confirmation is not reused.
`export-proof --output /private/new-receipt.json` retrieves existing verified proof.
An existing output is never overwritten. CLI exit zero means the command returned,
not payment settlement: inspect both transport and wallet obligation statuses.

Only explicit queue creation may initialize a dedicated dispatch journal. Wallet
files, wallet SQLite sidecar aliases, unrelated stores and existing dispatch
configurations that are missing or differ are rejected before implicit adoption.
The native dispatcher commits attempts before I/O and locks its own journal.
The wallet's signatures and holds remain in the original financial journal.

## Checks and evidence

With the existing pinned dependencies installed:

```sh
# All four parts together cover the delivery suite.
for n in 0 1 2 3; do
  python tools/wallet-delivery/tools/verify.py --native-root . --parts 4 --part "$n"
done
```

This follow-up passed 83 delivery tests (51 inherited and 32 new), 974 standard
core tests across 31 completed module processes, 45 account-view tests and 30
separate JavaScript reference cases. Counts are separate scopes, not repeated runs
added together. Four deliberately weakened controls were caught by assertions.
The new local HTTP/application examples use synthetic committee attestations.

The uploaded dd096 return was checked against its refreshed ZIP digest. Its 294
manifest entries and exact source tree matched; all 28 certified transactions were
replayed, reproducing all four saved final states and application roots. Codex's
22/39/62/67 validator checks belong to that original source. The updated runner
here is authored and unit-tested but has NOT run against actual validators here.
The old VERIFICATION.md is retained as a historical checkpoint, not the current
follow-up's result. The complete package includes the new logs and review utility.

## Limits

This is development software for one trusted local workspace with static genesis
validators, explicit local policy and full unpruned state. Only a literal loopback
endpoint is supported. There is no transaction spanning wallet reads and network
submission: changes after the final capture remain possible. Separate devices,
other journals, old binaries, direct dispatcher/raw-key access and whole-workspace
rollback can operate outside this approval boundary. Native execution still
controls final balances, counters and permissions. Another journal can submit the
same bytes; this is not globally exactly-once delivery or invoice deduplication.

No new monetary rule, cryptographic primitive, dynamic light client, latest-state
guarantee, public network, production custody, USD backing, bridge/card service or
independent audit is claimed. No Actions, paid compute, real funds, deployment,
DNS/site work, Resident/Luna/Psyche work, force-push or merge is part of this change.
