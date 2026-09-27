# 1soft — delivery of an existing wallet decision

This adapter connects the published CertifiedWallet journal to the existing local
payment dispatcher. Select a decision ID, payer and role instead of exporting a
transaction and manually importing it elsewhere. It never unlocks a key, signs,
changes an amount or nonce, or creates a second reservation store.

The normal dependency is the fully published PR #10 account/core source at
`631dcc309c01ea5d183c90d5983e45063695e12a`. No unpublished transfer or catch-up
implementation is required. It also accepts decisions produced by the separately
delivered transfer-preparation workflow, because both use the same original wallet.
This is development code, not public deployment or production custody.

## One signing decision, two separate records

The signing journal owns signed decisions and pending financial obligations. The
existing dispatch journal owns submission attempts and verified receipt packets.
This adapter does not make those two databases one transaction or a global wallet.
Their states remain separately labelled in every status response.

`review` checks the saved committee-signed state and complete local obligation
inventory in a read-only snapshot. It verifies the chosen decision's original
signature and explicit payer/role, confirms that it remains pending and admissible
under the saved native state, and queues the exact bytes in the dispatcher.
Queueing is not broadcasting, signing or a new hold.

The delivery confirmation binds the decision, signature bytes, payer, role,
recipient, amount, native fee, nonce, validity, selected local paths, endpoint,
policy, checkpoint, pending inventory, first-send/replay action and next attempt.
Path hashes are local selection bindings, not authentication or anonymity.
`send` recomputes the review under the dispatch lock and requires the original
confirmation. A changed checkpoint, inventory or attempt requires explicit review
again. There is no silent re-signing, nonce selection or fee increase.

Before network I/O the original dispatcher commits the attempt. A lost reply or
process exit therefore leaves a durable attempted/unresolved state. First send
cannot simply be repeated. Explicit replay requires `review --replay` followed by
`send --replay` with its new confirmation; it reuses exactly the original bytes.
Previously verified receipts and already-recorded/expired wallet decisions cannot
be sent again through this adapter. This is not exactly-once network delivery.

## Receipt verification is not wallet reconciliation

`refresh` only uses the existing read-only receipt collector. It can record a
verified receipt, but it does not update the wallet or release a reservation.
A missing response, endpoint admission/decline, timeout or missing receipt cannot
be interpreted as settlement, nonpayment, cancellation or a refund.

`reconcile` makes no network request. It rechecks the stored exact receipt and
passes its full state through the existing CertifiedWallet.sync checks. Those
checks still require freshness, linked signed headers, unpruned receipts and all
pending-obligation invariants. If the receipt already contains every intermediate
signed header needed for a short gap, the adapter supplies that consecutive set;
it never skips a missing header. A longer or invalid gap returns
`wallet_sync_required` while retaining both the receipt and the financial hold.

If the journal contains newer optional catch-up progress, this adapter defers to
that catch-up path rather than letting older core code ignore its frontier.
Neither trust expiry nor header progress is reset. After explicit successful
reconciliation, the exact recorded debit no longer appears pending; the native
budget's recorded spending stays consumed.

## Local interface

With the existing pinned dependencies installed, run from the repository root:

```sh
export PYTHONPATH="$PWD/src"
base=(--genesis /private/genesis.json --policy /private/policy.json
      --journal /private/wallet.sqlite
      --dispatch-journal /private/delivery.sqlite
      --endpoint http://127.0.0.1:26657/
      --account ACCOUNT_ID --grant-id AGENT_GRANT
      --decision-id EXISTING_SIGNED_DECISION_ID)
python tools/wallet-delivery/scripts/deliver.py "${base[@]}" review
python tools/wallet-delivery/scripts/deliver.py "${base[@]}" send --confirm REVIEW_CONFIRMATION
python tools/wallet-delivery/scripts/deliver.py "${base[@]}" status
python tools/wallet-delivery/scripts/deliver.py "${base[@]}" refresh
python tools/wallet-delivery/scripts/deliver.py "${base[@]}" reconcile
python tools/wallet-delivery/scripts/deliver.py "${base[@]}" export-proof --output /private/new-receipt.json
```

Replace uppercase placeholders with explicitly selected development inputs. Omit
`--grant-id` only for an owner-signed payment. The tool accepts no vault, password,
raw transaction file, account-creation request or administrative signing operation.
It does not infer account ownership from the ability to inspect a journal.

`reconcile --continuation FILE` accepts an explicitly supplied bounded header list
when needed. `refresh --read-attempts N` allows 1–4 attempts to obtain the same
captured next-height commitment; it does not retry the payment.

CLI exit meanings: review/status/export return 0 for their own completed command,
not for payment finality. A send returns 2 even when the endpoint admits it, because
execution remains unverified. Refresh returns 0 only for a verified receipt;
reconcile returns 0 only when that wallet records the payment. Exit 3 means the
operation did not complete; earlier attempts or wallet commits may still exist.
NEVER implement an automatic resend based on exit 2 or 3. Inspect the separate
`delivery_status`, `receipt_verified` and `wallet_obligation_status` fields.

## Preserved boundaries

Only an explicit literal-loopback development endpoint is accepted. Existing RPC
method, framing, deadline and read limits are unchanged. Trust expiry forbids new
network work. Historical status/proof export remains available; it grants no new
spending authority. Receipts exported to disk are private, unsigned containers
of signed evidence and are never overwritten.

The original wallet must exist. A dedicated dispatch database is created only by
first-send review. A wallet, its sidecars, unknown database schema, or a dispatch
file missing its original configuration is rejected rather than migrated/adopted.
Normal dispatch journal locking and SQLite coordination files may be used even
for status; the source wallet's logical tables are not modified except by the
explicit original-wallet reconciliation call.

The wallet read and network submission are not atomic. Native state may change
after the last check, and this interface cannot recall already signed bytes held
elsewhere. Separate dispatch journals/devices, raw keys, old outboxes, complete
workspace rollback, task/invoice deduplication, a malicious host, dynamic validator
sets, public P2P/RPC security and production custody remain outside this protection.
A valid payment receipt is not proof that a purchased service met its contract.
No protocol/monetary rule, fee, supply or branding decision changes here.

## Reproduction

```sh
python tools/wallet-delivery/tools/verify.py --native-root .
```

For bounded test processes, run every `--parts 10 --part N` from 0 through 9. A
single part is not the whole suite. Both the native and account inventories are
checked, plus this add-on's six required code files. See VERIFICATION.md for exact
executed scopes and distinctions from prior real-validator evidence. No Actions,
paid compute, public deployment, real funds, DNS/site or Resident/Luna work.

Primary RPC behavior reference consulted: CometBFT v0.38 API documentation for
broadcast_tx_sync states that its return is CheckTx, not final execution:
https://docs.cosmos.network/cometbft/v0.38/api-reference/rpc/tx/broadcast_tx_sync
