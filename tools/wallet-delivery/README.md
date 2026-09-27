# 1soft decision-bound payment delivery

Submit a payment that the existing shared `CertifiedWallet` has **already signed**,
then recover its receipt and reconcile the original wallet. This add-on accepts a
wallet decision ID, explicit payer and grant role—not an arbitrary transaction
file, private key, password, draft, browser balance or replacement payment.

It calls the existing native dispatcher and receipt verifier. It does not create
another signer, spending-reservation store, monetary rule or transport protocol.
The financial wallet and the transport journal keep their different responsibilities.

## Source basis and availability

Normal dependencies are fully published PR #10 at
`631dcc309c01ea5d183c90d5983e45063695e12a`, tree
`787e791857a0a0e8dc65f057da754614270e8c05`: the PR #7 core plus the read-only
account inspector. All new runtime files live in `tools/wallet-delivery`.
There is no dependency on the unpublished catch-up extension or `transfer_flow`.
The optional end-to-end demo switch `--with-transfer` also exercises the previously
delivered local transfer-preparation adapter when present.

This complete conversation package additionally retains the tested local transfer
workflow at `1299b1d6d3a0ceaa2d6365f0f4987a59bfc3a2e4`. That parent is not a
published remote commit. The new delivery-only patch applies both to that local
parent and to exact published PR #10. It contains none of the previously blocked
transfer implementation. No source push, branch update or merge was performed for
this checkpoint; this session's GitHub actions exposed reads, not source writes.

## Three independent facts

1. A signed wallet decision creates the existing wallet's pending obligation.
2. A dispatch attempt records that the original bytes may have been submitted.
3. A verified receipt establishes recorded native execution under the pinned
   committee assumption. The wallet still has to verify the new state and its
   ancestry before it reconciles the obligation.

`endpoint_admitted` is not execution, and `unresolved` is not nonexecution. Receipt
collection deliberately leaves the financial wallet unchanged. A separate
`reconcile` operation calls the unchanged `CertifiedWallet.sync` to verify the
full state, header continuation, freshness and all its signed obligations.

A failed reconciliation retains the collected receipt and the prior wallet hold.
A crash after the wallet commit but before returning may leave reconciliation
completed: read the original decision again. No automatic resend, re-signature,
nonce increment, fee change, role fallback, policy renewal or balance release
occurs in this add-on.

## Commands

Use an installed, trusted Linux/WSL development environment with the repository's
pinned dependencies. These are templates, not public network configuration:

```sh
umask 077
export PYTHONPATH="$PWD/src"
base=(--genesis /private/genesis.json --policy /private/policy.json
      --wallet /private/wallet.sqlite --delivery-journal /private/delivery.sqlite
      --endpoint http://127.0.0.1:26657/ --account ACCOUNT_ID
      --grant-id raven --decision-id EXISTING_DECISION_ID)
python tools/wallet-delivery/scripts/deliver.py "${base[@]}" queue
python tools/wallet-delivery/scripts/deliver.py "${base[@]}" send \
  --confirm EXACT_DELIVERY_CONFIRMATION_FROM_QUEUE
python tools/wallet-delivery/scripts/deliver.py "${base[@]}" status
python tools/wallet-delivery/scripts/deliver.py "${base[@]}" refresh
python tools/wallet-delivery/scripts/deliver.py "${base[@]}" reconcile \
  --continuation /private/intermediate-signed-headers.json
python tools/wallet-delivery/scripts/deliver.py "${base[@]}" export-proof \
  --output /private/new-receipt.json
```

Only `queue` can initialize a new dedicated delivery journal. Existing wallets,
legacy outboxes, payment-job databases and unrelated SQLite stores are rejected
rather than converted. Wallet and delivery files must differ. Private owned
paths and normal WAL coordination are required. Existing exports are not overwritten.

`queue` does not contact RPC. Repeating it cannot reset a previous dispatch attempt.
`send` requires a confirmation binding the original decision, payer, grant,
canonical signature bytes, selected wallet/delivery locations and pinned route.
It is a content/route confirmation, not a secret or proof of human authentication.
Every send rechecks the stored signature and fresh local account evidence, and
trials the already-signed transfer in a disposable ledger copy. This cannot create
a new outgoing signature. It refuses already-recorded, expired, revoked, wrong-key,
wrong-role or stale-state requests before opening the socket where locally known.

After an attempt, another submission requires the explicitly selected `replay`
command and the same confirmation. Replay always uses the same original bytes.
When the original receipt is already known, this journal refuses resending.
`refresh` allows only the existing bounded read-only receipt collector; optional
`--read-attempts 1..4` waits for the captured state's following commitment, not a
second payment. `reconcile` makes no network request. Intermediate headers, when
needed, must be supplied explicitly and satisfy the existing wallet's 64-header
continuation bound. This is not a replacement for the separate long-gap client.

The CLI's exit zero means the command returned a report—not that money was paid.
Inspect BOTH `transport_status` and `wallet_obligation_status`, plus
`exact_transport_receipt_verified` and `wallet_reconciliation_needed`. Errors warn
that a prior submission or wallet commit may still exist. No password or vault
option is provided, and no browser/HTTP signing service is started.

## Verification and local example

```sh
python tools/wallet-delivery/tools/verify.py --native-root .
# Equivalent bounded runs: all four parts are required for the full add-on claim.
for n in 0 1 2 3; do
  python tools/wallet-delivery/tools/verify.py --native-root . --parts 4 --part "$n"
done
python tools/wallet-delivery/tools/demo.py --native-root . --output /private/new-demo
```

The default demo signs disposable fixture decisions through the original wallet.
In the complete transfer-workflow package, append `--with-transfer` to exercise
its prepare/approve adapter too. Only the latter demonstration needs that
separately delivered adapter. Test fixtures execute the actual native application
and use real loopback HTTP. The fixture closes the TCP connection AFTER native
execution, then exposes synthetic committee-signed evidence for read-only recovery.
This is distinct from the earlier real-validator tests' injected client-side loss;
it is not a fresh CometBFT or public-network result.

The demo preserves pending 100 until Raven's full-state reconciliation, then40,
then0 after Atlas's. Recorded budget spending finishes at100 and account balance
at892, including eight setup-fee units. All figures are unbacked DEV atomic units.
No generated private keys are exported; the demo removes its fixture vault files
before delivery to show that this stage does not need them.

## Limits

This is one shared local signing journal and one explicitly selected transport
journal. There is no distributed lock or atomic transaction spanning both stores.
A signer or sync can change the wallet after the last read and before submission;
native execution remains the final authority. Whole-workspace rollback, other
devices, copied journals, raw keys, older outboxes and direct dispatcher use are
outside this adapter. Tests explicitly demonstrate that another delivery journal
can submit the same bytes again. Native idempotency prevents recharging that
identical accepted transaction; this is not globally exactly-once delivery or
merchant/task deduplication.

Historical status remains readable after policy expiry, but submission and new
wallet sync do not renew that policy. The code verifies full, unpruned historical
state under static validator trust. It cannot guarantee the latest network state,
prove legal ownership, assess service quality or erase a prior public signature.
File checks assume a trusted local OS/filesystem; they are not hardware custody,
anti-rollback hardware or protection from a malicious same-user process.

No public RPC, real funds, issuance, dollar backing, bridge/card/bank integration,
Actions, paid compute, DNS/site work, Resident/Luna/Psyche changes, force-push or
merge. The site's deployment remains separate. See VERIFICATION.md for the exact
new test scope and unfinished actual-validator acceptance.
