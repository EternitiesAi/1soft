# 1soft P4 decision delivery

29 September 2026. Add-on for PR #28 at
`b73a88ca53666972ae2c8ce35fd9edb7ac0cb41c`, tree
`123e5bfc57d42ee31736969f61aa5a6d32482832`, with the exact previously supplied
P4 read client and transfer wallet. Existing node, signer, wallet, read client,
legacy delivery and explorer implementations are unchanged.

## A complete local payment path, not a new signer

The delivery API accepts an existing **P4Wallet decision ID**, exact payer and
owner/grant role. It recovers and revalidates that decision through the existing
wallet's saved evidence and signatures. It never accepts a free-standing signed
transaction for submission, a private key, a password, an administrative operation,
or a callback that can invent signing authority.

`prepare` creates a separate delivery review. The digest binds the wallet and
delivery identities, exact original signed-wire hash, endpoint, payer/role,
reviewed wallet revision, validator epoch, current checkpoint and fee-inclusive
debit. It creates no hold or dispatch. An intervening wallet signature or imported
checkpoint makes the review stale. A changed review cannot authorize another
endpoint, payment or role merely by recomputing an untrusted digest.

`send` rechecks the complete signed decision, current verified evidence, all local
pending account/shared-budget debits, grant validity, nonce and expiry. Expired or
revoked payments, deficits and already-recorded payments are refused. Missing
agent authority never falls back to the owner's role. Freshness and the original
external trust deadline are enforced without renewal.

All of that happens before network access. The implementation uses the existing
strict native `payment_transport._worker` and `payment_rpc` HTTP path solely as a
bounded key-free transport. The old static DispatchJournal is NOT initialized
with P4 or weakened. Only one `broadcast_tx_sync` request is made. Response identity
and exact integer CheckTx codes are validated by the inherited worker and again by
this adapter; code=False is not code=0. The response remains an endpoint observation,
not a verified execution or nonexecution decision.

## Durable attempt before I/O

The delivery journal stores a single claim per decision BEFORE invoking the network
worker. The wallet and delivery database locks are released before HTTP. Two senders
using this journal cannot both claim the same decision; repeating a send or reopening
an interrupted process cannot automatically submit it again.

This deliberately does **not** promise globally exactly-once delivery. A process
may die after the attempt commits but before any request is sent. The record then
means uncertain dispatch, not successful submission or proof of nonexecution.
There is no retry/delete/reset/rearm/cancel API in this slice. A lost or declined
payment may remain unresolved indefinitely. Do not recreate the journal or resign
a transfer to bypass that restriction. Safe explicitly authorized repeat-attempt
handling is future work.

The tests also exercise a separate second delivery journal: it can submit the same
wire again. The native chain rejects replay without another debit, but the second
submission still occurs. Copies, other journals/devices, raw-key use, direct signed
wire submission and malicious local storage/clock control are outside coordination.

## Collection is not reconciliation

`collect` calls the unchanged P4 read worker, using only `abci_query`, `commit` and
`block`. It captures state H once, waits only for that state's fixed H+1 signed
commitment, obtains the complete bounded history, and verifies dynamic signatures,
transaction inclusion, monetary execution and administrative transitions.
The delivery adapter re-verifies the resulting proof and requires the exact signed
payment receipt. Original wire, signer and recorded receipt identity must agree.

Collection writes positive receipt evidence only to the delivery journal. The
wallet's signed bytes, pending holds and revision remain unchanged. Missing evidence
is `unavailable`, never unpaid or safe-to-retry. Unrecognized/unavailable network
responses, incomplete history or a false receipt cannot release an obligation.

`reconcile` is separate and requires the explicitly reviewed current wallet revision.
Only the original P4Wallet.sync imports the proof and retires a positively matched
obligation. If a newer wallet checkpoint already contains that exact receipt,
reconciliation returns `already_recorded` without trying to import an older state.
If wallet sync commits and the return is lost, reopening recognizes the recorded
receipt rather than claiming rollback or syncing it twice. No transaction spans
both databases and the network.

`inspect` and `export-receipt` reverify retained evidence at its historical recorded
times, including exact role binding. They remain available after policy expiry but
explicitly do not establish current spending authority or renew trust. New send,
collection and wallet reconciliation still refuse after expiry. Historical exported
proofs require their independently supplied genesis and policy, not trust chosen
by the export itself.

## Scope and limits

Only literal `http://127.0.0.1:PORT/` endpoints are accepted. No DNS, public addresses,
HTTPS, redirects, proxies, credentials or public listener is added. The inherited
submission worker has a four-second total deadline. The read worker retains its
45-second deadline, at most 162 calls and 64-block RPC history limit; no automatic
polling or background task is created. Offline proof import retains the existing
512-block/16-MiB development evidence bounds.

Up to 256 attempt claims and 32 collected receipts / 64 MiB of receipt payload are
retained. Capacity exhaustion refuses instead of evicting evidence. These are
logical bounds, not complete disk/RAM or production-throughput guarantees.

The separate SQLite journal is pinned to wallet ID, policy, genesis and endpoint.
Creation is explicit/exclusive. Missing, empty, mismatched or unknown configuration
is refused, not repaired. Wallet, delivery and all SQLite sidecar path families must
be disjoint. Private owned POSIX paths and regular unaliased files are required.
All saved attempts are rechecked against their actual historical wallet context.
These checks assume a trusted host and filesystem; they do not qualify hostile OS,
whole-workspace rollback or power-loss durability.

This adapter intentionally uses the exact version-pinned P4 wallet audit functions
rather than copying its reservation rules or exposing another signer. They are
internal APIs; any dependency upgrade requires explicit review and requalification.
The generic network worker is reused without invoking legacy P4-rejecting signers.

## Commands

Install the three directories in `addons/` under the actual PR28 checkout's `tools/`.
Run the existing pinned Python dependencies; no automatic downloads occur.

```sh
python tools/protocol4-delivery/tools/verify.py --native-root . --report ../new-delivery-tests.json
python tools/protocol4-delivery/scripts/demo.py --output ../new-delivery-demo
```

All normal CLI commands require `--genesis`, `--policy`, `--wallet`, `--journal`
and `--endpoint`. The wallet must already exist; the delivery CLI cannot initialize
or replace it. Example arguments are placeholders, not production trust policy.

```sh
python tools/protocol4-delivery/scripts/p4_delivery_cli.py \
  --genesis /private/engine-genesis.json --policy /private/policy.json \
  --wallet /private/wallet.sqlite --journal /private/delivery.sqlite \
  --endpoint http://127.0.0.1:26657/ init

# Same global arguments as above:
# prepare --decision-id ID --payer ACCOUNT --grant raven --output NEW-REVIEW.json
# send --review NEW-REVIEW.json --confirmation EXACT_REVIEW_DIGEST
# inspect --decision-id ID --payer ACCOUNT --grant raven
# collect --decision-id ID --payer ACCOUNT --grant raven
# reconcile --decision-id ID --payer ACCOUNT --grant raven --expected-revision WALLET_REVISION
# export-receipt --decision-id ID --payer ACCOUNT --grant raven --output NEW-PROOF.json
```

Read the full delivery review before confirming its digest. Omit `--grant` for the
owner lane. `import-receipt --evidence FILE` supplies original offline evidence
instead of collection; it still requires the exact decision/payer/role. Obtain the
wallet revision with the existing wallet's `status` command. Output files must be
new and in private directories. Failed output does not imply rollback.

Exit zero means that command completed, not that an endpoint-admitted payment has
executed. An unresolved/declined submission and an unavailable collection return2.
The CLI never interprets a nonzero exit as safe to resend.

## Demonstrated and still unassessed

The demo signs Raven58+fee2 and Atlas38+fee2 under a shared100 budget and rejects
Atlas39+fee2. It deletes fixture vault files, submits Raven once, drops the actual
TCP reply after native execution, reopens and collects without changing the100 hold.
Wallet reconciliation reduces pending to40/spent60. All validators are replaced;
the original Atlas wire and40 hold survive. Atlas is sent once, its normal response
is received, and separate collection/reconciliation ends pending0/spent100. An older
receipt revisited under the newer checkpoint is already_recorded, not a rollback.

The node is a local HTTP fixture backed by real P4 application transitions and
synthetic committee signatures. It is not CometBFT voting, independent operators,
a public payment service or real funds. Test execution includes actual process exits
around the claim, network return and wallet sync, not a P4 engine Commit-reply drill.
The ordinary P4 engine, actual changing-validator acceptance, user-facing wallet,
independent security/custody review, retry/retirement design and public economics
remain separate gates. No Actions, paid compute, deployment, site/DNS, Resident/Luna
work, real keys for production, force-push or merge is part of this component.
