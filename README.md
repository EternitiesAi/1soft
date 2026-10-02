# 1soft — native cryptocurrency development

1soft is a native-coin development project for people and persistent agents. This
branch combines the v0.16 node source with the private repository's earlier
attested-state wallet. **There is no public or production network, real-fund service, dollar
backing, bank account, issued card, or audited wallet.** Public economics and
licensing remain open.

## What the code does

The application implements native transfers, agent grants, account opening and key
rotation, protocol-3 shared budgets, receipt records, persistent compact state
proofs, bounded execution images, and a bounded ABCI state-sync snapshot path. CometBFT v0.38.25 is the pinned consensus engine; the Python application
speaks its ABCI protocol. The v0.16 admission cache is bound to exact transaction
bytes and a committed checkpoint. Proposal and finalization still execute the
transactions against ordered native state.

The older state-wallet outbox is retained for history and refuses protocol 3. The
current protocol-3 development path uses the shared-journal `CertifiedWallet`,
decision-bound delivery and verified receipt reconciliation. Separate devices, raw
keys, copied journals and the legacy outbox are still outside that local reservation
boundary; do not operate competing signing paths against the same funds.

An **opt-in fresh-genesis protocol-4 development application** combines native
payments and the SIP-0003 validator registry in one SQLite commit and AppHash.
It has a separate ABCI entry point and format-2 composite state sync. The
protocol-1/2/3 node and static wallet, explorer, and receipt archive refuse
P4. Separate development P4 read, signing-wallet and decision-delivery clients
verify signed validator history and native execution; receipt collection leaves
wallet holds intact until explicit reconciliation. See
[P4 client and engine acceptance](docs/P4_DELIVERY_ENGINE.md) and
[protocol-4 development scope](docs/PROTOCOL4_DEVELOPMENT.md).


## Follow the original payment

P4 wallets can now [create an encrypted journal backup and restore a historical
recovery archive](tools/protocol4-custody/README.md). The archive preserves original
transactions, spending holds and consumed delivery attempts, and can export saved
receipt evidence. It cannot sign or dispatch, establish that a backup is current,
or fence the old signing device. Private keys are outside this backup.

The local browser wallet locks pending reviews to their request and signing role,
inspects the saved wallet after a lost response, and shows the next action for the
original payment. Unknown outcomes, collected receipts, reconciled execution and
historical authority remain distinct. Desktop/mobile rendering and an actual
guarded-service browser journey have bounded fixture checks; native consensus
evidence remains tied to its earlier exact source. See
[browser payment recovery](docs/BROWSER_PAYMENT_RECOVERY.md).

## Merchant checkout in the browser

The local invoice wallet shows the merchant's public terms beside the native
payment review and requires both approvals before signing. It preserves the
original payment through interrupted responses, expiry and historical recovery.
The browser never decrypts private invoice content. Merchant fulfillment remains
independently verified. See [the merchant browser guide](docs/MERCHANT_INVOICE_BROWSER.md)
for the configured v3 workspace, local launch command and exact verification scope.

## Signed invoice payments

The fresh **v3 local merchant workspace** supports native signed invoice terms.
Its owner, Raven and Atlas payments bind the exact quote, public resource digest,
chain, merchant, amount and lifetime in the original native signature. The
merchant replays the payment and checks that commitment before releasing the
resource. Private invoice content remains locally encrypted; the ledger remains
public. Existing workspaces are preserved and cannot enable this capability by
repinning their files. See [native invoice commitments](docs/NATIVE_INVOICE_COMMITMENTS.md).

Merchants can [export portable payment proofs](docs/PORTABLE_MERCHANT_PROOF.md)
containing the original committed terms, signed payment, native receipt and public
content. A separate offline checker replays them under independently supplied
trust and invoice pins. This proves payment/content binding, with no external
service delivery or on-chain privacy claim.

```sh
python tools/private-payments/scripts/1soft_merchant_network.py init \
  --workspace NEW_PRIVATE_DIRECTORY --engine PINNED_COMETBFT \
  --recipient-count 3 --invoice-commitments
python tools/private-payments/scripts/qualify_native_invoice.py \
  --engine PINNED_COMETBFT --output NEW_QUALIFICATION_DIRECTORY
```

The candidate qualifier checks the exact changed-file map against `a09afbf`, all
component suites, official Go vectors and local validator journeys. Historical
byte-seal scripts and manifests below belong to their earlier parent revisions;
they intentionally refuse this modified native/caller candidate. The qualification
result records execution status. Local tests do not establish production privacy,
custody, economics or independent operator readiness.

## Node bootstrap

Format-1 ABCI state sync can now serve and restore a bounded complete application
snapshot to a fresh node whose native genesis is explicitly pinned. Peer metadata
and chunks do not establish authority: the restored native state is fully validated
and must reproduce CometBFT's light-client-verified AppHash before it is committed.
The current 16 MiB snapshot ceiling and complete receipt history make this a
development bootstrap path, not the final pruning design. See
[state sync](docs/STATE_SYNC.md). Its new real-engine acceptance runner is authored
but still must execute on the exact modified source before this feature is called
engine-qualified.

Protocol 4 uses a separate format-2 snapshot. It replays monetary and signed
registry inputs against the trusted composite AppHash, but does not import peer
claims about historical block IDs, votes, or full responses. Historical `/block/H`
results remain unavailable on a newly synced node until separately verified.
The combined P4 development candidate includes real-engine bootstrap and durable
Commit reply-loss acceptance alongside the client delivery gate. See
[P4 recovery integration](docs/P4_RECOVERY_INTEGRATION.md) for exact scope,
source compatibility, commands and remaining qualification boundaries.

## Verification boundary

Historical checkpoints have executed pinned CometBFT v0.38.25 on one-host
four-validator protocol-1/2/3 networks, including certified wallet and decision
delivery flows. Those results are source-specific development evidence, not an
independent-operator testnet or production security audit. The current ABCI
state-sync additions modify application/wire code and therefore require their own
real-engine gate rather than inheriting an older green network result. Exact
source/test scopes live beside each checkpoint and in `docs/STATE_SYNC.md`.

On a trusted local Linux/WSL host with the pinned Python dependencies installed:

```sh
python scripts/verify_checkout.py
python scripts/run_tests.py
python scripts/check_upstream_wire.py --output NEW_OUTPUT.json
python scripts/local_dev.py network --engine PATH_TO_COMETBFT --output NEW_DIRECTORY
python scripts/run_state_sync.py --cometbft PATH_TO_COMETBFT --protocol-version 1 --output NEW_STATE_SYNC.json
python scripts/run_state_sync.py --cometbft PATH_TO_COMETBFT --protocol-version 3 --state-commitment smt-v1 --output NEW_SMT_STATE_SYNC.json
```

The network gate must run the real engine and all four scenarios; fixture
certificates and scripted application calls are not substitutes. The local runner
uses disposable validator keys and loopback listeners only. Do not use its public
test seeds for funds.

The P4 real-engine runner is separate:

```sh
python scripts/run_protocol4_engine.py --engine PATH_TO_COMETBFT --engine-sha256 PINNED_SHA256 --output NEW_P4_RESULT.json
```

Its one-host result cannot qualify independent operators, custody, economics,
dynamic client evidence, or a public network.

No GitHub Actions, public RPC, hosted compute, or production keys are used here.
The static website is separate. Read [node admission](docs/NODE_ADMISSION.md),
[wallet scope](docs/STATE_WALLET.md), [verification](docs/VERIFICATION.md), and
[reuse notice](NOTICE.md) before extending or reusing this code.
