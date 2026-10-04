# 1soft

**Native payments with spending limits for people and persistent agents.**

1soft combines a native coin, scoped agent grants, shared budgets and portable
payment evidence. A wallet can preserve the original signed payment through lost
replies, changing validators, receipt collection and historical recovery. The
merchant workspace binds a payment to the exact signed invoice before fulfillment.

This is a **development network**. It has no public mainnet, value-bearing service,
chosen public supply or audited production wallet. The application uses pinned
CometBFT 0.38.25 for local validator consensus. Independent operators, external
security review, production custody and economic design remain release gates.

## Selected product direction

1soft is being evaluated as **private programmable money and durable economic
authority for people and persistent agents**. The first wedge is a private mission
treasury in which several agents share one aggregate allowance, retain unresolved
obligations through failure, obey current revocation, and disclose only the evidence
needed for a selected purchase. Read the [direction, decisive proof and explicit
reconsideration gates](docs/PRIVATE_ECONOMIC_AUTHORITY_DIRECTION.md), then the
[executable shared-parent attack model](docs/PRIVATE_AUTHORITY_ATTACK_MODEL.md).

This direction does not describe present on-chain privacy. Today's ledger remains
transparent, and the independent Layer 1 must still prove that it provides customer
guarantees that a confidential application on existing settlement rails cannot.

## Durable invoice payer

A fresh invoice-capable durable alpha combines committed invoice review and the
encrypted invoice store with the original shared wallet. Owner and delegated
payments retain exact signatures, fee holds, at-most-one local dispatch, historical
alpha receipts and inert A1 financial history as the chain advances. Both payment
and invoice consent remain required. See [the setup and boundaries](docs/DURABLE_INVOICES.md).
The separate [durable merchant adapter](docs/DURABLE_MERCHANT.md) verifies alpha
receipts before retaining one exact public resource result. Local HTTP retries and
cold reopening retrieve the original result without another charge; portable
alpha merchant proofs replay the payment and content commitment offline. The
legacy merchant formats remain exclusive to legacy receipts. Transactions remain public.

The [browser purchase flow](docs/BROWSER_MERCHANT_DELIVERY.md) can now retrieve
the enrolled original resource through a guarded host bridge, verify its digest,
and offer resource and proof downloads. Lost returns and cold listener reopening
require explicit review of the original payment, without another signature or charge.

## Try the local product

The [first-run guide](docs/LOCAL_DEMO_GUIDE.md) walks through a native payment,
agent spending review, verified receipt, encrypted history download and retained
workspace recovery. With the pinned prerequisites already installed on Linux/WSL:

```sh
python tools/local-platform/scripts/1soft.py doctor --engine /path/to/cometbft
python tools/local-platform/scripts/1soft.py new \
  --profile durable-private-alpha-v1 \
  --workspace "$HOME/1soft-alpha" --engine /path/to/cometbft
```

Open the exact loopback URL printed by the command. This starts four disposable
local validators and encrypted development vaults. The explicit durable alpha
retains up to 4,096 authenticated blocks in batches of at most 64, while preserving
the original signing journal and payment obligations across restart. Its original
24-hour horizon and uninterrupted checkpoint deadlines keep elapsing while stopped.
Stop with Ctrl+C. The default legacy profile retains its short-demo limits.
See [durable alpha](docs/DURABLE_ALPHA.md) and the
[local platform reference](tools/local-platform/README.md) for exact behavior.

## What you can build with it

| Capability | Delivered behavior | Start here |
|---|---|---|
| Agent spending | Recipient, lifetime and account limits; grants share a parent budget and one financial journal. | [Wallet and budget model](docs/STATE_WALLET.md) |
| Shared-parent attack model | Two copied journals race one parent fragment; exactly one fee-inclusive successor commits, stale authority fails and the losing obligation remains pending. Transparent semantics only. | [Private authority model](docs/PRIVATE_AUTHORITY_ATTACK_MODEL.md) |
| Native invoice checkout | A signed payment commits to the quote, merchant, amount and resource digest; the merchant verifies execution before fulfillment. | [Merchant browser](docs/MERCHANT_INVOICE_BROWSER.md) |
| Recoverable payment delivery | Original bytes, consumed dispatch claims and unresolved holds survive interrupted replies. Receipt collection and reconciliation are separate actions. | [P4 delivery](docs/P4_DELIVERY_ENGINE.md) |
| Changing validator committees | The opt-in P4 client verifies the complete signed roster history and replays payments from independently pinned genesis. | [P4 client](tools/protocol4-client/README.md) |
| Owner key replacement | Incoming-key consent and current-owner approval share the wallet's fee reservation and exact receipt confirmation. | [Owner replacement](docs/P4_KEY_ROTATION.md) |
| Encrypted historical recovery | Original journal rows, signed wires, holds and receipts survive complete backups, including larger admitted journals. Restored archives cannot sign or send. | [Custody and recovery](tools/protocol4-custody/README.md) |
| Durable merchant delivery | Committed alpha receipts unlock exact resource bytes; durable consumption, cold retries and separate offline proof. | [Durable merchant](docs/DURABLE_MERCHANT.md) |
| Browser purchase retrieval | Separate public-receipt consent, verified resource download and original proof through a fixed local merchant bridge; operator enrollment stays separate. | [Browser delivery](docs/BROWSER_MERCHANT_DELIVERY.md) |
| Reduced delivery disclosure | A strict local-alpha receipt projects only resource digest, loopback route, quote commitment, fulfillment fact and verifier anchor; it is not payment proof or shielded privacy. | [Minimal delivery receipt](docs/MINIMAL_DELIVERY_RECEIPT.md) |
| Durable private alpha | Incremental authenticated history, preserved original journal and an actual-hour qualification command; fresh genesis and explicit finite trust policy. | [Durable alpha](docs/DURABLE_ALPHA.md) |
| Browser history download | Explicit encrypted export of all retained shared wallet/delivery history; no private keys or active restoration. | [Browser recovery](docs/BROWSER_HISTORY_BACKUP.md) |
| Portable payment evidence | An offline checker verifies the original invoice, signed transaction, receipt and public content under external trust pins. | [Merchant proofs](docs/PORTABLE_MERCHANT_PROOF.md) |

Private invoice content is encrypted locally. **Ledger transactions remain public.**
This is not shielded on-chain privacy, a stablecoin, a bank account or an issued card.

## Two explicit development paths

The protocol-1/2/3 application supports the existing `CertifiedWallet`, legacy
explorer and receipt archive. Protocol 3 adds shared spending budgets. Flat and
opt-in `smt-v1` state commitments remain compatibility surfaces.

Protocol 4 is a separate **fresh-genesis, opt-in development application** combining
native payments and the validator registry in one SQLite commit and AppHash. Its
read client, signing journal, decision delivery, explorer and custody tools live
under `tools/protocol4-*`. The current local browser wallet and fresh merchant
workspace also use the P4 signing and delivery journals. Legacy static clients
refuse P4; copying files or changing a policy does not activate a protocol upgrade. See [P4 scope](docs/PROTOCOL4_DEVELOPMENT.md)
and [recovery integration](docs/P4_RECOVERY_INTEGRATION.md).

Use one supported shared signing journal for the same funds. Copied journals,
independent devices and raw key paths do not share its reservations. A collected
receipt does not release a hold until explicit wallet reconciliation. A historical
backup does not prove latestness, renew trust or fence the original device.

## Qualify a clean checkout

On Linux or WSL, with Git, Node and the versions in `requirements.txt` already
installed, run from the repository root:

```sh
python tools/local-platform/scripts/1soft.py check --output "$HOME/1soft-current-check"
```

The output must be a new directory outside the checkout with an existing parent.
The entry point executes `tools/release/check_current.py` with the same interpreter
and returns its actual exit status. This command checks the
complete current Git source and modes, installed dependency pins, native and
component Python suites, and the key-free JavaScript unit suites. It retains raw
logs, distinct test identities and exact source/run bindings. It does not install
software, start a public network or declare a production release.

**Local checks, browser journeys and real validator runs are separate evidence.**
The current-source command and affected-scenario workflow are explained in
[current qualification](docs/CURRENT_QUALIFICATION.md). Engine and browser receipts
belong to the exact tested revision; old green results do not automatically qualify
new code. The older fixed-manifest checkers and dated add-on documents retain their
original historical scope.

For actual local P4 validator acceptance with an already verified engine:

```sh
python scripts/run_protocol4_delivery_engine.py \
  --engine PATH_TO_COMETBFT --engine-sha256 PINNED_SHA256 \
  --output /private/new-p4-delivery-evidence
```

This creates disposable loopback validators and test keys. Follow the
[engine guide](docs/P4_DELIVERY_ENGINE.md) before running it. These keys and genesis
must never hold value. Owner replacement, fresh-node recovery, lost Commit replies,
browser merchant checkout and legacy protocol matrices have their own scenarios.
Fresh format-2 bootstrap and final snapshot-reply interruption are registered in
[the P4 state-sync gate](docs/PROTOCOL4_STATE_SYNC_QUALIFICATION.md); unit checks
and an old legacy state-sync pass do not qualify those real-engine profiles.

## Current engineering priorities

The read verifier now executes the complete ordered P4 history sequentially from
pinned genesis, while retaining signed header checks, every intermediate AppHash
and the original final receipt audit. This reduces repeated prefix work; it does
not prune history or change the node's execution rules. See [sequential replay](docs/P4_SEQUENTIAL_REPLAY.md).

Complete custody format 2 uses bounded authenticated frames for journals that exceed
the original format's complete-representation limit. Small backups still use format
1 automatically, and old backups remain readable. Original financial audits and
recovery-only authority remain. Explicit format 3 adds bounded lossless compression
to encrypted backups while preserving the exact format 2 stream and historical
authority. See [compact backups](docs/CUSTODY_COMPRESSION.md). Maximum-capacity
resource behavior and power-loss certification are still open. See
[backup scale](docs/CUSTODY_BACKUP_SCALE.md).

An explicit fresh read-store format 2 can retain complete canonical proof packets
with bounded lossless compression. The existing read verifier, receipt lookup and
explorer still consume the original bytes under the same external trust policy.
Observation and original-byte limits remain unchanged; small compressed files do
not admit more history. See [read-proof storage](docs/READ_PROOF_STORAGE.md).

P4 retains its height-512 and bounded-history development limits. Public throughput,
long-term history/pruning, cross-device coordination, hardware key recovery and
independent-host operation require separate design and evidence. The
[roadmap](docs/ROADMAP.md) lists the remaining gates without a launch promise.

The static website is separate from node infrastructure. This repository does not
create public RPC, deploy a chain, use real funds, or run GitHub Actions. Read
[node admission](docs/NODE_ADMISSION.md), [source and reuse notice](NOTICE.md) and
the project [engineering contract](AGENTS.md) before extending the code.
