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

## Current developer paths

| Path | What works | Entry point and evidence |
|---|---|---|
| Local browser product (P4 durable alpha) | Native public-ledger payments, spending review, invoices, merchant resources and retained recovery | [First-run guide](docs/LOCAL_DEMO_GUIDE.md), [durable alpha](docs/DURABLE_ALPHA.md), [release architecture](docs/LOCAL_DEVELOPER_RELEASE.md) |
| Proof-backed owner treasury (P7) | Fresh-network enrollment/revocation/rotation, atomic payment/shared allowance, exact owner/payment recovery after lost acknowledgements | [Owner profile](docs/PROTOCOL7_OWNER_TREASURY.md), [prepared-wire client](docs/PROTOCOL7_CERTIFIED_CLIENT.md), [actual caller receipt](evidence/protocol7-client/20261005/client-qualified-01.json) |
| Encrypted restricted CHANGE custody (P7) | Exact certified import, encrypted reopen, protected-input re-spend and original-wire recovery | [Custody guide](docs/PROTOCOL7_VAULT.md), [commands](docs/PROTOCOL7_CUSTODY_CLI.md), [24-check receipt](evidence/protocol7-vault/20261005/vault-qualified-02.json) |
| Retained authority and preparation status (P7) | Three-payment CHANGE 7 -> 4 -> 1 progression, original-wire recovery, AS-OF inspection and full-state restart certificate | [Authority](docs/PROTOCOL7_RETAINED_AUTHORITY.md), [reconciliation](docs/PROTOCOL7_RECONCILIATION.md), [36-check v2 receipt](evidence/protocol7-reconciliation/20261006/reconciliation-qualified-04.json) |
| Certified local purchase fulfillment (P7) | Precommitted exact resource quote, native recipient/amount/expiry opening, encrypted disclosure and same-result recovery after a lost reply | [Merchant guide](docs/PROTOCOL7_MERCHANT.md), [26-check actual receipt](evidence/protocol7-merchant/20261006/merchant-qualified-03.json) |

The separate [P8 recipient component](docs/PROTOCOL8_RECIPIENT.md) adds
key-controlled receive/re-spend and a bounded native state kernel. Its
[validator application](docs/PROTOCOL8_RECIPIENT_CONSENSUS.md) now has a
[19-check actual four-validator receipt](evidence/protocol8-validator/20261006/recipient-validator-01.json):
receive/re-spend, valid competing-spend refusal, ordered proposals, atomic
persistence, same-store restart and signed AS-OF full-state replay. This is a
finite synthetic qualification on one host. The separate
[P8 encrypted recipient wallet](docs/PROTOCOL8_RECIPIENT_WALLET.md) has a
[22-check actual wallet receipt](evidence/protocol8-wallet/20261006/recipient-wallet-02.json):
exact received-note import, arbitrary native spending, discarded-reply original
recovery, private recipient delivery and certified conflict holds. P8 state sync,
production custody and public deployment remain separate gates; no P7 notes migrate.

P7 is an opt-in successor with a fresh genesis. It does not migrate or upgrade
P4/P6 state, and it is not the default browser or merchant path. Its developer
path prepares real proofs, retains encrypted CHANGE/private authority and
inspects original obligations without automatic retry. These receipts cover
one trusted host with finite synthetic funds. Recipient disclosure/discovery,
merchant redemption and production custody remain open gates. See the [deployment readiness map](docs/DEPLOYMENT_READINESS.md)
for the remaining privacy/custody, scale, operator and economic decisions.

## Selected product direction

1soft is being evaluated as **private programmable money and durable economic
authority for people and persistent agents**. The first wedge is a private mission
treasury in which several agents share one aggregate allowance, retain unresolved
obligations through failure, obey current revocation, and disclose only the evidence
needed for a selected purchase. Read the [direction, decisive proof and explicit
reconsideration gates](docs/PRIVATE_ECONOMIC_AUTHORITY_DIRECTION.md), then the
[executable shared-parent attack model](docs/PRIVATE_AUTHORITY_ATTACK_MODEL.md).
The [shielded privacy foundation](docs/SHIELDED_PRIVACY_FOUNDATION.md) describes
the isolated transparent-witness note transition now present in source and the
security gates that must precede any on-chain privacy claim.

This direction does not describe production on-chain privacy. Protocols 1 through 4
remain transparent. Protocol 5 is a separate finite development profile for
Halo2-verified note spends; it does not make the earlier ledgers private or by
itself establish anonymity, metadata resistance or a production private-money
system. The independent Layer 1 must still prove that it provides customer
guarantees that a confidential application on existing settlement rails cannot.

The new [shielded-note lab](tools/shielded-note-lab/README.md) is an isolated
research component under qualification against its
[design specification](docs/superpowers/specs/2026-10-04-shielded-note-lab-design.md).
It uses synthetic keys and values to examine note commitments, nullifiers,
authenticated membership, spending authorization, integer conservation, exact
replay, failure recovery and selected-output disclosure. Making those rules
executable exposes semantic mistakes before a future circuit has to encode them.
No production proof system has been selected for the chain. The lab provides no zero-knowledge privacy,
production readiness, public deployment or real-funds support; the live ledger
remains public and no wallet, browser or consensus caller uses the lab.

The separate [privacy-proof benchmark](tools/privacy-proof-benchmark/README.md)
has two experimental profiles for one synthetic one-input/two-output relation:
gnark v0.16.3 with gnark-crypto v0.21.0, Groth16 over BN254, Poseidon2 and
ephemeral setup; and Zcash Halo2 0.4.0 with Pasta IPA, Poseidon P128Pow5T3 and
deterministic public parameters. Both verifiers run offline against exact source
and require the listed rejection cases. This is not a
production proof-system selection, production privacy, consensus integration,
network anonymity, custody, independent review, public-network readiness or
real-funds safety.

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
| Shielded-note transition lab | Isolated transparent-witness source under qualification for local note-spend, replay, recovery and disclosure semantics; no proof system or live integration. | [Component and boundaries](tools/shielded-note-lab/README.md) |
| Privacy proof-stack benchmark | Two independent local profiles for one frozen synthetic note relation: Groth16/BN254/Poseidon2 and Halo2/Pasta IPA. Each has adversarial acceptance/rejection coverage; exact-source qualification remains separate from production integration. | [Benchmark and boundaries](tools/privacy-proof-benchmark/README.md) |
| Protocol 5 shielded consensus profile | Separate fresh-genesis, finite note chain with actual Halo2 proof admission, global nullifier/output uniqueness, atomic persistence and marker-only state sync, qualified on one loopback host. | [Component](tools/shielded-consensus/README.md) and [protocol guide](docs/PROTOCOL5_SHIELDED_CONSENSUS.md) |
| Authenticated obligation reconciliation | The supported root wallet shares exact receipt and post-expiry absence classification with a compact Protocol 3 audit seam. The compact audit does not mutate wallet holds. | [Authenticated reconciliation](docs/AUTHENTICATED_RECONCILIATION.md) |
| Opt-in cloned-journal fencing | A shared owner-only POSIX registry gives explicit `FencedApproval` callers one active device epoch and one reservation per payer/role/nonce. Direct approval and separate registries bypass it. | [Device fence](docs/DEVICE_FENCE_RESERVATION.md) |
| Real-engine state sync | Both registered P4 profiles passed the external controller and independent semantic validator for one exact source tree on one loopback host. | [Phase-two engine evidence](docs/PROTOCOL4_REAL_ENGINE_SECURITY_PHASE2.md) |
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

Private invoice content is encrypted locally. **Protocol 1 through Protocol 4 ledger
transactions remain public.** Protocol 5 has a different public statement and state
model, but its one-host qualification is not evidence of production privacy. None
of these profiles is a stablecoin, bank account or issued card.

## Three explicit development paths

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

Protocol 5 is another separate **fresh-genesis, opt-in development application**.
It has its own canonical genesis, AppHash, SQLite schema, state-sync domain and
circuit identity. Four immutable equal-power validators admit bounded public
transaction statements only after an isolated verifier worker accepts the actual
Halo2 proof; global nullifier and output uniqueness, ordered note-tree appends and
finite history budgets remain application consensus rules. Validators contain no
prover or witness operation. The development client and prover run only in the
external qualification controller. There is no state migration or live upgrade
from Protocols 1 through 4. See the
[shielded-consensus component](tools/shielded-consensus/README.md) and
[Protocol 5 guide](docs/PROTOCOL5_SHIELDED_CONSENSUS.md).

### Protocol 5 qualified identity

The source-bound consensus and state-sync checkers passed for one loopback host
with synthetic notes and fresh validator keys. These hashes identify that exact
development evidence; they do not extend it to later source or another binary.

| Identity | Exact value |
|---|---|
| Qualified implementation source | commit `6a8f33c9e5e6fa53ff2cb13ae66df9c81d7d79ff`; tree `f98000a92e780c8cc54338345db18696a55cd8d0` |
| CometBFT | v0.38.25; SHA-256 `218628da07bed5d27e178d38d0bef9ecf46f21b214c8e9fea402fd215fccc024` |
| Verifier worker | SHA-256 `e3af1dc06bc109129dbf2e7429a72d5919f9118ed93c2b2c72ad71731bd96278` |
| Development controller binaries | client SHA-256 `7fdb0f90c1414252732a134727aea9a66e0402c651f1dc6ed34ce2759a3a5b3f`; prover SHA-256 `f7a01f3269a225024f9f743a5b6e242f1bd9f3fc1e87970c50f20c3675d31806` |
| Cryptographic profile | profile ID `272f8ea5ea7e04fa24b27c5125650150760b618229f2f3fbe0b7cc95bbca3eef`; descriptor SHA-256 `37f40b69aa64ae78e08ab50bb6efc962d272b7c8a62b16c77f0beeadb6c5c74a`; KAT SHA-256 `2a3d49921a6a9106637573849b503457314afbe180cf81f2235a0408b3746e22` |
| Deployment binding | ID `76129871a4659caf919ccdb32c545b0330b4ba1018cf6b1ec85ac61582eb3cac`; toolchain SHA-256 `eb2972cd9713e39085ca241b802ed9d9fdb267aae7233912d01912d6ca75d6ca`; sandbox policy SHA-256 `1cd41bb9a0bd45702e8e0cc6ffbe63f3e10315121785775700b69ce44610c97b` |
| Qualification template | genesis SHA-256 `298e09fb615e041b61e729d5ccf9d441a1fe417fbebb409b02c3349c6dc39f94` |
| Fresh run genesis values | consensus SHA-256 `7c4d3206eac0ee5b6717f7acd6f748b56b9a64cc8a26a170e8d364c71f3e53bf`; state-sync SHA-256 `bdbb9d76c4256e99f68002b095d7f1d2e4726f99e1be4127ef49cd72830cdb89` |
| Checked reports | consensus SHA-256 `6ef26345af2654f3553b6a884eeef81b11ef1bb26c361c46bb82c0de05b8bd42`, checker receipt `0a93d3f1680dc636d307f4ffd90fe0f129301a4ae583695b5e131146e8aa97df`; state-sync SHA-256 `5ba80ad83b17d57935edb8e9985b0df0e5deab6912693625204fbff1421713d4`, checker receipt `16ce3c15f65b26ed0cb4a205b6ec444f7372404e5fb7043b5095411f8c312010` |

This qualification establishes bounded one-host development behavior for the
listed source and artifacts. Public-network readiness, real-funds safety,
anonymity or metadata resistance, production custody, exchange readiness,
scaling, production proof-system selection and independent cryptographic review
all remain false or unassessed.

Use one supported shared signing journal for the same Protocol 1 through Protocol
4 funds. Copied journals,
independent devices and raw key paths do not automatically share its reservations.
The optional local device-fence adapter coordinates only clones that explicitly
use the same live registry; direct `P4Wallet.approve`, existing CLIs, raw signers,
separate registries and restored registries remain outside that boundary. A
collected receipt does not release a hold until explicit wallet reconciliation.
A historical backup does not prove latestness, renew trust or fence the original
device.

## Qualify a clean checkout

On Linux or WSL, with Git, Node, local Go >=1.25.7, the Go modules already
cached, and the versions in `requirements.txt` already installed, run from the
repository root:

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
and an old legacy state-sync pass do not qualify those real-engine profiles. Both
profiles passed for the exact source commit and tree recorded in the
[4 October real-engine report](docs/PROTOCOL4_REAL_ENGINE_SECURITY_PHASE2.md);
later consensus or state-sync changes require new runs.

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

The root full-state wallet now uses one exact authenticated receipt classifier
for positive inclusion and absence strictly after the signed expiry height. A
Protocol 3 compact witness can produce separately persisted audit evidence under
a pinned static-validator checkpoint, but it does not independently update wallet
headroom or reservation state. See
[authenticated reconciliation](docs/AUTHENTICATED_RECONCILIATION.md).

An opt-in trusted-host registry can serialize actual cloned P4 wallet approvals
and fence a retired device key for callers that use `FencedApproval`. It is a
local development seam: the registry is not chain-enforced, does not cover legacy
approval paths, and can strand a fail-closed reservation after interruption. See
[device fencing](docs/DEVICE_FENCE_RESERVATION.md).

P4 retains its height-512 and bounded-history development limits. Public throughput,
long-term history/pruning, cross-device coordination, hardware key recovery and
independent-host operation require separate design and evidence. The
[roadmap](docs/ROADMAP.md) lists the remaining gates without a launch promise.

The static website is separate from node infrastructure. This repository does not
create public RPC, deploy a chain, use real funds, or run GitHub Actions. Read
[node admission](docs/NODE_ADMISSION.md), [source and reuse notice](NOTICE.md) and
the project [engineering contract](AGENTS.md) before extending the code.

## Later Protocol 5 wallet continuity

The [finite trusted-host wallet](docs/PROTOCOL5_WALLET_CONTINUITY.md) adds recipient-key payments, exact
lost-return recovery, selected-output capsules, authenticated H+1 reconciliation
and one-attempt delivery. These later controller-only additions preserve the
existing circuit/profile/KAT/worker and historical qualification identities.
They do not establish production custody, privacy, public deployment or real-funds safety.

## Private shared allowance proof milestone

The [isolated authority lab](docs/PRIVATE_AUTHORITY_PROOF_LAB.md) now generates and verifies actual Halo2
proofs for hidden shared allowance successors and ordered revocation. Its trusted
local context is outside consensus; it has no payment or wallet caller. The
separate atomic treasury component below adds local value-note composition;
authenticated validator authority and wallet integration remain required.

## Atomic private treasury payment component

The [separately versioned component](docs/ATOMIC_PRIVATE_TREASURY.md) links a conserved private note
payment with exact shared allowance debits and durable local obligation retention.
It preserves the earlier runtime contracts. Local execution and real proofs do
not establish validator consensus, production privacy/custody or launch readiness.

## Protocol 6 atomic treasury validator development

The separately pinned [P6 treasury protocol](docs/PROTOCOL6_TREASURY.md) promotes the frozen combined payment/allowance relation into a finite four-validator development application with atomic recovery and signed AS-OF full-state evidence. Existing protocols remain separate. Static genesis grants, one-host validators, bounded trusted-host verification, no owner lifecycle, wallet integration or merchant redemption are explicit limits. The [clean-source real-engine receipt](evidence/protocol6-treasury/20261004/engine-qualified-01.json) passed all 18 checks; [review and validation scope](evidence/protocol6-treasury/20261004/AI_REVIEW.md) records the failures, repairs and remaining gates.

## Certified treasury controller and release gates

The [P6 certified journal](docs/PROTOCOL6_CERTIFIED_WALLET.md) retains exact prepared payments, claims one delivery attempt before loopback I/O and records only independently replayed signed inclusion. The [deployment readiness map](docs/DEPLOYMENT_READINESS.md) separates development qualification from owner lifecycle, merchant/custody, scale, independent operators and public-launch gates. Exact wallet-engine evidence is registered after its clean-source run; the original P6 receipt remains scoped to its captured runtime.

The certified treasury wallet [registered receipt](evidence/protocol6-wallet/20261005/wallet-qualified-01.json) passed19 actual engine/recovery checks. The [deployment readiness map](docs/DEPLOYMENT_READINESS.md) keeps public-launch and production custody gates explicit.

The [P7 owner treasury](docs/PROTOCOL7_OWNER_TREASURY.md) has registered fresh-domain rotation, reactivation and enrollment evidence:17 checks per four-validator run. Exact owner/payment client recovery and public-release gates remain separately assessed.

The [P7 encrypted restricted CHANGE vault](docs/PROTOCOL7_VAULT.md) now has a [registered24-check actual four-validator receipt](evidence/protocol7-vault/20261005/vault-qualified-02.json): import, encrypted reopen, real command re-spend, exact lost-return recovery, and spent/revoked-grant refusal. [Custody commands](docs/PROTOCOL7_CUSTODY_CLI.md) use protected stdin and an external key. This remains finite trusted-host development custody; merchant redemption, discovery, rollback protection and production privacy are separate gates.

## P8 authenticated node recovery

The separate [P8 recovery store/server](docs/PROTOCOL8_RECOVERY.md) now has a
[22-check actual-engine receipt](evidence/protocol8-recovery/20261006/state-sync-04.json):
a fresh nonvalidator imports replayed recipient state through CometBFT's light
client, recovers a lost final snapshot reply, rejoins, executes a genuine wallet
spend and survives a same-store restart. Historical engine responses remain
explicitly absent; only real post-origin execution is retained. This is finite
one-host synthetic development evidence. Independent operators, signer recovery,
production privacy/custody, scale/economics and public launch remain gates.

## Protected P8 application workflow

The [P8 operator CLI](docs/PROTOCOL8_OPERATOR.md) now has a
[fresh actual caller receipt](evidence/protocol8-operator/20261006/operator-02.json):
five pinned private workspaces, read-only configuration diagnosis, foreground
application serving and native audit of stopped stores. Eleven operator checks
passed alongside the unchanged 22-check real recovery/recipient-payment journey.
It provisions no engine, chooses no trust, generates no keys and repairs no store.
Independent operators, signer recovery, production custody/privacy and public
launch remain separate gates.

## Protected P8 wallet commands

The [local wallet CLI](docs/PROTOCOL8_WALLET_CLI.md) now has a
[fresh actual caller receipt](evidence/protocol8-wallet-cli/20261006/wallet-cli-03.json):
four encrypted wallets, authenticated receive/import, durable preparation before
proving, exact wire export, one-attempt marking, lost-response reconciliation and
explicit private delivery. Thirteen caller checks passed alongside the unchanged
22-check four-validator wallet journey. All 57 CLI invocations were reaped.
The command requires external custody inputs and sends no transaction. Production
key management, network freshness, independent hosts and public launch remain gates.

## Local P8 payment caller

The [payment caller](docs/PROTOCOL8_PAYMENT_CALLER.md) now submits an exact
retained wallet wire once to an explicit loopback node, keeps a lost reply
unknown, and reconciles through signed state. Its [fresh actual receipt](evidence/protocol8-payment-caller/20261006/payment-02.json)
passed 13 caller checks and the unchanged 22-check four-validator wallet journey.
The real node admitted one exact request; the caller received no reply and later
recovered exact execution without resubmission. Public launch remains a separate gate.

## Local P8 payment console

The [terminal console](docs/PROTOCOL8_PAYMENT_CONSOLE.md) presents protected original
intent, requires confirmation of the exact transaction and wire hash, and keeps
unknown submission, admission and signed execution distinct. Its
[fresh actual receipt](evidence/protocol8-payment-console/20261006/console-05.json)
passed 12 console, 13 payment and 22 actual wallet checks. It adds no automatic
retry or public service; production custody and independent operators remain separate gates.

The additive [local wallet journey](docs/PROTOCOL8_WALLET_JOURNEY.md) brings
observation, receive/import, separately confirmed native preparation, exact export
and private delivery into the console. Wallet/core pins are unchanged from PR83.
Its new console source is pending a fresh actual journey qualification; no earlier
receipt is transferred to it.
