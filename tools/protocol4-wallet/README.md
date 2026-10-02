# 1soft P4 wallet — reviewed payments and explicit owner replacement

The current development wallet also has a separately reviewed
[owner key replacement workflow](../../../docs/P4_KEY_ROTATION.md). It requires
incoming-key consent and current-owner approval, reserves the fee in this same
payment journal, and pauses payer payments while rotation is unresolved.
Transfer and invoice review formats retain their original bytes. The new
`p4_rotation_cli.py` interface is explicit; ordinary `approve` remains transfer-only.
Custody archives remain recovery-only. The dated original transfer-wallet scope
below and its source manifest describe that historical delivery.

29 September 2026. Development-only add-on to PR #28 at
`b73a88ca53666972ae2c8ce35fd9edb7ac0cb41c` / tree
`123e5bfc57d42ee31736969f61aa5a6d32482832`, with the separately supplied,
unchanged `tools/protocol4-client` read verifier installed.

This is the first **transfer-only P4 wallet engine and command-line interface**.
It is not the consumer/mobile wallet, a custody service, an activated chain upgrade,
an administrative signer, a delivery client, or a production-security claim.
Existing native, node, static wallet, explorer and archive files are unchanged.

## One financial journal, not an optimistic balance cache

All agents using this supported workflow for the same funds share one P4 wallet
SQLite journal. It stores complete verified checkpoint observations and exact
signed transfer decisions. A separate P4 read store is not a signing journal.
The wallet will not initialize over, migrate or repair an existing file, node DB,
old CertifiedWallet DB or P4 read-store DB.

`prepare` verifies the original evidence and returns a transfer review. It does
not reserve or sign anything. The review binds the exact wallet identity, external
policy, checkpoint, existing decisions, account/registry epochs, role, signer,
nonce, recipient, amount, native fee and expiry. The review digest is also the
future durable decision ID.

`approve` opens the sole writer transaction, rechecks that exact review, replays
its source evidence, and accounts for every still-unresolved signed debit before
unlocking the existing encrypted Ed25519 PKCS8 vault. It then validates the signed
transfer against the pinned native rules and commits its original bytes and
reservation before returning. Key access uses the existing vault decoder; the
legacy offline signer's P4 rejection is not removed or called with broadened trust.
There is no arbitrary external signing callback or remotely selected module path.

Amounts are exact positive atomic native units; the reserved amount includes the
native fee. Different grant lanes share both account and parent-budget reservations.
Individual grant limits, allowed recipients, expiry, revocation and account epochs
are checked. An invalid agent grant never falls back to owner authority. An owner
transfer still respects all of that account's locally pending agent debits.

The public API supports native transfers only. It cannot sign registry proposals,
create/revoke grants, change keys, open accounts, issue money or change validators.
Those functions need separately reviewed workflows, not a generic raw-body escape
hatch through this interface.

## One unresolved transfer per owner/grant lane

This bounded first version allows at most one unresolved signed transfer for each
payer/owner-or-grant lane. Different agents can sign concurrently through the same
journal, but one agent cannot create a speculative nonce ladder. After the original
transfer is positively reconciled, that lane can sign again from new evidence.

This deliberately trades throughput for explicit recovery. In particular, an
expired or revoked transfer with no exact recorded receipt stays reserved, even
when it can no longer be validly submitted. There is no cancellation/delete/manual
release API and no inference that missing evidence means unpaid. A future
unexecuted-transfer retirement mechanism must be designed and qualified separately.
Do not work around that limitation by recreating the journal or using another key
path against the same funds.

## Evidence, turnover and financial authority

The P4 read verifier authenticates the complete signed header/validator sequence
and replays the monetary and administrative history. This wallet accepts original
evidence, not a caller-supplied verified-balance dictionary or an RPC success label.
Only an exact positive receipt for the original signed transaction and signer
removes it from pending calculations. Seeing it in another read store or receiving
an unverified network reply does not change this journal.

Validator turnover alone neither releases a hold nor renews the trust policy.
A pending transfer signed under the earlier roster can reconcile under a later
roster when its complete evidence validates. A new transfer can also be reviewed
and signed after turnover. Signature domains continue to bind the full P4 genesis.
Consensus or administrative approval is never substituted for the payer's signature.

Recorded balances, pending commitments and uncommitted headroom are displayed
separately. Headroom is not permission to spend and does not establish globally
latest funds. If activity through an unsupported external signer consumes account
funds or a shared budget, the imported state is retained, pending decisions stay
intact and a reservation deficit is displayed. New transfers that do not fit refuse.
This detects the observed consequence; it does not coordinate that external signer.

The external policy retains its original fixed expiry. New approval requires the
latest authenticated header to be at most 300 seconds old (with the policy's small
future-drift allowance). Checks repeat after decryption and before commit. Transfers
may expire at most 32 blocks after the verified application height and must not
outlive their grant/budget or P4's existing height-512 development boundary. None
of these numeric development bounds is a recommended production security policy.

## Recovery and interruption

`recover` exports an explicitly selected decision's original bytes, with an exact
payer and role check, without decrypting a key, contacting a node or re-signing.
It revalidates saved signing/evidence context at the recorded historical times.
Recovery remains available after external policy expiry, but that historical audit
cannot create a new approval, current balance, renewed trust or dispatch permission.
Other current wallet operations still refuse after expiry.

A process dying before database commit leaves no published signature or reservation
from this API. A process dying after commit leaves the exact original decision
recoverable. The CLI prints the durable ID before attempting the transaction-file
export; if that export fails, use `recover` into a new file. A partial output file
is not a reason to repeat approval. The review already contains the same ID when
terminal output is lost.

Imports and signatures share serialized SQLite writer transactions. Signed
observations and decisions are append-only; status is derived from reverified
receipts rather than a mutable paid flag. Conflicting reviewed revisions and
concurrent decisions cannot silently overwrite one another. These are local process
and database guarantees under a trusted host, not power-loss certification or
protection from malicious storage, clock control, whole-workspace rollback, copied
journals or another program reading raw private keys.

## Commands

Install both add-on directories into the exact PR28 checkout. Use Python with the
repository's existing pinned dependencies. Commands resolve their own checkout;
there is no dependency download and no need for a network endpoint.

```sh
python tools/protocol4-wallet/tools/verify.py --native-root . --report ../new-wallet-tests.json

python tools/protocol4-wallet/scripts/p4_wallet_cli.py \
  --genesis /private/engine-genesis.json --policy /private/p4-policy.json \
  --wallet /private/new-wallet.sqlite init

python tools/protocol4-wallet/scripts/p4_wallet_cli.py \
  --genesis /private/engine-genesis.json --policy /private/p4-policy.json \
  --wallet /private/new-wallet.sqlite sync \
  --evidence /private/original-signed-evidence.json --expected-revision empty

python tools/protocol4-wallet/scripts/p4_wallet_cli.py \
  --genesis /private/engine-genesis.json --policy /private/p4-policy.json \
  --wallet /private/new-wallet.sqlite prepare \
  --payer EXACT_ACCOUNT --to EXACT_RECIPIENT --units 58 \
  --valid-until REVIEWED_HEIGHT --grant raven --output /private/new-review.json

python tools/protocol4-wallet/scripts/p4_wallet_cli.py \
  --genesis /private/engine-genesis.json --policy /private/p4-policy.json \
  --wallet /private/new-wallet.sqlite approve \
  --review /private/new-review.json --confirmation EXACT_REVIEW_DIGEST \
  --vault /private/encrypted-raven.pem --output /private/new-signed-payment.json
```

Review the full document before using its digest as confirmation. The approve
command requires a local terminal and prompts for the vault password without echo.
There is no password argument, environment-variable password or echoed fallback.
No vault-generation command is added: the vault must already exist and match the
reviewed role. No hardware signer, mnemonic/backup standard or production key
lifecycle is implemented. The process necessarily holds a decrypted software key
while signing; secure memory erasure is not claimed.

`status` prints the verified account/budget/reservation view and exact revision for
a later `sync`. `recover --decision-id ID --payer ACCOUNT --grant ROLE --output NEW`
exports original canonical signed bytes. Omit `--grant` for the owner lane.
Outputs must be new files in private owned POSIX directories. An existing output
is never overwritten. Approval and current-status failures do not imply payment
failure or release a reservation.

## Runnable demonstration and scope

```sh
python tools/protocol4-wallet/scripts/demo.py --output /private/new-wallet-demo
```

The demo uses public disposable test keys, real P4 native execution and synthetic
committee signatures. It signs two grant payments totaling 100 with fees, refuses
an overcommit, reconciles the first, replaces every validator, preserves the second
hold, reconciles that payment, and signs/executes a new owner payment after turnover.
The harness feeds signed transactions into the local application; the wallet itself
never submits anything. It then closes the source, deletes temporary fixture vaults,
and recovers all original signatures after policy expiry. Public proof/transaction
files are exported; private keys and databases are not.

Limits: 32 stored full observations, 64 MiB observation payload, 256 signed decisions,
16 MiB individual evidence, the parent P4 height-512 development ceiling, and one
unresolved transfer per lane. Stored evidence is replayed; this is intentionally
bounded and not a production-throughput or total-disk guarantee.

Still required: real changing-validator engine acceptance of this new wallet,
separately verified decision delivery and unexecuted-obligation retirement,
account/grant/key lifecycle workflows, cross-device coordination, hardware/custody
review, consumer UI, independent security/host qualification and economic decisions.
A P4 state-sync/Commit crash check is not established by these client tests.
No Actions, paid compute, public endpoint, deployment, real funds, production keys,
DNS/site or Resident/Luna work is performed by this add-on.
