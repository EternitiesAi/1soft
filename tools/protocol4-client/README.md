# 1soft P4 verified read client

29 September 2026. Additive to draft PR #28 at
`b73a88ca53666972ae2c8ce35fd9edb7ac0cb41c`, tree
`123e5bfc57d42ee31736969f61aa5a6d32482832`.

This is a separate client for reading recorded P4 accounts and positive payment
receipts across authorized validator changes. It is not a signing wallet, public
explorer, compact receipt-archive format, new node implementation or activated
upgrade. It does not change existing node, wallet, explorer or archive files.

## What is verified

The caller supplies the exact engine genesis and a separately chosen policy pinning
its SHA-256 and one signed header's hash/height/time. The evidence cannot supply its
own policy. The client verifies every signed header from height 1 through H+1,
including both validator-set commitments, the complete preceding block identity,
strictly increasing times, expected protocol versions, every signature slot and
strictly more than two-thirds committing power. A newly supplied roster is trusted
only when the preceding verified header committed it.

Each transaction list at heights 1 through H must match its signed block data
root. The client re-executes the complete monetary and administrative input history
using PR #28's pinned P4 implementation. Each intermediate composite AppHash must
match signed H+1; each current/next roster must match the authorization schedule.
The final balances, grants, budgets, receipts and registry must equal the supplied
checkpoint exactly. Consensus signatures cannot substitute for valid administrative
approval, and administrative approval cannot authorize a spend.

The client's runtime reuses the exact node rules and low-level dynamic-header
signature primitive; it is not an independent implementation of those rules. This
can detect inconsistent evidence but does not independently audit the protocol.
The normal legacy static TrustAnchor is not called with P4 or weakened to accept it.

Snapshot transaction history is only replay input. A format-2 snapshot alone is
not accepted as client evidence because it lacks independently signed block
identities and inclusion proofs. Recomputed ABCI outputs are not described as
observed engine request/response bytes. Header H+1 anchors state H; the client does
not invent executed payments at H+1.

## Account and receipt APIs

`verify_evidence`, `verify_account` and `verify_receipt` accept original evidence,
not an untrusted precomputed display report. `P4ReadStore.account` and `.receipt`
first reverify their saved evidence. Balances are decimal strings of native atomic
units. They exclude pending signed wallet commitments and are NOT spendable-balance
or approval calculations. No dollar price, peg, reserves or external settlement is
implied.

A positive receipt binds the selected payer, exact canonical signed transaction,
its included block, successful native execution and immutable receipt record. A
repeat included but rejected transaction is not a second execution receipt. A
missing record returns `unavailable`, never `unpaid`, `absent`, or permission to
retry. This intentionally does not offer absence-based wallet-hold retirement.

## Durable read observations

The private SQLite read store is separate from the node, wallet, dispatcher and
receipt archive. It will not initialize over an existing or unknown database.
Each observation keeps its complete evidence and parent digest. Updates require
the exact reviewed current tip; another writer's progress makes that review stale.
Rollback, changed prior transaction history and conflicting accepted block identities
are refused. An alternate valid quorum-signature subset for the same blocks is not
called a fork; existing stored bytes remain unchanged.

Insertion is atomic. A failed import leaves the earlier observation; a completed
import survives process interruption. Evidence at older heights remains exportable
under the same still-valid policy. Reads recheck cryptographic evidence and state
rather than trusting a materialized balance. Capacity exhaustion refuses rather
than evicting records. These are trusted-host filesystem checks, not protection
against a malicious OS, deleted records or rollback of an entire workspace.

The original anchor's fixed trust deadline is checked on reads and immediately
before writes, including no-op imports. Later headers do not renew it. The saved
clock observation cannot move backward inside this store. After expiry, existing
bytes are retained, but this API refuses to requalify or export them as currently
verified. The maximum 31-day policy interval is only a development limit, not a
recommended secure trust period or an economic/unbonding design.

## Commands

Apply the additive patch to the exact published PR #28 checkout, with its pinned
Python dependencies already installed. From the repository root:

```sh
python tools/protocol4-client/tools/verify.py --native-root .
export PYTHONPATH="$PWD/src:$PWD/tools/validator-transition/src"

python tools/protocol4-client/scripts/p4_read.py \
  --genesis /private/engine-genesis.json --policy /private/read-policy.json \
  init --store /private/p4-read.sqlite

python tools/protocol4-client/scripts/p4_read.py \
  --genesis /private/engine-genesis.json --policy /private/read-policy.json \
  import --store /private/p4-read.sqlite --expected-tip empty \
  --evidence /private/complete-signed-evidence.json

python tools/protocol4-client/scripts/p4_read.py \
  --genesis /private/engine-genesis.json --policy /private/read-policy.json \
  account --store /private/p4-read.sqlite --account EXACT_NATIVE_ACCOUNT

python tools/protocol4-client/scripts/p4_read.py \
  --genesis /private/engine-genesis.json --policy /private/read-policy.json \
  receipt --store /private/p4-read.sqlite --payer EXACT_NATIVE_ACCOUNT \
  --transaction /private/exact-signed-payment.json
```

`verify` checks an evidence file without creating a store. `inspect` reports the
verified checkpoint. `export --evidence-id DIGEST --output NEW.json` exports a
selected retained observation without overwriting an existing file. A later import
requires the current evidence digest instead of `empty`. There are no `sign`,
`send`, `renew`, wallet-unlock or administrative-execution commands.

The external policy has exactly these fields:

```json
{
  "schema": 1,
  "format": "1soft/protocol4-read-policy/v1",
  "genesis_sha256": "INDEPENDENTLY_PINNED_ENGINE_GENESIS_SHA256",
  "anchor_height": 1,
  "anchor_hash": "INDEPENDENTLY_PINNED_HEADER_SHA256",
  "anchor_time": "EXACT_ANCHOR_HEADER_UTC_TIME",
  "trust_period_seconds": 3600,
  "max_clock_drift_seconds": 5,
  "expected_block_version": 11
}
```

These placeholders must be replaced using an independently trusted development
checkpoint. The example interval is not a security recommendation. A peer that
provides both the evidence and its own trust root is not independent trust.

## Bounded local RPC collection

`sync --store FILE --expected-tip empty-or-digest --endpoint http://127.0.0.1:PORT/`
collects and imports a checkpoint from an explicitly selected local development
node. It captures `/state` once, waits at most eight seconds and 33 attempts for
only that state's signed H+1, then fetches each earlier block and commit. The
read worker derives validator rosters from replay of the pinned registry, not
an arbitrary RPC roster. The receiving store independently verifies the entire
returned proof again.

Only `abci_query`, `commit` and `block` requests are possible. The existing strict
HTTP reader rejects hostnames, public addresses, TLS URLs, redirects, compression
and ambiguous framing. No DNS, proxies, automatic polling or payment submission.
A fresh child explicitly resolves the already-imported native checkout, even with
PYTHONPATH cleared; network bytes cannot choose a module path.

This RPC profile supports heights 1 through 64, at most 162 requests, 4 MiB captured
state and a 45-second process deadline. The final header must be within 300 seconds
of the local clock, allowing only the configured small future drift. Any failure
leaves the current read tip unchanged. A successful recent read still does not
prove globally latest state. Longer histories require a separately assembled,
complete signed evidence file; the client never silently resets, skips or renews.

Offline evidence supports all existing P4 development heights through 512, at most
16 MiB per document. The read store retains at most 32 observations and 64 MiB of
payload. These are logical bounds, not total database-size or production scaling
claims. Each observation replays full history, deliberately favoring verification
over index efficiency in this development slice.

## Demo and remaining work

```sh
python tools/protocol4-client/scripts/demo.py --output /private/new-p4-read-demo
```

The demo executes actual local P4 transactions with public disposable signing seeds
and synthetic committee signatures. It saves/reopens at queued, emitted and active
transition heights, verifies a second full-roster replacement, and checks receipts
before and after both changes after the source application has closed. It exports
no private keys or databases. Do not put funds in fixture accounts.

The next real-engine acceptance should feed actual P4 headers/blocks into this
same collector, re-open its read store, compare accounts and exact receipts with
node evidence, and preserve negative cases. Current tests use a local fixture HTTP
server, not a CometBFT process. A production P4 signing/reservation wallet, dedicated
explorer integration, receipt-capsule archive, real-engine P4 state sync/Commit crash,
independent operators, security review, governance recovery, custody and economics
remain separate. Nothing here changes P1-P3 rules or their P4 rejection gates.
