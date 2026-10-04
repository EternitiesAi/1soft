# Authenticated obligation reconciliation

`src/authenticated_reconciliation.py` verifies one local native wire against one
compact SMT witness, one signed header and a separately pinned static-validator
trust anchor. It records **authenticated audit evidence** in a local SQLite table.
Recording that evidence does not change a supported wallet's reservation state.

## Classification and authentication

The pure `classify_authenticated_receipt` implementation lives in
`src/wallet_obligations.py` and is re-exported by
`src/authenticated_reconciliation.py`. The root wallet inventory and compact-proof
audit wrapper share these receipt checks. It returns one of three values:

- `included`: the receipt matches the exact local signed envelope, transaction ID
  and expected signer. Envelope binding compares canonical bytes, so Python
  boolean/integer aliases cannot match another signed body. Its parsed record is
  an object; its sequence and previous digest agree with the authenticated row;
  its record digest matches; and its
  integer execution height is at least one, at most `valid_until`, and no later
  than the authenticated checkpoint.
- `absent_after_expiry`: the receipt key is absent and the authenticated state
  height is **strictly greater** than the signed `valid_until` height.
- `pending`: the receipt key is absent before or exactly at `valid_until`.

The classifier performs no proof verification, signature validation, database
writes or wallet changes. Its caller must authenticate the state under the
expected genesis and verify the local envelope's signatures first. A wallet can
pass its signing checkpoint plus one as `minimum_receipt_height`, so a receipt
cannot predate the local signing decision. Invalid or inconsistent receipts raise
an error rather than being reclassified as absence.

`reconcile_obligation` supplies the compact-proof boundary around this classifier.
It selects the receipt key from the caller's exact canonical wire and pinned
chain/genesis, authenticates the requested proof and next signed header, and only
then consumes the authenticated genesis protocol version to verify the native
signature. The underlying compact verifier still enforces the exact requested
query set, genesis binding, height-bound application root and quorum certificate.
A forged local wire fails even when there is a valid authenticated absence proof
for its transaction ID.

The wrapper records only `included` or `absent_after_expiry`. It rejects `pending`
without creating a journal table or row. An included receipt remains inclusion
evidence if a later checkpoint is past the transaction's expiry; expiry does not
erase historical execution.

A missing row from an ordinary endpoint, provider status, wall clock, caller's
self-asserted current height, or unverified witness is never sufficient evidence.

## Durable audit journal

The wrapper requires a connection with no open transaction. It rejects an already
open transaction before any journal mutation and preserves the caller's pending
changes. It then owns one `BEGIN IMMEDIATE` transaction containing schema creation
or validation, existing-result comparison and any insertion. SQLite failure rolls
back the schema and row changes together. Transaction closure uses explicit SQL
COMMIT or ROLLBACK, including Python 3.12+ connections configured with
autocommit=True. Connection.commit() and Connection.rollback() have no effect in
that mode; they cannot close the explicit BEGIN. A failed operation rolls back
only if its owned transaction remains open, preserving the original error when
SQLite has already ended it or BEGIN itself failed.

An existing table must have the expected column order, SQLite types, nullability
and transaction-ID primary key. `CREATE TABLE IF NOT EXISTS` alone is not schema
validation. An incompatible schema is rejected without migration or repair.

A durable row binds transaction ID, neutral classification, authenticated state
height, signed checkpoint hash and a digest of that evidence. Exact replay returns
`recorded: true, replayed: true` and retains one row across connection close/reopen.
A first successful recording returns `replayed: false`. These flags describe the
audit journal write, not settlement or reservation release.

A different result for the same transaction ID fails closed and leaves the prior
row intact. This includes an otherwise valid newer authenticated checkpoint: the
journal deliberately retains exact evidence, with no implicit replacement or
checkpoint-advancement policy. The original exact evidence remains replayable.

## Wallet integration and limits

The supported root `CertifiedWallet` now consumes the shared classifier through
`wallet_obligations.inventory`. `CertifiedWallet.sync` first authenticates the
full-state witness, checks its trust policy and checkpoint ancestry, and restores
the semantically validated ledger. Inventory verifies each original local signing
decision with `checked_decision`, selects the complete five-column receipt row,
and passes the exact stored envelope and signer to the classifier. It sets
`minimum_receipt_height` to the decision's signing state height plus one.

Inventory maps `included`, `absent_after_expiry` and `pending` to the existing
`recorded`, `expired_absent` and `pending` statuses. Incoming-key consent remains
`consent_only`. Account, grant and shared-budget holds still derive from all
immutable local decisions. `CertifiedWallet.sync` owns the transaction that records
the authenticated checkpoint and reconciles those holds; the pure classifier
creates no table and cannot commit or roll back the caller's changes.

The same inventory checks serve root signing reviews, pending inspection, account
views and `DecisionDelivery.reconcile`. The standalone compact audit table is not
a reservation authority and is not added to a financial wallet journal. This
integration does not implement compact-only wallet synchronization: root wallet
reconciliation still requires its authenticated full-state witness.

Protocol 4 keeps its separate complete-history and changing-validator verification
path. Its unresolved signed holds still require an exact positive execution
receipt; expiry or revocation alone does not retire them. The root classifier does
not change that Protocol 4 policy or broaden the static compact verifier's trust.

This module does not establish freshness, honest behavior by a dishonest quorum,
liveness, cross-wallet coordination, shielded privacy or a production light
client. Tests use real local state-machine commits, SMT proofs and cryptographic
signatures under disposable static-validator fixtures. They are not live
CometBFT consensus or production-custody evidence.

## Focused verification

Run the reconciliation cases independently of the compact-state tests:

```sh
PYTHONPATH=src:tests .venv/bin/python -m unittest -v test_authenticated_reconciliation
PYTHONPATH=src:tests .venv/bin/python -m unittest -v test_compact_state
PYTHONPATH=src:tests .venv/bin/python -m unittest -v test_wallet_obligations test_certified_wallet
```

The reconciliation test class reuses only the compact application's fixture
methods, without inheriting its test methods. The focused cases cover inclusion
before/at expiry, historical inclusion, absence strictly after expiry, holds
before/at expiry, forged local signatures despite proven absence, unrelated proof
keys, unauthenticated leaf mutation, authenticated bad digest/signer/envelope/ID,
receipt record shape/sequence/previous/height, minimum decision height, on-disk
replay after reopen, open-transaction rejection before schema creation, caller
transaction preservation, incompatible schemas, write-failure rollback and clean
reopen/retry, explicit transaction closure and reopen durability under
autocommit=True, and conflicting durable checkpoint evidence.

Durability cases create their SQLite journals in `TemporaryDirectory`; they do
not share a fixed `/tmp` database or remove another test's table. The injected
SQLite failure happens after a real row insertion and before commit, so the test
checks rollback of actual changes rather than a mocked successful write.
