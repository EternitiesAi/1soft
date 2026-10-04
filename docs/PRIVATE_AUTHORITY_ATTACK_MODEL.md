# Private authority attack model

`src/private_authority_attack_model.py` is an executable transparent model of
the shared-parent transition selected in
[`PRIVATE_ECONOMIC_AUTHORITY_DIRECTION.md`](PRIVATE_ECONOMIC_AUTHORITY_DIRECTION.md).
It pressure-tests the accounting and failure semantics that a future shielded
successor must preserve. It does not implement shielded state, a proving
system, consensus, a light client, authenticated non-inclusion, or production
custody.

## Decisive scenario

The fixture starts with one mission parent capped at 10 units and two delegated
grants capped at 8 units each. Both agents independently authorize a purchase
of 4 units plus the exact 2-unit native fee. Each 6-unit intent fits its grant,
but the two grants overlap against one parent; they are not separate escrows.

Both intents bind the exact chain and genesis, asset, parent and grant fragment
versions and commitments, current authority epoch, current transparent
nullifiers, payment, fee, recipient, validity window, output commitment, and
proposed parent and grant successors. Ed25519 authorization covers the complete
canonical body. Preparation records the original envelope in a private local
SQLite journal before returning it and does not mutate the committed model.

Execution consumes the current parent and selected grant fragments in one
SQLite transaction. The accepted successor has parent spent 6 and remaining 4.
The other pre-authorized intent is stale under either submission order. Exact
replay of the accepted envelope is idempotent. Two independent database
connections racing the copied parent also produce exactly one commit and one
rejection.

The losing journal records an untrusted failure message without releasing the
obligation. Its pending decision survives restart. A later revocation advances
the authority epoch, consumes the current transparent fragments, preserves
historical spend, and rejects pre-revocation intents.

## Executable invariants

The model checks these rules inside every committed transition:

- parent spend equals the sum of linked grant spend;
- parent spend equals the sum of committed fee-inclusive debits;
- parent remaining is `cap - spent`, and neither parent nor grant can exceed
  its integer cap;
- one accepted delegated transition consumes exactly one parent nullifier and
  one selected grant nullifier;
- parent and grant authority epochs remain equal;
- revocation never resets counters or recreates an active historical fragment;
- one committed intent has one receipt, while local failure alone never changes
  a pending obligation to committed or released.

The tests mutate payment, fee, recipient, epoch, current fragment nullifiers,
and successor commitments. They also cover both inclusion orders, concurrent
writers, exact replay, restart, revocation between authorization and execution,
injected database aborts after partial internal work, a deterministic randomized
sequence checked against an independent integer oracle, and a reduced receipt
projection.

## Receipt boundary

`1soft/transparent-authority-scoped-receipt/v1` opens only caller-selected
payment fields and omits owner, grant, recipient, keys, and fragment nullifiers.
Its verifier compares the projection with the exact locally retained execution
and a caller-supplied trusted state root. That is a bounded local semantic check,
not a portable payment proof. The model does not authenticate the supplied root
or provide an inclusion path from an independent consensus checkpoint.

The browser-oriented
[`minimal delivery receipt`](MINIMAL_DELIVERY_RECEIPT.md) is a separate format.
It reduces application-level disclosure for resource delivery and is not derived
from this authority model.

## Run

From an environment containing the pinned repository dependencies:

```sh
PYTHONPATH=src python -m unittest discover -s tests -p 'test_private_authority_attack_model.py' -v
```

Passing this suite establishes only the tested transparent transition semantics.
It does not establish hidden recipient membership, secret nullifier derivation,
zero-knowledge soundness, witness privacy, network anonymity, consensus safety,
cross-device coordination, or production key security. Those remain explicit
gates before any private-payment or mainnet claim.
