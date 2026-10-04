# Device-fence positive outcome recovery and product adoption

Date: 4 October 2026

## Decision

The shared device fence gains one monotonic terminal state:
`decision_committed`. It may be recorded only from an exact, reverified P4
wallet decision whose review matches the reservation and whose canonical signed
wire hashes to the stored outcome.

A reservation with no exact decision remains `reserved` and returns
`unknown_quarantined`. It continues consuming its wallet, authority lane, and
native nonce. There is no release, cancellation, expiry shortcut, negative
terminal state, or absence tombstone.

This conservative rule is required because the registry coordinates cloned P4
journals. The absence of a decision in one copy says nothing about another copy.
Releasing a lane from local absence could permit a second signed transaction
with the same native nonce while another clone retains the first.

## State and evidence

The only transition is:

```text
reserved -- exact positive wallet decision --> decision_committed
```

The terminal row binds the original reservation digest, product request ID,
native decision ID, and SHA-256 of the canonical signed wire. The active device
authorizes the outcome message at its current epoch. A successor device may
record a decision proven by the original wallet journal after a valid rotation;
rotation never authorizes re-signing the old request.

The registry also retains one append-only event for the positive transition.
That event improves local audit and idempotency. It does not detect or defeat a
privileged owner's whole-file rollback, copied registry, or hostile storage.

## Interruption and recovery

Reservation commits before vault access. The registry writer remains serialized
through native wallet approval and positive outcome recording.

- If neither wallet nor registry commits, no positive outcome exists.
- If the wallet commits and the registry outcome commits, the result is terminal
  and exact replay is idempotent.
- If the wallet commits but registry commit or response fails, reconciliation
  opens the supplied wallet journal read-only, reauthenticates the stored
  decision, checks the original review and reservation, and records the same
  wire hash. It never opens a vault, signs, submits, or changes a hold.
- If the supplied journal lacks the exact decision, reconciliation reports
  `unknown_quarantined` and leaves the reservation unchanged.
- If the registry records a decision but the supplied clone lacks its exact
  bytes, reconciliation reports `committed_elsewhere`; it does not invent or
  export a transaction.

An exact v1 registry may migrate transactionally to v2. Every reservation is
preserved as reserved. Unknown, altered, partially migrated, or unrelated
schemas remain refused.

## Product path

`PlatformService` accepts an optional approval factory. The default remains the
existing direct P4 wallet path. When explicitly supplied, the factory must wrap
the exact wallet object owned by the service.

The canonical browser and private-payment callers already converge on
`PlatformService.approve`. That method keeps its existing order:

1. validate the role, frozen review, and confirmation;
2. rederive the current wallet review;
3. durably bind the RequestBook entry;
4. reserve through the injected fence;
5. open the existing native vault and approve;
6. record the positive fence outcome before returning.

The product request ID is the registry request identity. The review confirmation
remains the native decision ID. No device key, native private key, password,
registry control, or new caller-selected field is added to the browser API.

When the native decision already exists, the opt-in path reconciles the fence
before returning the original retained-decision result. A verified decision that
predates fence activation and has no reservation returns `unfenced_decision`;
its original bytes remain recoverable, but no registry authority or event is
created. The opt-in response exposes this status. Unknown or conflicting results
for an existing fenced reservation fail closed. The adapter borrows the platform
wallet and cannot close or replace it.

## Operator boundary

Enrollment, device-key custody, and rotation are explicit trusted-host operator
operations. Normal product startup does not enroll, rotate, regenerate keys, or
repair a registry. Native owner-key rotation remains a separate protocol.

Direct `P4Wallet.approve`, existing wallet CLIs, raw signers, independent
registries, copied or rolled-back registries, and callers that omit the approval
factory remain outside this opt-in fence. The registry outcome is not embedded
in the native transaction and validators do not enforce it.

This phase establishes local positive-decision reconciliation and one actual
product composition seam. It does not establish cross-host or global
coordination, chain-enforced device epochs, hardware custody, rollback
resistance, production security, public deployment, real funds, or independent
operator qualification.
