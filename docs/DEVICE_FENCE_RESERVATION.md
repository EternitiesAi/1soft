# Shared device fencing reservation

This development component coordinates **P4 journal clones that explicitly use
`FencedApproval` and the same live local SQLite registry**. It gives one journal
identity an active device key and a monotonic device epoch. It adds no network
service, native signing domain, transaction field, consensus rule, production
custody system, or default signing-path change.

## Authority and identity

`wallet_identity(wallet)` derives the registry namespace from the original P4
journal's validated random wallet ID and the exact pinned genesis bytes. Copies
of that journal share the namespace. A separately created journal has another
identity even when it controls the same payer. Enrollment must use this helper,
rather than a filename or the bare journal ID. This is trusted local enrollment,
not a proof that the device key owns a native account.

The registry authorizes a **device coordination key**; the existing encrypted
native owner/grant vault still supplies the transaction signature. Device rotation
does not rotate that native key. `rotation_message(..., epoch=current_epoch)`
binds the wallet, both device labels, replacement public key, current epoch, and
successor epoch. Both the current and incoming device keys must sign those exact
bytes. `rotate(..., epoch=current_epoch)` compares that epoch inside its writer
transaction. Retired device labels cannot be reused. Epochs are bounded exact
integers and cannot wrap or accept booleans.

A reservation signs `reservation_message(...)`, including its action, wallet,
device, epoch, canonical payer/grant lane, native nonce, request ID, and frozen
body. `authority_lane(body)` derives the lane from the exact payer and explicit
owner-or-grant role; nonce is a separate key, and an owner role cannot alias a
grant named `owner`. A caller cannot invent another lane spelling for the same
body. Request IDs are wallet-wide: an exact repeat reports `already_reserved`;
changing any signed reservation field under that ID refuses. Two requests cannot
reserve the same wallet/lane/nonce, including after device rotation.

## Approval and interruption

`FencedApproval` freezes the review, checks its exact confirmation and current
wallet/genesis identity, and derives the same review through the existing wallet
before creating a reservation. The wallet revalidates its review again during
actual approval. Unsupported native key-rotation reviews are refused by this
transfer adapter.

Reservation COMMIT occurs **before vault access or native signing**. A second
registry writer transaction checks the device/epoch and reservation, then keeps
rotation serialized through `P4Wallet.approve`. Rotation that commits between
reservation and this signing guard prevents key access. A rotation that waits
behind an already-authorized approval takes effect after that approval completes.
The registry lock serializes other writers too; long signing operations can make
them hit the five-second SQLite timeout and fail closed.

A missing vault, bad password, stale wallet revision, process interruption, or
other failure after reservation leaves its lane/nonce reserved. The adapter
refuses an exact retry rather than treating idempotent reservation as permission
to sign twice. There is no release, delete, cancellation, or receipt-reconciliation
API in this registry. If the wallet has already committed a decision and the
later registry transaction or output fails, recover that decision's original
bytes from the wallet; do not repeat approval. A crash before wallet COMMIT can
leave a reservation without a wallet decision. Resolving that case requires a
separately qualified recovery design.

Use the adapter as a context manager or call `close()`. A successfully created
adapter owns its supplied wallet and closes it exactly once; it borrows the
caller-owned registry and leaves that registry open for other adapters. Closed
adapters and registries refuse approval.

## Storage boundary

Use an existing owner-only POSIX directory. The constructor creates a new 0600
database exclusively, or opens an existing recognized registry in read/write
mode. It refuses symlink parents, writable non-sticky ancestors, wrong ownership,
broad directory/file permissions, hardlinks, non-regular files, unsafe sidecars,
and an unrelated/changed database schema. It does not chmod or repair existing
files, create missing parent directories, or migrate the earlier experimental
unversioned registry. Do not replace an active registry to escape its holds.

The parent directory is pinned by an open directory descriptor; file creation
uses that descriptor and `O_NOFOLLOW`. Parent/database identities and sidecar
safety are checked before and after open and at transaction boundaries. SQLite
uses serialized `BEGIN IMMEDIATE` transactions, WAL, full synchronous mode, and
schema uniqueness constraints. Storage/busy/transaction failures become
`DeviceFenceError` (a `ValueError`) and never permit fallback signing. A failed
rollback closes the connection.

These checks are proportionate to trusted local coordination. They are not an
atomic secure-open SQLite VFS, hostile-host defense, protected key custody,
whole-registry rollback detection, power-loss certification, or a guarantee on
network filesystems. The registry owner or a privileged process can rewrite or
replace storage and bypass this control. Use separate connections per process;
do not share a SQLite connection across threads or fork it into workers.

## Explicit exclusions

Direct `P4Wallet.approve`, current wallet CLIs, raw signers, separately initialized
journals, independent registries, and restored/rolled-back registries are outside
this opt-in boundary. The integration suite deliberately demonstrates that direct
legacy approval still signs from a stale clone even after device rotation. An
already signed native transaction remains valid under its native rules; validators
do not inspect this device epoch or reservation digest.

This is not offline, global, cross-host, or chain-enforced fencing. It does not
combine account/budget holds across different clone journals or authenticate the
latest state of funds. Distinct grant lanes may still overcommit a shared budget
across copies; the existing shared financial journal remains the supported budget
accounting path. No claim of production readiness or independent security
qualification follows from these local tests.

## Reproduction

From the repository root, the delivery and custody sources are needed by
existing rotation and recovery regressions in the complete wallet suite:

```sh
export PYTHONPATH=tools/protocol4-wallet/src:tools/protocol4-wallet/tests:src:tools/validator-transition/src:tools/protocol4-client/src:tools/protocol4-client/tests:tools/protocol4-delivery/src:tools/protocol4-custody/src
.venv/bin/python -m unittest test_device_fence test_fenced_approval_integration -v
.venv/bin/python -m unittest discover -s tools/protocol4-wallet/tests -p 'test_*.py' -v
```

Focused regressions cover epoch-bound rotation/replay, request and lane binding,
real multi-process conflicting/idempotent reservations, rotation/signing ordering,
unsafe storage, database error/rollback/commit behavior, clone identity, adapter
lifecycle, pre-reservation review validation, fail-closed signer failure, recovery
after wallet commit, and the explicit direct-approval bypass. Native wallet tests
use disposable keys, the actual local P4 ledger, and synthetic committee headers;
they are not a live engine, public network, or real-funds exercise.
