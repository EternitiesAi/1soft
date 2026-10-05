# P7 restricted change-note custody

This additive developer custody layer imports only a restricted CHANGE output
from an exact certified P7 payment, stores its opening encrypted, and constructs
a new payment through the canonical certified journal. The frozen profile,
parameters, verifier key, consensus bridge and P1-P6 formats are unchanged.

## What the vault holds

Build owner-note-controller alongside owner-payment-prover with the tracked
lockfile, offline, release mode and two build jobs. Create a NoteController with
the measured executable hash, external canonical genesis and the journal's
actual Worker. ChangeVault requires that controller, a caller-held random
32-byte AES key, an explicit opaque vault ID and a private owner directory.
The key must be supplied again on every open. It is never stored in the vault.

import_change(journal, transaction_id, opening) requires the journal's exact
quorum-certified execution record. The opening has exactly agent_secret, value,
expiry, note_secret and blind. Native derivation checks the original restricted
commitment, selected key, authenticated note set/path and nullifier. Domain600
restricted CHANGE is distinct from domain604 merchant output. This API cannot
turn a merchant output into a restricted input.

AES-GCM encrypts canonical origin/opening records and immutable staged requests.
Authenticated associated data pins format, vault ID, genesis/bootstrap, profile,
parameters, verifier, worker, KAT, controller and revision. Each update uses a
fresh nonce checked against the encrypted history. Files are owner-only0600 in
an owner-only0700 directory; symlinks, hard links and unexpected plaintext
sidecars are refused. Ciphertext is written to an exclusive private stage,
fsynced and atomically published; directory changes are fsynced. Failed or
uncertain writes are not treated as successful preparations.

## Permission, preparation and recovery

The journal remains the sole authority. The vault does not maintain its own
spent flags. A spend checks the current certified history for the exact origin,
active grant/generation/key, owner epoch, treasury epoch, authenticated note
position/root, expiry, unspent nullifier and existing journal holds. An imported
owner sequence is provenance, not note identity. A later permitted owner command
can advance that sequence without relabeling an otherwise valid note; the new
proof must use the current sequence and authority context.

prepare_payment requires explicit current parent/grant openings, amount, validity
window and payment request. The parent list is cap, spent, version, blind; the
grant list is cap, spent, version, blind, expiry, recipient. Both contain
canonical field hex values. Input-note openings come from the encrypted vault;
new output secrets/blinds come from the operating system random source.
The native controller validates the resulting full canonical request. The vault
durably encrypts that request before journal.prepare performs its final atomic
current-state check, actual proof generation, verification and retention.

On a lost return, recover_prepared returns only the unique exact wire already
retained in the journal. It never proves again, submits, retries, clears a hold
or assumes an uncertain operation did nothing. A stage with no journal commit
is explicitly refused by recovery. An operator can separately re-evaluate the
original request through journal.prepare; this is not an automatic vault retry.
import_prepared_change retrieves the retained future opening only after the
journal authenticates the exact new execution certificate.

Inventory exposes note commitments and retained preparation request IDs. These
are immutable history, not spendable balance or authoritative pending status.
The encrypted format is bounded to16 records and8 retained preparations, with a
2MiB plaintext limit. P7's16-note tree with3 initial notes actually permits at
most6 payments because each payment appends two outputs. Capacity is deliberately
finite; no pruning or preparation deletion is inferred.

## Evidence and limits

The supplied actual-origin custody tests exercise real derivation/proving,
encrypted reopening, wrong-key/identity/ciphertext refusal, altered origins and
openings, unsafe storage, duplicate inputs, publication/nonce faults, lost local
return, and an actual child process exiting after the encrypted stage. Audited
state fault doubles for generation/epoch/nullifiers are explicitly labeled.

The [one-shot custody caller](PROTOCOL7_CUSTODY_CLI.md) exposes the same operations
with protected canonical stdin, fixed public diagnostics and exact recovery.
It has no delivery or retry operation.

The additive run_protocol7_vault.py gate uses a fresh four-validator CometBFT
network. It must import a real payment's CHANGE, certify an unrelated grant
revocation, re-spend that same note through the actual custody command using the
new owner sequence, recover the
exact retained wire after reopening, certify/import its new CHANGE, then refuse
a revoked active grant before proving. The checker independently replays exact
proofs, certified transitions, source and artifact identities and public origin
bindings. It checks canonical ciphertext and pins, without receiving a key or
independently decrypting the vault. Exported path metadata is informational;
the actual second proof verifies the authenticated input path.

This remains one trusted POSIX host and finite synthetic development funds.
Private material is ordinary process memory and protected stdin/ciphertext; no
secure erasure, hostile-host sandbox, rollback detector, cross-device fencing,
key recovery, recipient discovery, merchant redemption, production privacy or
public-launch claim is made. Restoring an old valid encrypted copy can lose
custody history. Backups must preserve the external key, exact vault identity,
the current ciphertext and canonical journal together under operator control.

At this source checkpoint the new actual validator gate is not yet qualified.
Its eventual registered receipt must state the exact clean executed revision.
