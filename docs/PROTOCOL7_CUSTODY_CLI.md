# P7 trusted-local custody commands

scripts/owner_treasury_custody.py is a one-shot developer caller for the
[restricted change vault](PROTOCOL7_VAULT.md). It creates or opens that encrypted
store and uses the existing canonical certified journal. It does not deliver
payments, discover notes, recover keys, export private data or start a service.

## Inputs and outputs

Provide these public arguments: journal, vault, genesis, worker, KAT and
controller paths; genesis, worker and controller SHA-256 pins; and vault ID.
Both prepare and prepare-retained require a prover path and SHA-256 pin. All paths/pins must
match the expected genesis and measured executables. The journal must already
exist as a private owner-only regular file; use the journal interface to
initialize it and authenticate observations. Vault creation is explicit and
refuses an existing target.

Provide exactly one canonical JSON object, at most8192 bytes, on a protected
stdin pipe. Close that pipe after the object; a newline is not part of the
canonical input. Every operation requires the key property containing the
external32-byte key as lowercase hex. No key/private opening is accepted in
arguments, an environment variable or a configuration file. Interactive terminal
input is refused. The caller must obtain its key from its own protected source
and must not persist the private request in a plaintext file or shell history.
Canonical encoding uses sorted keys, compact separators and no NaN; duplicate,
extra, missing or noncanonical input is refused.

| Operation | Additional stdin properties | Public result |
|---|---|---|
| create | None | Vault ID, revision0, empty immutable inventory |
| inventory | None | Imported commitments and retained preparation request IDs |
| import-change | txid, opening | Imported restricted commitment and revision |
| prepare | commitment, authority, amount, valid_until, request | Exact retained transaction ID, request ID, wire hash and attempt count |
| prepare-retained | source_txid, amount, valid_until, request | Exact retained transaction ID, request ID, wire hash and attempt count |
| recover-prepared | commitment | Unique exact retained transaction ID and wire hash |
| import-prepared | txid | Certified future-change commitment and revision |

Opening and authority layouts are defined in PROTOCOL7_VAULT.md.
The [retained authority path](PROTOCOL7_RETAINED_AUTHORITY.md) derives the next
authority only from an exact certified encrypted preparation with current
commitment continuity. It refuses missing stages or stale authority.
Private witness
construction belongs inside that controller; callers cannot supply a different
wire to recover-prepared or relabel a merchant output as restricted CHANGE.
Successful preparation is a local journal result. It is not delivery, settlement,
a spendable-balance report or authorization to retry.

The optional public --execution-receipt flag includes the measured note-controller
process records; either preparation operation includes the actual prover process record. These
contain operation, PID/start ticks, executable hash, exit code and byte counts,
without private requests or their hashes. The output remains bounded to32768
bytes. Normal output is one canonical JSON response plus a newline.

## Failure and interruption

Every failed command exits nonzero. Diagnostics contain only the fixed result
format, operation, status, failure class and reconciliation flag. Exception
strings, private inputs, ciphertext plaintext, openings and key material are
never echoed. SIGTERM enters normal bounded cleanup instead of abandoning
the owned private prover/controller child; Ctrl-C is also handled without an
exception-string diagnostic.

Once either preparation operation is entered, any unreturned outcome is conservatively labeled
prepare-not-returned with failure_class unknown and reconcile_required true.
This can include a validation failure before a stage exists: the flag means
inspect/reconcile before another action, not proof that a stage or journal row
was committed. A missing recovery result is not permission to regenerate or
resubmit. The vault retains its staged request, and recover-prepared only finds
the unique original journal wire. No operation automatically retries or clears
holds.

## Validation scope

The command tests include actual bounded/noncanonical input and argument
refusals, a real process interrupted during private input, a labeled wrapper
post-entry fault proving static unknown diagnostics, and actual supplied-origin
create/import/inventory/prove/recover/uncertified-import refusal. The full fresh
four-validator gate additionally performs the imported-note prepare and cold
recovery through this command, verifies the exact proof and certified execution,
and records public child lifecycles.

The same one trusted POSIX host, finite synthetic funds, external-key and
canonical-journal limits apply. This does not establish hostile-host protection,
rollback detection, cross-device coordination, key recovery, merchant redemption
or production privacy. No public/paid deployment or value-bearing network is
created by these commands.
