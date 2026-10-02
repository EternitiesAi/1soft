# P4 journal custody and recovery

## Goal and chosen boundary

Dom authorized continuing from validator-turnover qualification into dependable
wallet custody/recovery. This first slice backs up the canonical P4 wallet and
its bound delivery journal together. Restore is a recovery archive, never a
second active wallet. It preserves original signed wires, shared holds, consumed
attempts, endpoint observations and positive execution evidence.

Copying only a live SQLite main file can miss WAL records. Reactivating a copied
wallet cannot establish that the backup is latest or that the old signer stopped.
Choose a complete logical snapshot under wallet then delivery writer locks, with
authenticated encryption and a distinct recovery archive application identity.

## Storage and verification

Capture all seven existing tables as canonical typed rows; preserve BLOB bytes
exactly. Audit with the existing P4 wallet and delivery rules at retained times.
No source lock may span password prompting, encryption or publishing files. CLI
prompts before opening the journals; capture releases locks before encryption. No
checkpoint, repair, migration, source-journal mutation or policy renewal.

Use only installed cryptography46.0.4: Scrypt(n=32768,r=8,p=1,length=32), random
32-byte salt, AES-256-GCM with a random12-byte nonce and a fixed canonical header
as associated data. Accept only those exact KDF/version/cipher parameters before
derivation. Passwords are16-1024 UTF-8 bytes. Unknown fields, duplicate JSON keys,
noncanonical encoding, oversize records and authentication failures refuse.
This is a versioned development format, not an audited interoperable standard.

Snapshot journal payload is bounded at7MiB; complete canonical plaintext at16MiB,
encrypted envelope at23MiB, restored archive at17MiB. A larger valid source wallet
refuses without eviction. Restore contains sensitive journal data in a private
owned0600 file under a0700 POSIX directory. It includes no private keys or vaults.

After decryption, externally selected original genesis and policy must match.
Reconstruct the original schemas only in memory and call their existing auditors.
Never persist an intermediate ordinary wallet/delivery DB. Publish a distinct
SQLite recovery archive only after complete verification, using an exclusive
temporary file, fsync, atomic no-overwrite publication and parent fsync.

## Public interface

`backup(delivery, output, password)` freezes and encrypts the complete pair.
`restore_backup(backup, output, genesis, policy, password)` authenticates, audits
and publishes one recovery-only archive. `RecoveryArchive(path, genesis, policy)`
offers `inspect()`, `recover(decision_id, payer=..., grant_id=...)` and
`export_receipt(decision_id, payer=..., grant_id=...)`.

Inspection differentiates wallet-reconciled receipts from receipts collected only
in delivery. The latter do not silently retire wallet holds. Expiry or a missing
receipt never releases an obligation. Original wire/receipt recovery remains
historical after policy expiry. No new proof import is added in this first slice.

No signing, dispatch, resend, rearm, cancellation, trust renewal or conversion to
an active wallet. Existing active wallet/delivery constructors must reject the
archive before accessing a key or transport. Status explicitly says old device
fencing/latestness/current authority are unestablished; all dispatch is disabled.

## Acceptance and exclusions

Use actual native execution and existing synthetic committee fixtures to exercise
100-unit shared holds, claim-without-response, collection-before-reconciliation,
wrong-role selection, expiry, exact source preservation, consistent concurrent
capture, wrong password, authenticated tampering, corrupt logical records, size
limits, path/sidecar aliases, output failure and active-constructor rejection.
Exercise CLI password prompts with a real PTY, and refuse nonterminal fallbacks.
These component tests do not establish independent operators, genuine CometBFT
consensus, power-loss or hostile-host protection.

Do not modify protocol1/2/3/P4 consensus bytes, prior source manifests, frozen
archives, dependencies or existing wallets. No Actions, paid/public compute,
downloads/installs, deployment/DNS/site changes, real funds/production keys,
other-project work, force-push or merge. Production key recovery, old-device
fencing, hardware custody and trusted renewal remain separate design gates.

Primary API references: [authenticated encryption](https://cryptography.io/en/46.0.4/hazmat/primitives/aead/)
and [Scrypt](https://cryptography.io/en/46.0.4/hazmat/primitives/key-derivation-functions/#scrypt).
