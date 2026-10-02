# P4 encrypted journal backup and historical recovery

This development component backs up the existing P4 wallet and its bound delivery
journal together. It preserves original signed transaction bytes, fee-inclusive
shared-budget holds, consumed delivery attempts, endpoint observations and retained
positive receipt evidence. No private signing keys are included.

Restore creates a **recovery-only archive**, with a different SQLite application
identity. It can show historical obligations and export the selected original
transaction or saved receipt. It cannot sign, send, reset an attempt, cancel a
hold, import a new proof, reconcile the wallet, activate a device or renew trust.
Both ordinary P4 wallet and delivery open paths refuse this archive.

## Why an old backup stays historical

A backup cannot prove that it contains the latest decisions, that the old device
has stopped signing, or that a transaction absent from the backup is unpaid.
Every inspection reports those limits. An attempt without a saved response stays
unresolved, and no restored decision is marked safe to resend. A delivery receipt
does not remove a wallet hold unless reconciliation was already recorded in the
backed-up wallet. Historical recovery continues after the original trust period
expires; it creates no current spending authority.

Replacing a signing device needs a separate reviewed fencing/key-rotation and
obligation reconciliation design. This feature does not provide key recovery or a
production custody certification. Keep the original canonical signing journal.

## Local commands

Use the existing installed Python dependencies on a trusted Linux/WSL host. The
source and output directory must meet the existing private ownership and mode
checks; use a directory owned by your UNIX user with mode `0700`. Outputs are new
exclusive files with mode `0600`. No directories or signing wallets are created
implicitly. Supply the original independently selected genesis and trust policy.
The endpoint must exactly match the existing delivery journal; these commands do
not call it.

```sh
python -B tools/protocol4-custody/scripts/p4_custody_cli.py \
  --genesis GENESIS.json --policy ORIGINAL_POLICY.json backup \
  --wallet PRIVATE/wallet.sqlite --delivery PRIVATE/delivery.sqlite \
  --endpoint http://127.0.0.1:26657/ --output PRIVATE/new-backup.json

python -B tools/protocol4-custody/scripts/p4_custody_cli.py \
  --genesis GENESIS.json --policy ORIGINAL_POLICY.json restore \
  --backup PRIVATE/new-backup.json --output PRIVATE/new-recovery.sqlite

python -B tools/protocol4-custody/scripts/p4_custody_cli.py \
  --genesis GENESIS.json --policy ORIGINAL_POLICY.json status \
  --archive PRIVATE/new-recovery.sqlite

python -B tools/protocol4-custody/scripts/p4_custody_cli.py \
  --genesis GENESIS.json --policy ORIGINAL_POLICY.json recover \
  --archive PRIVATE/new-recovery.sqlite --decision-id DECISION_ID \
  --payer PAYER_ID --grant GRANT_ID --output PRIVATE/original-wire.json
```

Omit `--grant` for an owner payment. Use `export-receipt` with the same selection
arguments to export an already retained positive proof. Missing proofs mean
unknown outcome. Exporting bytes is not submitting them or authorizing a retry.
The restore archive and exported evidence are **unencrypted private local files**;
only the backup envelope is encrypted. They contain payment and identity data.

Backup prompts twice for a passphrase; restore prompts once. Terminal input must
be non-echoing. There is no password argument, environment or pipe fallback, and
failure to suppress echo aborts before the fallback can read a password. The API
accepts 16–1024 UTF-8 passphrase bytes; use a strong independently stored passphrase.
Loss of that passphrase makes the encrypted backup unrecoverable.

## Format, consistency and publication

Capture acquires the existing wallet writer lock and then the delivery writer
lock. All seven tables are copied as typed logical rows under those locks; no WAL
file is copied. Prompts, encryption and output publication occur outside source
locks. All existing historical signature, state, budget, attempt and receipt
auditors run unchanged against fixed schemas reconstructed only in memory. Source
preservation means logical records; opening SQLite can affect its physical sidecars.

The version-1 envelope uses the installed cryptography library's Scrypt
(`n=32768, r=8, p=1, length=32`), a random 32-byte salt and AES-256-GCM with a random
12-byte nonce. The exact canonical header is authenticated. Unknown parameters,
noncanonical encoding and inflated KDF settings are refused before derivation.
No custom encryption primitive or authenticated compression is introduced.

Version 1 retains its 7 MiB complete journal BLOB limit, 16 MiB plaintext limit,
23 MiB encrypted envelope limit and 17 MiB archive limit. The default keeps this
format when the complete legacy representation fits, and selects version 2 for a
larger admitted wallet/delivery pair. `backup(..., format_version=1)` or CLI
`backup --format 1` explicitly requests the original bounds. `--format 2` requests
the new format; `--format auto` is the default. Current readers accept both
versions. Older readers accept only version 1; unknown versions are refused.

Version 2 preserves original BLOB bytes in a fixed typed row stream and encrypts
at most 1 MiB per AES-GCM frame. A fresh salt and nonce prefix, the frame position,
type and length, and an authenticated final manifest prevent frame mixing,
reordering, duplication and incomplete-file publication. Its limits are derived
from the unchanged current admission rules: at most 141 MiB+4096 journal BLOB
bytes, 834 rows and 1 MiB external genesis. Bounded metadata/framing yields a
152,329,575-byte plaintext stream, 152,340,868-byte encrypted file and
153,591,143-byte private recovery archive ceiling. No record is pruned or evicted.
The archive still has the recovery-only application ID and cannot activate a
wallet or delivery journal. See [the format contract](../../docs/CUSTODY_BACKUP_SCALE.md).

Encryption and row serialization use bounded buffers. Original historical audits
and frozen archive chunks still retain bounded journal/proof data in memory;
this is not a constant-RAM or maximum-capacity operational qualification.

All inputs and outputs must be disjoint from each other's full database/sidecar
families, including absent sidecar names. Symlinks, hardlinks and existing output
files or sidecars are refused. Complete output is flushed to an exclusive private
temporary file, linked into place without overwrite, and its directory synced.
Before-publication failure leaves no output. If directory sync fails after the
link, the command reports that complete output exists with **unconfirmed durability**;
inspect that file before retrying. Physical power-loss durability and a hostile
host that controls clocks, files or process memory remain unassessed.

## Verification

```sh
python -B tools/protocol4-custody/tools/verify.py --report NEW_REPORT.json
```

The verifier requires a clean committed source, records its entire current file
inventory before and after execution, and requires every discovered custody test
to succeed without skips or expected failures. Cases use real wallet, native
execution, signatures and journal rules with disposable synthetic committee keys.
They include a real local PTY CLI flow and a forced competing wallet writer. The
transport-loss case faults only the external submission boundary; no engine or
public service is executed. Its receipt proves this component's local behavior,
not consensus, independent-operator readiness or external security review.

The scale case builds an admitted pair above 7 MiB using actual native transfers,
increasing wallet observations, original approvals, a consumed unresolved claim
and a verified receipt. It checks every decoded table row, original wires and
receipt, continued holds and active-constructor refusal. Its disposable publicly
known fixture vaults and databases stay in a new private directory under
`/home/xnuonux`; package only the printed metadata receipt, never that directory.

Historical components' source manifests remain intact. Their byte seals identify
their own revisions; this verifier records the current candidate rather than
resealing a historical receipt.
