# Preserve and recover private payment history

**Keep three things together: the encrypted history download, the original full
genesis file, and the original independently selected trust policy. Keep the
backup passphrase separately.** The history download preserves records and
unresolved obligations; it does not restore signing keys or an active wallet.

This workflow applies to the current local development wallet and merchant
browser. It is a recovery-only procedure, not a production custody approval.

## While the workspace is healthy

1. In the browser's history-backup form, enter and repeat a separate backup
   passphrase and acknowledge the whole shared-history scope. Download
   `1soft-recovery-history.p4b3` and store it privately. The form clears its
   passphrase fields; remember or separately preserve your passphrase.
2. Preserve the workspace's **`engine-genesis.json`**, byte for byte. In the
   standard local-development workspace this is the full engine genesis used by
   the wallet. `app-genesis.json` is only the application state and is not a
   substitute. Do not reformat the full genesis JSON: even a semantically equal
   file can have different bytes and fail its original hash binding.
3. Preserve the original `policy.json` selected when the journals were created.
   Retain its provenance and your independently trusted genesis/policy identity
   records. A copied policy file or a hash supplied alongside an untrusted
   backup does not establish network trust. Do not derive a replacement policy
   from backup contents, alter its expiry, or choose a new trusted checkpoint to
   make recovery pass.
4. Record hashes of your selected copies so you can detect accidental changes.
   On Linux/WSL, `sha256sum engine-genesis.json policy.json
   1soft-recovery-history.p4b3` reports their exact-byte identities. Preserve the
   receipt privately, with a separately trusted record where appropriate.
5. Keep any required vault/key backups and private invoice records under their
   own custody plan. This history download excludes private keys, encrypted
   vaults, private invoice content and its invoice book, unsigned request book,
   separate portable receipt book, and derived read/ledger stores. The original
   workspace's browser launcher still requires its configured development
   files; this feature does not add browser startup after key or catalog loss.

The download captures all wallet/delivery roles and all seven original journal
tables, including generic decisions and unresolved claims. It is not limited to
the role or invoice currently visible on screen. The browser intentionally
refuses a capture above its 8 MiB original-BLOB bound or a complete encrypted
file above 16 MiB. A refusal is not a partial successful backup. For larger
admitted journals, use the existing custody CLI with its separately documented
core bounds; never prune original records to fit the browser limit.

## Restore into a new private archive

Use the same qualified Python environment as the local wallet, including its
existing cryptography dependency. Run these commands from the repository root
in a local Linux/WSL terminal. Replace the uppercase file names with your own
selected, regular files. `PYTHON` below means the qualified interpreter path,
not a new interpreter installation.

```sh
PYTHON=/path/to/qualified/python
mkdir -m 700 recovery-work

"$PYTHON" tools/protocol4-custody/scripts/p4_custody_cli.py \
  --genesis /private/original/engine-genesis.json \
  --policy /private/original/policy.json restore \
  --backup /private/history/1soft-recovery-history.p4b3 \
  --output recovery-work/recovery.sqlite
```

The CLI prompts for the backup passphrase once, with terminal echo disabled.
There is no password command-line argument or environment fallback. Keep the
output path new: existing files and unsafe aliases are refused rather than
overwritten. A wrong passphrase, altered backup, or mismatched original context
must remain a refusal. Diagnose the source and copies instead of changing trust
inputs until the command accepts them.

The resulting `recovery.sqlite` is an **unencrypted private recovery archive**.
Its containing directory must remain private. It is deliberately incompatible
with an active wallet/delivery restore.

## Inspect obligations before any further action

```sh
"$PYTHON" tools/protocol4-custody/scripts/p4_custody_cli.py \
  --genesis /private/original/engine-genesis.json \
  --policy /private/original/policy.json status \
  --archive recovery-work/recovery.sqlite
```

Inspect `pending_debit_units`, each decision's payer and `grant_id`, recorded
attempts, and the distinct wallet/delivery receipt states. An unknown outcome or
missing receipt is not proof that a payment was unpaid. Receipt collection and
wallet reconciliation remain distinct events. The archive retains the original
policy and its historical time; an expired policy does not become current again
because its historical records can be read.

The status must keep `current_spending_authority`, `signing_enabled`,
`dispatch_enabled`, `automatic_resend`, `latestness_established`,
`old_device_fenced`, `trust_policy_renewed`, and `private_keys_restored` false.
A successful recovery cannot establish that no newer backup exists, disable an
old device, coordinate multiple writers, or make a recovered payment safe to
resend. Those require a separate, explicitly qualified operational procedure.

## Export a selected original record

Use the exact decision ID, payer, and role returned by archive status:

```sh
"$PYTHON" tools/protocol4-custody/scripts/p4_custody_cli.py \
  --genesis /private/original/engine-genesis.json \
  --policy /private/original/policy.json recover \
  --archive recovery-work/recovery.sqlite \
  --decision-id DECISION_ID --payer PAYER --grant raven \
  --output recovery-work/original-wire.json
```

For an owner decision omit `--grant`; for a role decision substitute its exact
`grant_id`. Export an original retained delivery receipt with the same selection
arguments using `export-receipt` in place of `recover`, and a different new output
file. A receipt that was never retained remains unavailable. Both exports are
private plaintext evidence. Exporting a signed wire does not sign it again,
submit it, authorize a resend, or prove current settlement.

## Evidence behind these instructions

The development qualification exercised five real Chromium attachments: two
from the ordinary guarded service and three from the four-validator merchant
flow, including an expired-policy cold launcher. The original canonical decoder
restored each completed attachment and compared all seven tables, original wires,
receipts, holds, and unchanged source rows inside the disposable fixtures. The
merchant browser still made exactly three original sign/submission calls and
closed all eight app/validator processes. These are bounded local runtime checks;
the private attachments and decrypted archives were removed with their fixtures.

A separate operator drill ran six actual canonical CLI commands against one
retained, pinned, public-development format-3 sample. Terminal restore reproduced
the original recovery archive byte for byte; status retained a 40-unit unresolved
hold and every authority flag above remained false. Original-wire export matched
its recorded hash. Existing-output, wrong-passphrase, and reformatted-genesis
attempts were refused without overwrite or a new archive. This drill started no
engine, accessed no key, and sent no transaction. It does not qualify independent
operators, hostile hosts, production funds, power-loss durability, maximum-size
inputs, or public deployment.

See [browser history scope](BROWSER_HISTORY_BACKUP.md), the
[custody CLI and format bounds](../tools/protocol4-custody/README.md), and
[custody compression](CUSTODY_COMPRESSION.md) for the implementation contracts.
