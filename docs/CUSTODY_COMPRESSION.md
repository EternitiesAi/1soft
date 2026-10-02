# Compact encrypted historical recovery backups

Explicit backup format 3 compresses each bounded journal-stream chunk before
encryption. It preserves the exact version-2 row stream, snapshot identity,
original signed payments and historical receipt evidence. Restoring it creates
the existing version-2 recovery-only archive. It cannot activate a wallet,
submit a payment, release a hold, renew trust or fence another device.

## Use and compatibility

```sh
python -B tools/protocol4-custody/scripts/p4_custody_cli.py \
  --genesis GENESIS.json --policy ORIGINAL_POLICY.json backup \
  --wallet PRIVATE/wallet.sqlite --delivery PRIVATE/delivery.sqlite \
  --endpoint http://127.0.0.1:26657/ --format 3 \
  --output PRIVATE/new-compact.backup

python -B tools/protocol4-custody/scripts/p4_custody_cli.py \
  --genesis GENESIS.json --policy ORIGINAL_POLICY.json restore \
  --backup PRIVATE/new-compact.backup --output PRIVATE/historical.sqlite
```

Use an already initialized bound journal pair, its exact original genesis and
policy, a trusted POSIX host and an owned0700 directory. Terminal passphrase
input, exclusive0600 outputs and no-overwrite durable publication follow the
existing [custody contract](../tools/protocol4-custody/README.md).
The restored archive is **unencrypted private local payment data**; only the
backup envelope is encrypted. No private signing key is backed up.

The API selects it with `backup(..., format_version=3)`. The default `auto`
behavior is unchanged: small complete backups use version1 and larger admitted
pairs use version2. Explicit versions1 and2 remain available. Current restore
accepts all three envelopes and both existing recovery-archive versions. Older
readers refuse version3. No existing database is migrated, edited or evicted.

## Exact transport and resource bounds

The magic is `1SOFTP4B3\n`, followed by a four-byte canonical-header length and
header JSON. The exact header fixes schema3, format, AES-256-GCM, the original
Scrypt parameters, fresh32-byte salt and8-byte nonce prefix,1MiB chunk size,
standard zlib at level6 and window_bits15. Unknown or inflated settings and
noncanonical headers are refused before key derivation.

Data frames consist of kind`D`, one-byte codec (`0` raw or `1` zlib), four-byte
original length, four-byte ciphertext length and ciphertext including its16-byte
GCM tag. Compression is used only when strictly smaller; otherwise the original
chunk is encrypted directly. Each chunk is independent. Associated data binds
magic, exact header, kind, frame position, codec, original length and encoded
length. The nonce is the fresh prefix plus four-byte frame position.

The final kind`F` frame uses raw encoding and its own nonce, authenticating the
unchanged version-2 manifest. That manifest commits to every original stream
byte, chunk count, total length and each table's row/BLOB count. Exact file EOF
is required. Identical frozen captures encoded as2 or3 have the **same snapshot
ID**; independent captures can differ because capture timestamps are retained.

Restore bounds frame sizes before reading or decryption and authenticates a
frame before decompression. Zlib output is capped at the declared original
length plus one, then must equal the exact declared length. Missing EOF, tails,
concatenated streams and dictionaries are refused. All nonfinal original chunks
must fill1MiB. The existing limits remain146 chunks,152,329,575 stream bytes,
153,591,143 private archive bytes, seven fixed journal tables and their original
row/cell/aggregate caps. The encrypted v3 ceiling is152,341,603 bytes: the v2
ceiling plus at most735 bytes of additional frame metadata. Incompressible data
uses raw fallback rather than increasing logical admission.

After the final commitment, restore reconstructs the fixed in-memory schemas and
runs the unchanged historical financial and proof auditors against external
genesis/policy. It publishes a recovery archive only after all checks succeed.
Both active wallet and delivery constructors refuse the archive. Exact original
wires, consumed attempts, endpoint observations, saved receipt bytes and
fee-inclusive pending holds remain recorded, including unresolved outcomes.

## Reproducible qualification

```sh
python -B tools/protocol4-custody/tools/verify.py --report NEW_CUSTODY_REPORT.json

python -B scripts/run_protocol4_delivery_engine.py \
  --engine PINNED_COMETBFT --engine-sha256 INDEPENDENT_SHA256 \
  --custody-format 3 --output /private/new-validator-custody-evidence
```

The opt-in engine profile adds10 custody observations to the42 original delivery
observations. It uses eight loopback nodes on one host, performs full replacement
of four validators, executes the original payments and then tests v3 recovery of
the exact journals and receipts. Its snapshot precedes the separate optional
owner-replacement stage. No keys, journal payloads, backups or plaintext archives
are exported in the public result; retained metadata records their hashes only.
An exact-source receipt is required to claim this profile passed.

The paired profiler prepares one new private signed-native fixture above the old
7MiB representation limit and freezes a single capture. Fresh processes compare
v2/v3 encoding and restore against exactly those same rows and snapshot ID:

```sh
python -B tools/protocol4-custody/scripts/profile_backup.py \
  --fixture /private/new-backup-fixture --prepare
python -B tools/protocol4-custody/scripts/profile_backup.py \
  --fixture /private/new-backup-fixture --format 2 --sample /private/new-sample-v2
python -B tools/protocol4-custody/scripts/profile_backup.py \
  --fixture /private/new-backup-fixture --format 3 --sample /private/new-sample-v3
```

Use a new sample directory each time. Preparation and whole-process memory are
reported separately from timed encoding; restore timing includes the original
historical audits. The fixture uses real native signatures/execution rules but
**does not run CometBFT consensus**. The profiler requires clean committed source
and verifies every source byte/mode and the frozen fixture before and after.
Keep its private keys, journals, frozen input and sample files out of published
reports; the printed JSON contains only sizes, hashes and timing metadata.

These are bounded local development checks. Compression reduces encrypted backup
bytes; it does not reduce the restored archive, audit memory, native receipt
state, trusted history or chain-height limits. No maximum-capacity resource,
physical power-loss, independent-host, production-custody or public-launch claim
follows from a smaller file. Ledger transactions remain public. Long-lived
history/pruning, cross-device coordination, external security review and public
economics remain separate engineering gates.
