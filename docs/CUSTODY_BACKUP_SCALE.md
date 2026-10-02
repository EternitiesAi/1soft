# Complete P4 custody backups within current admission bounds

The original custody format can refuse a valid journal pair once its complete
BLOB payload exceeds 7 MiB. Wallet observations independently admit 64 MiB and
delivery receipts independently admit 64 MiB. Version 2 closes this representation
gap without changing wallet, delivery, evidence, RPC or native admission rules.
It does not prune histories or turn restored records into current authority.

## Compatibility and authority

`backup(delivery, output, password, format_version=None)` uses the complete legacy
format whenever it fits, then uses version 2 for a larger admitted pair or the
separate legacy plaintext-capacity edge. Explicit versions 1 and 2 are supported;
other selectors are refused. The CLI exposes `--format auto|1|2`. Existing v1
encrypted backups and recovery archives remain readable, with their original
snapshot IDs and original byte limits. An older implementation cannot read v2.

Capture still takes wallet-then-delivery locks, audits the source pair, copies its
exact logical cells into fixed in-memory schemas and releases source locks before
encryption. Nothing checkpoints, repairs, migrates, rewrites or renews the source.
Every restore audits against externally selected exact genesis and policy bytes.
The original wallet and delivery historical auditors verify original decision and
attempt contexts, signatures, fee-inclusive holds, proof lineage and receipt
bindings at the saved original times. Capture time is descriptive metadata.

The restored SQLite application ID remains the recovery-only `ARCHIVE_ID`.
Version 2 archives have only fixed `recovery` and `chunks` tables. There is no
persisted ordinary signing journal, key, send capability or active restore path.
Latestness, old-device fencing, current spending authority, policy renewal and
automatic resend remain false. A consumed claim without response remains
unresolved even when a later clock or another restored archive exists.

## Fixed bounded serialization

The stream contains bounded canonical metadata, exact genesis bytes, and the
seven existing tables in their fixed order. Each row has canonical scalar/type
metadata followed by original raw BLOB bytes. Only nonnegative SQLite integers,
strings and bytes are accepted. No SQL, module name, filename or schema is loaded
from the stream. A terminal marker and exact stream EOF are required.

The conservative admitted BLOB maximum is 141 MiB+4096 bytes: 64 MiB observations,
8 MiB decisions (256*32768), 4 MiB attempts (256*16384), 1 MiB responses
(256*4096), 64 MiB receipts, and 4096-byte policy. This is a safe aggregate ceiling,
not proof that every maximum is simultaneously attainable. Seven table row limits
total 834; each row metadata frame is at most 4096 bytes, snapshot metadata at most
8192 bytes, and exact genesis at most1 MiB. These derive a 152,329,575-byte complete
stream ceiling. Per-table/per-cell/row caps are enforced before BLOB allocation
and before original financial audit. Admission constants are imported, not raised.

## Authenticated chunk stream

The binary envelope starts with `1SOFTP4B2\n`, a four-byte header length and exact
canonical header JSON. The header fixes version 2, the format, library AES-256-GCM,
the original Scrypt parameters, a fresh 32-byte salt, a fresh 8-byte nonce prefix
and 1 MiB chunk size. Header length is at most 4096 bytes; unknown parameters and
inflated KDF settings fail before derivation.

Every frame is a type byte (`D` data or `F` final), four-byte ciphertext length,
then ciphertext including the 16-byte GCM tag. The nonce is the per-file prefix
plus the four-byte monotonically increasing frame position. Associated data is
the magic, exact encoded header, frame type, frame position and plaintext length.
The final frame gets its own position/nonce and authenticates exact counts,
stream SHA256, total bytes and every table's row/BLOB counts. All preceding data
frames except the last fill1 MiB. Exact envelope EOF follows the final frame.
The snapshot ID is a SHA256 commitment with a version 2 domain prefix.

The full encrypted bound is 152,340,868 bytes and at most 146 data chunks.
Restore retains authenticated chunks privately, verifies the complete final
commitment, reconstructs fixed in-memory journals and runs original historical
audits before creating or linking the recovery output. Its fixed 4096-byte SQLite
pages and bounded chunk/schema overhead yield a 153,591,143-byte archive limit.
Plaintext bytes authenticated in an earlier frame do not authorize partial
publication, spending, sending or early success.

Private ownership/mode/single-link checks, no-follow file access, exclusive output
and sidecar refusal, temp-file fsync, no-overwrite linking and directory fsync
remain. Failure before the output link removes the temporary file. A directory
fsync failure after linking reports complete output with unconfirmed durability
and requires inspecting the existing result before retrying.

## Verification scope

Tests cover old-format compatibility, explicit and automatic selection, actual
admitted journals above 7 MiB, exact table/wire/receipt preservation, unresolved
holds and historical clocks, active-constructor refusal, wrong passwords,
authenticated altered signatures, corrupt archives, unknown parameters/versions,
mixed/reordered/duplicated/deleted/truncated/appended frames and publication
failures. The actual scale fixture uses real native rules and synthetic public
committee/signing keys; it uses no engine, network or value-bearing funds.

Cipher and serializer buffers are bounded per chunk/cell. Existing auditors and
frozen archive chunks still retain full bounded journal/proof data. Maximum-size
RAM, CPU, disk-pressure and power-loss behavior are unmeasured, and this is not
constant-space auditing or production custody certification. Hostile-host review,
private-key recovery, cross-device fencing, pruning/history economics and
independent operators remain separate gates.
