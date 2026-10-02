# Compact verified read-proof storage

Fresh read-store format 2 reduces the disk space used by complete canonical P4
proof packets. It stores a bounded compressed representation and reconstructs the
original bytes before the existing signed-history verifier, receipt reader and
explorer use them. It creates no key, financial journal, hold or submission.

## Choose a fresh store explicitly

`P4ReadStore(path, genesis, policy, create=True, storage_version=2)` creates the new
format. Omitted selection creates the original format 1. The CLI adds
`--storage-format 2` to `init`; the other existing policy and genesis arguments are
still required. The `storage` command opens a store read-only and returns
`format_version`, `observations`, `logical_evidence_bytes`, `stored_payload_bytes`
and `spending_authority: false`. These are storage measurements, not a current
balance, freshness or execution certificate.

Existing stores open automatically by their recognized version. An explicit
creation selector on an existing store refuses. There is no in-place migration,
record eviction, schema repair or silent upgrade. Old software refuses format 2.
The application identity remains `0x31503452`; `config.version` distinguishes the
two schemas. Format 2 adds `logical_bytes` after the original six observation
columns. The external genesis and trust policy must still match exactly.

## Original bytes and original resource limits

Each stored format-2 payload contains a fixed 15-byte frame: ten magic bytes, one
raw/zlib codec byte and four bytes of original length, followed by encoded bytes.
The writer uses standard zlib level 6, window 15, only when smaller than the raw
proof. Otherwise it stores the raw proof. This representation does not become a
trust anchor: SHA256 of the reconstructed original canonical proof remains its
evidence ID. Exports reproduce those original bytes exactly.

Before loading proof BLOBs, the catalog checks descriptor types, count, individual
logical and physical lengths, and aggregate sizes. Payloads must have SQLite BLOB
type and original lengths must have integer type; text-character lengths or
coercive sums cannot replace these checks. The decoder requires the fixed `78 9c` zlib header without a dictionary flag,
caps output before decompression, then requires the exact declared length, end of
stream and no
trailing, concatenated or dictionary-backed stream. Missing, corrupt or inflated
frames refuse without rewriting history.

The limits remain 32 observations, 64 MiB of aggregate **original** proof bytes,
16 MiB per original proof, and native development height 512. Framing adds at most
480 bytes beyond the aggregate logical cap. Smaller compressed bytes cannot buy
extra admissions. These limits are not a total SQLite-file or production scaling
claim. Every accepted proof still carries complete history and is fully replayed
under the pinned external policy.

## Financial and trust boundaries

Import, current views and exports retain full verification. Expected-tip
compare-and-swap, fork and rollback refusal, alternate-quorum handling, original
external clocks, trust expiry and atomic persistence remain. Compression finishes
before the final expiry check immediately preceding the insert. Any error rolls
back the attempted import.

This is a separate read-only-derived service; wallet and delivery journals,
reservations and authority are unchanged. The explorer uses its existing
`current_view` caller and projection. Compression is neither local encryption
nor on-chain privacy. The native ledger remains public. Historical views do not
prove globally latest state or renew trust.

## Local qualification

Run the complete current-source checker, then the actual local validator scenario
with an already verified engine and the optional read-store flag:

```sh
python tools/release/check_current.py --output /private/new-current-evidence
python scripts/run_protocol4_delivery_engine.py \
  --engine PATH_TO_COMETBFT --engine-sha256 PINNED_SHA256 \
  --custody-format 3 --read-store-format 2 \
  --output /private/new-p4-storage-evidence
```

The read-store gate feeds both formats the exact original packets retained by the
wallet during full validator replacement and payments. It checks original exports,
recorded receipts and account balance, full verified reports, the existing explorer
projection, original-byte capacity charging and no new submissions or financial
journal changes. These are disposable loopback validators, not independent hosts.

`tools/protocol4-client/scripts/profile_storage.py` prepares a new private proof
sequence from the audited reference native-test archive prepared by commit
`3df15e3f14795ec5641a47e449ebc350fe452937` and measures fresh
format-1/format-2 stores in separate processes. It binds original proof hashes and
clocks, the exact complete original 560-file capture manifest and its canonical
source identity, unchanged native/verifier files and the exact
current source. Import timing includes new store creation and complete verification;
current-view timing includes full latest-proof verification. Canonical export checks
are outside the timed read. SQLite database and sidecar bytes and whole-process
peak RSS are reported separately. Use the same frozen input and balanced order;
report encoding/read costs alongside disk savings. Synthetic signed fixtures are
not CometBFT evidence, and one bounded shape does not establish maximum capacity.

Height extension, stable trust renewal, long-term pruning, shared-history indexing,
independent operators, cross-device reservations, power-loss certification and
external security review remain separate work. Compression addresses physical
derived-store usage within the existing development envelope.
