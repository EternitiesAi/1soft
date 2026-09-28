# 1soft — portable historical receipt archive

An offline archive for already-executed payments. It uses the existing 1soft
certificate and sparse-Merkle verifiers; it creates no coin, key, signature,
spending authority, RPC service or alternative wallet journal.

Parent: PR #15, `072ebe6a6850c80044a5ad1b0496c6f3a1ffebe0`, full repository tree
`e0fd1339358f2c8d3320b1668bee1c1c6febdef7`. This directory is additive. Native code,
root source inventory, block retention and the competing PR #11 are unchanged.

## What it does

`pack_receipt` converts a saved full certificate into a portable historical proof.
For protocol 3 / `smt-v1`, the output carries one authenticated receipt row rather
than the complete ledger. Protocol 1/2/3 flat commitments necessarily retain their
full-state witness; there is no made-up compact proof for a flat hash.

Every capsule contains the exact signed transaction, its block and signed commit,
a signed state commitment, the receipt proof, and every intermediate signed header
linking the inclusion block to that state commitment. At most 64 intermediate
headers are supported. Capture near execution or supply the exact available links;
a larger or incomplete gap is refused, not silently bridged or truncated.

The caller supplies the exact transaction bytes and independently pins BOTH the
engine-genesis file SHA-256 and final state-header hash. A capsule cannot select its
own validator list or supply its own trust. Verification checks the exact signed
bytes, receipt fields and digest, execution height, original native signatures
(including incoming-key consent when relevant), proof root, all required validator
signature slots, full preceding block IDs, consecutive heights and timestamps.
The existing static-validator trust assumptions remain. A compromised quorum or
untrustworthy initial pins are not solved by archiving.

These are **historical** proofs. There is no freshness claim, trust renewal,
latest-balance claim, proof of independent validators, or off-chain settlement.
Unlike a wallet approval, inspecting an old receipt requires no current password,
key or live network connection. It never updates the wallet or frees a reservation.

## Append-only local archive

`ReceiptArchive` stores canonical capsules by content digest in a separate SQLite
file. It will not initialize over an existing file, use a wallet/dispatcher database,
repair an unknown schema, or evict evidence to make space. Default capacity is
4,096 capsules and 128 MiB of stored capsule payload, not a total-disk/RAM bound.
An individual capsule is limited to 16 MiB. Operators may explicitly choose bounded
capacities when creating an archive; stored capacities survive reopening.

Imports verify once-frozen input bytes and then insert metadata and payload in one
SQLite transaction. Exact repeats are idempotent. Competing valid receipts for the
same native transaction are retained, as are conflicting signed state headers at
the same height. Lookup reports `conflict` rather than selecting by arrival time.
All associated evidence remains explicitly exportable, but export is not a vote
for that evidence or a resolution of the conflict.

A lookup reports `available`, `unavailable`, or `conflict`. **Unavailable does not
mean unpaid, absent on-chain or safe to retry.** This archive contains selected
positive evidence, not a complete execution set. No archive status is consumed by
the signing, reservation, delivery or wallet-reconciliation code.

The database lives in a private owned POSIX directory; the database and its SQLite
sidecars must be private regular files without symlinks or hard links. Inspection
rechecks payload hashes, signatures, pins and index correspondence. Outputs are
exclusive new files. These measures assume a trusted local host/filesystem, not
hostile-OS custody or protection against deletion/rollback of an entire archive.
There is no distributed availability guarantee or encryption at rest. Flat-state
capsules and transaction inclusion blocks can include other public chain records;
keep archives private as appropriate for their contents.

## CLI

Run from the repository root with its already-installed pinned dependencies:

```sh
python tools/receipt-archive/tools/verify.py --native-root .
export PYTHONPATH="$PWD/src"

python tools/receipt-archive/scripts/receipts.py \
  --genesis /private/engine-genesis.json --genesis-sha256 EXPECTED_DIGEST \
  pack --packet /private/certificate.json --transaction /private/signed-tx.json \
  --state-header-hash INDEPENDENTLY_PINNED_HEADER_HASH \
  --continuation /private/intermediate-signed-headers.json \
  --output /private/new-receipt.json

python tools/receipt-archive/scripts/receipts.py \
  --genesis /private/engine-genesis.json --genesis-sha256 EXPECTED_DIGEST \
  init --archive /private/new-archive.sqlite

python tools/receipt-archive/scripts/receipts.py \
  --genesis /private/engine-genesis.json --genesis-sha256 EXPECTED_DIGEST \
  import --archive /private/new-archive.sqlite --capsule /private/new-receipt.json \
  --transaction /private/signed-tx.json --state-header-hash INDEPENDENTLY_PINNED_HEADER_HASH
```

The same CLI has `verify`, `lookup` and `export`; `--help` lists their required
inputs. Signed transaction files contain exact canonical bytes (no newline
normalization). `--continuation` is omitted only when the state header immediately
follows the inclusion block. Parent directories for new outputs must already be
private and owned. No command downloads dependencies, signs, submits or retries a
payment. Exit 2 means refusal/unavailable/conflicting evidence, not payment failure.

## What this does NOT finish

The source node's native receipts remain complete and its snapshots are unchanged.
Archiving is a prerequisite for useful historical retrieval, **not permission to
prune consensus receipts under existing protocols**. Current wallet expiration and
absence-based reconciliation still require complete authenticated receipt history.
They must never be run against this partial archive.

A future native-history protocol needs an explicit version/genesis boundary,
authenticated history roots and transition rules, replay prevention after payload
removal, archive-proof/availability behavior, and a wallet that preserves unknown
obligations when historical evidence is missing. This code supplies durable,
portable positive receipts; it does not implement that future consensus transition.

No public network, real funds, production custody, Actions, paid compute,
website/DNS work, Resident/Luna work, merge or force-push is involved.
