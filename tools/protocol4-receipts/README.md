# Portable P4 payment receipts

30 September 2026. Additive to base
`4133b3fd632bbbb44eba34447b8aefb67e637f3b`.

This tool exports one positively verified native P4 **transfer payment** into a
portable capsule. A separate caller can reopen and verify it after the original
wallet, delivery journal, node application and encrypted key files are gone. The
caller must preserve independently selected full engine genesis bytes and the
exact external P4 read policy, and supply its own verification time. The capsule
carries the original canonical signed wire and complete signed replay evidence.
It is a bounded full-history document, not a compact Merkle receipt proof.

The implementation imports the unchanged `p4_evidence.verify_evidence` and
`verify_receipt` APIs. It verifies the full signed height-1..H+1 header ancestry,
external checkpoint, both validator-set commitments, ordered transaction inclusion,
and native/registry execution. It matches the original canonical signed transfer
with exactly one successful immutable execution receipt. Budget/grant-management
receipts, rejected replay attempts and unavailable records cannot be exported as
payments. These checks reuse the pinned native rules; they are not an independent
implementation or security audit of those rules.

## Python API

Use explicit import paths for this tool's `src`, `tools/protocol4-client/src`,
the native repository's `src`, and `tools/validator-transition/src`. The CLI
sets those paths itself from its installed repository location, with no module
path selected by a capsule.

```python
from p4_receipt_capsule import make_capsule, encode_capsule, verify_capsule
from p4_receipt_archive import P4ReceiptArchive, write_new

# delivery.export_receipt is an existing optional evidence source. This adapter
# does not change the wallet, send a payment, collect RPC data or reconcile holds.
evidence = delivery.export_receipt(decision_id, payer=payer, grant_id=grant_id)
# Recover original wire separately through the existing authorized wallet caller;
# no signer/private-key operation occurs inside the capsule API.
capsule = make_capsule(evidence, genesis_bytes, policy, exact_transaction,
                       payer=payer, now_ns=external_now_ns)
raw = encode_capsule(capsule)
write_new(new_private_path, raw)

# Reopening needs no wallet/delivery/node object or private key.
report = verify_capsule(raw, genesis_bytes, policy, now_ns=external_now_ns,
                       expected_payer=payer,
                       expected_wire_sha256=original_wire_sha256)
```

`make_capsule(evidence, genesis_bytes, policy, exact_transaction, *, payer, now_ns)`
returns a detached dictionary. `encode_capsule(capsule)` returns canonical ASCII
JSON bytes after structural checks; encoding alone is **not** verification.
`parse_capsule(dict_or_bytes)` parses/freeze-checks bounded canonical input.
`verify_capsule(dict_or_bytes, genesis_bytes, policy, *, now_ns,
expected_payer=None, expected_wire_sha256=None)` replays and returns a positive
`verified-p4-payment-receipt` report. All three trust inputs are required.

Without expected payer/wire, verification proves only the payment carried by the
capsule. Invoice and intended-payment callers must compare their own previously
selected payer/wire hash, recipient, amount and purpose. The verified report
makes payer, recipient, signer, original wire hash, native transaction ID, receipt
hash, receipt height/index, and the original transaction explicit.

Display amounts are decimal strings in **native atomic units** with the pinned
asset label: amount, fee and total debit are separate. No dollar price, peg,
reserves, exchange rate, bank/card/issuer relationship or external settlement is
inferred. The report identifies the as-of state height/AppHash, signed header
height/hash and registry epoch. `latest_network_state_established`,
`spending_authority`, `wallet_reservations_changed`, `historical_absence_proven`,
`external_settlement_verified` and `automatic_resend` are always false.

## Format and trust

The strict version-1 fields are `schema`, `format`, `genesis_sha256`, `policy_id`,
`payer`, `wire`, `binding`, and `evidence`. `FORMAT.json` describes the wrapper
schema. Runtime semantic checks additionally require all unchanged P4 evidence
rules. Every binding field is recomputed from the successful replayed receipt;
there is no trusted precomputed display/status field.

`wire` is canonical base64 of the exact original canonical payment JSON bytes.
`binding` has exactly `native_txid`, `receipt_sha256`, `wire_sha256`, `height`,
`index`, and `signer_public_key`. The SHA-256 content address is the lowercase
hex digest of the entire canonical capsule bytes; no self-declared capsule ID is
trusted. The digest identifies bytes, not authority or availability.

The capsule's genesis/policy digest fields must match the separately provided
external policy, and the actual full external engine genesis must pass that
policy's SHA pin and P4 validation. There is no embedded trust policy, anchor
selection, clock or claimed latest state. `now_ns` is an external trusted-clock
assumption, never taken from capsule fields. A caller-supplied historical clock
must not be described as a current verification.

The existing fixed anchor deadline is unchanged: all new capsule verification,
export, archive opening/put/get/inspect refuse once it expires, including duplicate
writes. Later headers do not renew it. Existing bytes remain retained; this
slice does not introduce a post-expiry archival-only qualification API. Delivery's
journal-local historical export is a separate existing behavior and cannot supply
trusted provenance/time to a standalone capsule.

Input caps are 16 MiB for nested evidence, 16,384 bytes for decoded wire,
16 MiB + 32 KiB for the entire capsule, and JSON nesting depth 64. Bytes must be
canonical JSON; duplicate keys, floats/constants, unknown fields, malformed or
trailing data, noncanonical base64, wrong types/versions and oversized input are
refused. The capsule contains only public signed transaction/replay evidence;
no key, password, database, path, secret-config or vault input is accepted. Full
public history may still be private information, so outputs stay in owner-only
directories. This is no generic redaction service for secrets a caller intentionally
places in public chain data.

## Private content-addressed archive

`P4ReceiptArchive(path, genesis_bytes, policy, *, now_ns, create=False,
read_only=False, max_records=32, max_bytes=64*1024*1024)` is separate from every
monetary journal. Initialization is explicit and exclusive. An existing unknown,
empty, mismatched, symlinked, hardlinked or unsafe database/sidecar family is
refused without repair. The archive stores capsule payload and catalogue metadata
in one SQLite transaction, using SHA-256 addresses of canonical capsule bytes.

`put(capsule, *, now_ns, expected_payer=None, expected_wire_sha256=None)` verifies
before insertion and returns `stored` or `already_stored` plus `capsule_id`.
The latter is a no-op for payload bytes; both paths check the original deadline
and durable monotonic clock and advance only the archive's observation clock.
`get(capsule_id, *, now_ns, expected_payer=None, expected_wire_sha256=None)`
reverifies and returns the dictionary; `inspect` with the same arguments returns
the report. Read-only get/inspect do not write the clock/configuration. Callers
retain the returned capsule ID or their exported file for exact retrieval; this
slice has no search-by-wire, listing or latest-wins API.

The hard limits are 32 records and 64 MiB total encoded payload, with configurable
smaller capacities and an 80 MiB per-database/sidecar physical read bound.
Capacity exhaustion refuses rather than evicting. Different verified evidence
for the same wire may be retained under different IDs; no arrival order selects
current authority. Archive misses are outcome-unknown and cannot release holds
or authorize another submission. No signer, RPC, send, reconciliation, cancellation,
retry, reset, rearm, trust renewal or latest-state operation exists.

Archive/export paths require a private owned POSIX parent (0700), regular owned
unaliased files (0600), and no symlink ancestors/database sidecars. These checks
assume a trusted stable same-user host/filesystem and clock. They do not qualify
hostile OS access, whole-workspace deletion/rollback, independent operators,
power-loss behavior or availability. A failed output or uncertain external caller
return does not imply wallet rollback or safe retry.

## CLI

The CLI uses the local system clock and has no historical-clock override. All
commands require the same separately trusted `--genesis` and `--policy`. It
performs no network access, key loading or wallet/delivery mutation.

```sh
python tools/protocol4-receipts/scripts/p4_receipts.py \
  --genesis /private/engine-genesis.json --policy /private/read-policy.json \
  export --evidence /private/collected-original-evidence.json \
  --transaction /private/exact-original-signed-transfer.json \
  --payer EXACT_NATIVE_PAYER --output /private/new-capsule.json

# Same --genesis/--policy arguments:
# verify --capsule CAPSULE --expected-payer PAYER --expected-wire-sha256 HASH
# archive-init --archive NEW_PRIVATE.sqlite
# archive-put --archive PRIVATE.sqlite --capsule CAPSULE
# archive-get --archive PRIVATE.sqlite --capsule-id ID --output NEW_CAPSULE.json
# archive-inspect --archive PRIVATE.sqlite --capsule-id ID
```

Every output file is exclusive; an existing output remains intact. Exit zero
means the requested local command completed; exit 2 means refused/unavailable,
never unpaid or permission to resend. Error messages omit payloads and secrets.

## Verification

Use the already pinned interpreter/dependencies, with no package installation:

```sh
python tools/protocol4-receipts/tools/verify.py --native-root . \
  --report /private/new-receipts-report.json
```

`DEPENDENCIES.json` pins the original parent commit and all 190 unchanged
native/existing-addon dependency files. The parent must be an ancestor of the
current source commit; a clean additive integration may advance HEAD without
replacing any of those pinned bytes. `SOURCE_MANIFEST.json` records this tool's
deliverable bytes. Both inventories are checked before and after the focused suite.

The entrypoint also invokes the unchanged existing release
`tools/release/check_release.py:source_identity` before and after tests. That gate
requires a completely clean tracked/untracked checkout and verifies every tracked
byte and mode against current HEAD. The entire source identity must remain equal
across the run. The receipt tool must be installed under that selected checkout;
there is no skip, dirty-tree or ancestry-only qualification path. Reports record
`parent_commit` separately from the tested current `source_commit`, `source_tree`
and `source_id`. Write new reports outside the source checkout to preserve its
clean identity for subsequent checks.

Exact installed versions from the native requirements file remain required.
The unchanged `evidence/receipt-tests-20260930.json` is the historical
preintegration 32-case report. It and previous engine logs keep their original
provenance; they are not relabeled as tests of a later integration commit. See
`VERIFICATION.md` for observed scope and remaining gates. No byte identity check
or synthetic header is labeled a new real-engine or independent-security result.
