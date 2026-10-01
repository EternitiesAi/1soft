# Portable committed merchant payment evidence

A merchant can export one retained public invoice, original signed payment,
positive native receipt capsule and exact public resource in a bounded canonical
JSON file. The standalone checker replays the payment and proves that its signed
invoice commitment authenticates these terms and these resource bytes. This is
development-only native DEV; no protocol, monetary, custody or ledger-privacy
rules change.

## Export the original

Use an existing ready v3 invoice-capable merchant development workspace and its
original immutable merchant book. The quote must have a committed v2 offer, an
independently enrolled original wire and a retained completed fulfillment.

```sh
python -B tools/private-payments/scripts/1soft_merchant.py export-proof \
  --workspace EXISTING_WORKSPACE --engine PINNED_COMETBFT \
  --quote-id ORIGINAL_QUOTE_SHA256 --proof-out NEW_PRIVATE_PROOF_FILE
```

The export opens one consistent read-only snapshot, replays the stored receipt
at the book's retained fulfillment time, and writes one exclusive owner-only
file. It preserves the original required, signature and response headers, signed
wire, canonical capsule and resource bytes. The canonical invoice preimage is
reconstructed from the exact original quote and included without normalization.
It does not sign, submit, collect newer evidence, fulfill again, retire a wallet
hold, start an engine or renew trust. Existing files are refused.

The normal merchant-workspace and current fixed-policy guards still apply to
export. This command does not add historical opening of an expired merchant
workspace. Export while the original workspace remains valid; archive the proof
and independently retained trust/intent records for later inspection.

## Check it offline

The verifier needs five independently selected inputs: the proof, exact trusted
engine genesis bytes, original policy, authenticated expectation and original
assignment, plus an explicitly selected historical nanosecond time:

```sh
python -B tools/private-payments/scripts/verify_merchant_proof.py \
  --proof ORIGINAL_PROOF_FILE --genesis TRUSTED_ENGINE_GENESIS \
  --policy ORIGINAL_TRUSTED_POLICY --expectation TRUSTED_EXPECTATION \
  --assignment TRUSTED_ORIGINAL_ASSIGNMENT --as-of-ns TRUSTED_HISTORICAL_NS
```

The expectation contains merchant origin, resource URL, network, asset, genesis
digest, recipient and atomic amount. The assignment contains `quote_sha256`,
`request_id`, `recipient`, intended `payer` and the exact original `wire_sha256`.
These must come from independently authenticated retained records. Copying pins
from the untrusted proof merely establishes internal consistency. The proof
contains no policy, trusted assignment, key, private invoice content or timestamp
that can select its own authority.

This first version is explicitly **historical AS-OF inspection**. The caller's
time must be within the original quote interval and original fixed policy
interval; signed-header age/drift rules also apply unchanged. It does not silently
choose quote creation or fulfillment time. An expired quote cannot be verified
at today's time through this API even if a separate policy remains valid. A
historical pass cannot authorize current spending or live fulfillment, renew
trust, prove when the payer signed, or prove original delivery time.

The CLI runs without an engine, wallet, vault, merchant database or RPC. Input
files use the existing private-file guards; failures return a short generic
refusal without echoing payloads. Verification writes no files. The pure Python
API takes all external trust and intent inputs explicitly.

## Evidence and limits

The fixed field set uses canonical base64 for original wire, capsule, preimage
and resource bytes. It rejects duplicate/unknown JSON fields, noncanonical JSON
or base64, boolean integers, deep input, oversized headers and decoded parts.
There is no ZIP reader or extraction. Wire is capped at 16 KiB, public resource
at 64 KiB, preimage at 8 KiB and capsule at the existing 16 MiB plus 32 KiB.
The outer byte ceiling includes bounded base64 expansion and header overhead.

The existing receipt verifier checks validator ancestry/authorization, signatures,
inclusion and positive native execution. The invoice verifier additionally checks
the original quote/request, transfer recipient/amount, native signed commitment,
preimage and resource digest. The response is checked for consistency with that
replayed payment; it remains an unsigned declaration.

A valid proof establishes an executed payment committing to these public bytes.
It does **not** establish merchant identity, customer receipt, external service
completion, merchant-store durability, globally unique consumption, settlement,
latest network state, independent validator hosts, production readiness or
on-chain privacy. Full bounded public ledger history is disclosed in the capsule.
Private invoice encryption is separate and no private content/key belongs here.

## Reproduction gate

`tools/private-payments/tests/merchant_proof_comet.py` creates its own disposable
v3 workspace and four pinned local CometBFT 0.38.25 validators. It makes owner,
Raven and Atlas committed payments, fulfills them, invokes the actual export
CLI, checks exact original bytes, collision refusal and unchanged journals and
policy, then removes its owned runtime after clean shutdown. Three standalone
offline processes reverify only the retained public files after cleanup. Changed
resource bytes and a coherently relabeled genuine payment must be refused.

```sh
python -B tools/private-payments/tests/merchant_proof_comet.py \
  PINNED_COMETBFT NEW_PRIVATE_OUTSIDE_SOURCE_OUTPUT
```

The run retains exact public proofs, separate fixture trust/intent records, raw
bounded app/engine logs, counters, source inventories and cleanup results. Fixture
pins are generated by that owned operator; they are not a public network trust
anchor. Component tests use real native execution with synthetic signed headers;
the actual engine gate is separate. Results qualify only the source revision
recorded by the accompanying delivery receipt, not historical full-source or
upstream Go qualifications.
