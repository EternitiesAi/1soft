# Compact authenticated state — v0.13

September 24, 2026 (America/Chicago). Local development; no launched network,
independent audit, new asset issuance, or production-custody claim.

## What changes

An explicitly opted-in development chain can provide a proof for selected
account, grant, budget, or receipt rows instead of transmitting the entire native
ledger. The verifier binds each requested table/key to the root authenticated by
the existing static-validator signed-header verifier. A valid signature on an
unrelated root, a different record, or the wrong height is insufficient.

The same format can prove that a particular record was absent **at a specified
historical height**. Absence is not proof that a pending payment cannot execute
later and never automatically authorizes refunding or replacing a payment.

The read-only transfer preflight uses three records for an owner transfer and six
for a delegated transfer: owner account, recipient account, native clock, agent
grant, immutable grant-to-budget binding, and parent budget. It checks the signer,
nonce, available balance, grant/parent restrictions, and both remaining allowances
including fees. The budget ID may be supplied as a lookup hint, but that exact
link and its target must both prove against the same root. It cannot mix records
from different checkpoints.

The preflight does not unlock, sign, broadcast, reserve balance, or establish that
the witnessed state is the latest. The existing signing wallet still uses its
whole-state witness, freshness policy and journal. Connecting compact preflight to
that signing workflow is deliberately not claimed complete in this release.

## Explicit genesis choice

Use a **new** development genesis with both:

```json
{"protocol_version":3,"state_commitment":"smt-v1"}
```

These are two fields of the otherwise complete native genesis, not a complete
genesis file. No existing database is migrated and no existing validator genesis
should be edited. Absent `state_commitment`, protocols 1, 2 and 3 retain their
previous byte-for-byte application commitments. Unknown modes, missing explicit
protocol 3, and other protocol versions are rejected. The new mode retains the
native protocol-3 transfer and shared-budget semantics; genesis/hash bindings
prevent replay from a differently configured chain.

The new capacity bound applies only to this explicitly opted-in mode. The complete
map has at most 20,000 records. A transaction that would exceed the bound is
rejected before its native commit, with balances, counter, budget spending and
receipt rolled back together. Proposal preparation cannot accept an overflow and
then fail when creating its final root. Empty blocks can still commit at the
capacity. This is a finite prototype capacity, not a production storage-fee or
pruning policy; at capacity, state-growing transactions cannot proceed.

## Format and cryptographic construction

The construction uses ordinary SHA-256 and a fixed-depth sparse binary Merkle
map. It is project integration, **not a new cryptographic primitive**, and this
JSON proof format is **not ICS23, IBC, or standard ABCI ProofOps compatibility**.

Logical keys are the canonical ASCII JSON array `[table, key]`. Their 256-bit tree
paths are SHA-256 of `1soft/state-key/v1\0` followed by that array. A record's value
is its canonical positional row array; table schemas are fixed. Duplicate keys or
path collisions are rejected rather than overwritten.

Hash domains are deliberately distinct:

- Nonempty leaf: `SHA256(0x00 || path_digest || SHA256(canonical_row))`.
- Empty leaf: `SHA256(0x02)`.
- Branch: `SHA256(0x01 || left_digest || right_digest)`.

Empty-subtree hashes are derived for all 256 heights. A proof carries the exact
table/key, the row or `null`, a 256-bit bitmap, and only nondefault sibling hashes.
Bits and siblings are ordered from leaf toward root; a one bit at height h means
that h's sibling is supplied. Explicitly supplied default siblings, duplicate
entries, malformed masks, altered row keys and unused siblings are rejected.
The verifier uses the caller's expected query set, not the provider's preferred
selection. Requested absence and actual membership are distinct outcomes.

The application commitment is:

```text
SHA256("1soft/application-smt/v1\0" || native_genesis_sha256_bytes
       || uint64_big_endian(state_height) || sparse_merkle_root)
```

The existing verifier authenticates that application hash using the signed header
at state height **h+1**, not h. Public genesis metadata and validator trust still
need to be pinned independently. Native replay receipts, budgets, grant bindings,
accounts and metadata all remain in the committed map, even when a particular
proof discloses only one row.

`state_tree.py` constructs a compressed in-memory node structure and expands
skipped paths cryptographically. `tools/state-proof-reference/verify.mjs` provides
a second, bottom-up implementation for comparison. Both are project-authored;
cross-language agreement is not an independent audit.

## Interfaces

`BlockApplication.compact_witness([(table, key), ...])` returns up to 16 proofs
from committed state. A pending proposal/finalization is not visible through it.

An individual proof is available at the application query path:

```text
/proof/TABLE/LOWERCASE_HEX_OF_ASCII_KEY
```

It is custom proof JSON in the query **value**, using `prove=false`; the existing
ABCI transport was not changed to advertise standardized ProofOps. Nonexistent
keys produce a Merkle absence proof. Unknown tables, malformed keys and historical
query heights are rejected. Root construction still reads the local full snapshot.

Read-only client entrypoints are:

```text
verify_compact_witness(..., expected_queries=[...])
review_compact_transfer(..., body, signer_public_key)
verify_compact_receipt(..., expected_transaction=exact_signed_bytes, block, commit)
```

The receipt path requires both block inclusion and the committed execution-record
proof, and binds the caller's exact signed transaction bytes. One receipt proof
does not disclose every other receipt, but the current block inclusion verifier
still consumes that block's transaction list. Compact transaction-list proofs are
not implemented.

The CLI is `python scripts/verify_compact.py --help`. Supply a separately pinned
public genesis and its SHA-256, the compact witness, and a signed header. Subcommands
are `records` with explicit `--expect TABLE KEY`, `preflight` with a body and signer,
or `receipt` with exact transaction, block and commit files. It performs no network
requests. A historical success must not be presented as current signing authority.

## Measured evidence size

The included reproducible measurement executes 1,024 signed native transfers in
16 local application blocks. Both representations verify against the same
synthetic committee-signed state root and include the same signed-header overhead:

| Representation for one account | Serialized bytes |
|---|---:|
| Full-state witness | 1,212,982 |
| Compact witness | 3,961 |

That is a 99.6734% reduction for this fixture (306.2313 times smaller). The map has
1,031 rows; the account proof supplies 11 sibling hashes and no unrelated receipt
rows. Public genesis metadata is still included. This is a serialized-evidence
comparison, not a live-network, throughput, CPU, gas, fee or privacy benchmark.

Reproduce with installed pinned dependencies and a new output directory:

```sh
python scripts/measure_compact_witness.py --output evidence/my-witness-measurement
python scripts/check_compact_reference.py --output evidence/my-cross-check
```

## Important limits

The node still stores and restores whole snapshots and rebuilds the tree. This
release improves **client evidence size**, not production node storage, indexing,
throughput or incremental-update performance. Proofs have explicit byte and row
bounds. Large state still needs a persistent authenticated store and resource
accounting. No signing-wallet migration, secure backup recovery, dynamic validator
light client, live consensus, banking integration, USD backing, cards, or
cross-asset settlement is delivered.

The proof format does not make a public chain private or anonymous. It avoids
sending unrelated records in a selected response; genesis information, selected
records, access patterns and public transaction data can still reveal information.
Static-validator trust, honest quorum assumptions, local trust policy and genuine
source provenance remain necessary. Synthetic signatures do not establish that
real validators operated a network.

## Primary references and compatibility boundary

CometBFT's application requirements describe application Merkle roots in the next
header and proofs anchored by that root. ICS23 specifies generic positional
commitments and proof formats. Those are architectural references, not claims that
this prototype implements their complete APIs or proof encodings:

https://github.com/cometbft/cometbft/blob/main/spec/abci/abci%2B%2B_app_requirements.md
https://github.com/cosmos/ibc/blob/main/spec/core/ics-023-vector-commitments/README.md
https://github.com/cosmos/ics23

No upstream source was copied wholesale into the new tree or client. Third-party
signature and protobuf implementations retain their existing upstream attribution.
