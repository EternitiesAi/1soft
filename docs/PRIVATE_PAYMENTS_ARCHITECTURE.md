# Private payments architecture — design version 0.1

30 September 2026. Baseline: native/local developer release
`d14165df5476a617bb3048e61bb80b9767722eac`. This note selects a **next design
spike**, not a new consensus version, live-chain migration, implemented shielded
protocol or independently reviewed security boundary.

Keep the tested Protocol 4 line intact. Build application-data confidentiality
now, then evaluate a coherent native shielded successor using Penumbra as the
first architecture reference. The hard question is whether private transfers
can preserve overlapping shared agent budgets and durable uncertain obligations.
Importing a cipher, viewing-key type or proof library cannot answer that question.

## Delivered slice and version boundaries

| Surface | Version/status | Meaning |
| --- | --- | --- |
| P1/P2/P3/P4 native state, signatures, AppHash, budgets and execution | Existing compatibility surfaces | Transparent ledger. No bytes or monetary rules are changed by the invoice module |
| Encrypted invoice content | `1soft/private-invoice/v1`, local module | Description/contact/content confidentiality under an explicit trusted caller key; public request context remains visible |
| This architecture | Design 0.1 | Proposed proof obligations and acceptance gates; no circuits, proving system, private state or on-chain disclosure proof implemented |
| Future native private successor | Protocol number/genesis/circuit versions unassigned | Requires its own exact domains, fresh-genesis or expressly reviewed migration plan, source qualification and external review |

The authoritative present behavior is described by
[the local release](LOCAL_DEVELOPER_RELEASE.md),
[P4 clients](P4_DELIVERY_ENGINE.md) and their current component READMEs.
Earlier static-validator documents explain lineage; their limitations must not be
used to erase the later dynamic-validator implementation. Conversely, later P4
evidence does not qualify an unimplemented private successor.

## Exact source basis and alternatives

The private research bundle is
`C:/Users/Dom/Documents/Codex/2026-09-20/godagents-v2-recovery/outputs/1soft-product-thesis-20260930`.
`PRODUCT_DIRECTION.md`, `REUSE_RECEIPT.md` and
`REPOSITORY_EVIDENCE.json` preserve scope, licenses and failed source lookups.
Selected local excerpt hashes were checked against that manifest for this note.

| Foundation | Inspected source and supported observation | Assessment for 1soft |
| --- | --- | --- |
| Existing P4 plus encrypted application data | Existing native release; reviewed `cryptography` 46.0.4 AESGCM API | Deliverable additive step. Hides invoice text from a ciphertext-only reader; amounts, balances, ledger parties and links remain public |
| Penumbra-style native shielded state — selected next spike | [Keys module](https://github.com/penumbra-zone/penumbra/blob/36a31c17974c23a7e84cc02c64f0062ae57e79b1/crates/core/keys/src/keys.rs) and [full viewing key](https://github.com/penumbra-zone/penumbra/blob/36a31c17974c23a7e84cc02c64f0062ae57e79b1/crates/core/keys/src/keys/fvk.rs) at `36a31c17974c23a7e84cc02c64f0062ae57e79b1` distinguish spending, nullifier, incoming/outgoing and full viewing capabilities | Best first reference for a complete privacy model. Its Rust/group/hash/protocol dependencies are not P4-compatible components. Private grants/shared budgets remain a 1soft design obligation |
| Adopt an entire Penumbra-derived foundation | Same source pin; complete shielded-pool/custody/consensus graph not audited or built here | A separate chain/foundation decision, with asset, consensus, genesis, tooling and economic changes. No inheritance of Penumbra operators, audits or adoption |
| Aztec route | [Pinned Foundation README](https://github.com/AztecProtocol/aztec-packages/blob/3816a35a73f53f3cd12e8b4a8bc662c5f1a2e2e5/README.md), `3816a35a73f53f3cd12e8b4a8bc662c5f1a2e2e5`, identifies prover/circuits/L1 contracts and a separate Labs node/client repository | Alternate settlement architecture, not a native P4 plug-in. Separate Labs code/license/dependency assessment and charter decision would be needed; no client implementation selected |
| Monero-derived foundation | [Crypto interface](https://github.com/monero-project/monero/blob/2f9d1bbb2c553dc75f3335bd1452117dfddd86fa/src/crypto/crypto.h), `2f9d1bbb2c553dc75f3335bd1452117dfddd86fa`, plus README/license in the research receipt | Protocol study or whole-chain strategy only. An interface excerpt does not qualify proof mechanics, private shared budgets, custody or integration |
| Tempo / Cosmos authorization patterns | [Tempo keychain](https://github.com/tempoxyz/tempo/blob/6ef1f812c9ddcbe90a88ada73944012520942d26/crates/precompiles/src/account_keychain/mod.rs), `6ef1f812c9ddcbe90a88ada73944012520942d26`; [Cosmos send authorization](https://github.com/cosmos/cosmos-sdk/blob/72a2df8cdbe5a4d21e4407ad9608300c19e74aaf/x/bank/types/send_authorization.go), `72a2df8cdbe5a4d21e4407ad9608300c19e74aaf` | Patterns for expiry, revocation, limits and recipient controls. Neither establishes private P4 accounting. Cosmos's empty allowlist permits any recipient; Tempo's inspected README calls private tokens a future feature |

Penumbra key excerpt SHA256s are
`85343fff28e46849d32c8cac3dd20383856eb7f0e8fb4432752994e3af119d61`
(`keys.rs`) and
`e4c5495d9d66bb16237b44ec8d92c5231a5ec9c383a9b7388c1b367dd9d7be85`
(`keys/fvk.rs`). The latter imports decaf377, ark serialization, Poseidon and
protocol/key-agreement types: copying the type would not copy its security model.

Penumbra's official [interchain guide](https://guide.penumbra.zone/overview/interchain-privacy)
describes client proving and local scanning rather than public balance RPCs.
Its [disclosure guide](https://guide.penumbra.zone/overview/disclosure) distinguishes
spending authority from viewing and transaction-scoped disclosure. These mutable
guides were read on 30 September 2026; they are explanatory sources, not proof
that every statement applies to the pinned code commit. The complete dependency
graph, circuits, parameter provenance and release advisories remain unassessed.

No third-party protocol implementation is copied into this slice. Penumbra and
Tempo's selected roots provide MIT OR Apache-2.0 evidence; Cosmos and the Aztec
Foundation root provide Apache-2.0 evidence; Monero has BSD-style root evidence.
Per-file/dependency obligations, notices and separate repositories still require
review before integration. The research receipt is not blanket license clearance.

## Privacy target and leakage

The target for a private successor is confidentiality of native transfer values,
balances and shielded counterparties against public ledger observers, with
explicitly limited disclosures. This is a desired property to prove, not a
current feature or a promise of anonymity against every observer.

| Observer | Present invoice slice | Future private-state obligation |
| --- | --- | --- |
| Ledger reader / validator | Sees current native account relationships, units, fees, grants, budgets and receipts | See only defined commitments, nullifiers, proof/public inputs and selected fee/governance data; enumerate any authority-registry linkage |
| Invoice ciphertext reader | Sees genesis/request digest, schema, algorithm, nonce, ciphertext length and existence | Continue to bound linkability and length leakage; encryption alone does not conceal when/where content was handled |
| Merchant / recipient | Sees explicit recipient, amount and information voluntarily shared | Recipient necessarily learns the received payment; invoice/contact and external identity can identify the payer |
| RPC / relay / network observer | No new network route supplied by the module | IP, timing, sync ranges, repeated lookups, broadcast origin, sizes and outages can correlate activity even when amounts are hidden |
| Viewer / accountant | Key holder can decrypt content encrypted with that invoice key | Normal sharing must use transaction/output-scoped disclosure; broad viewing capability has a much larger privacy cost |
| Host / unlocked application | Plaintext and keys exist in trusted process memory | Hardware/isolated custody and device lifecycle remain separate work; hostile OS and complete local rollback are outside this slice |

Penumbra's [action-specific privacy guide](https://guide.penumbra.zone/overview/privacy)
makes public ingress/egress and action leakage explicit. A native private design
must do the same: shielding or withdrawing can expose public value, time and
addresses. Small usage/anonymity sets and recognizable amounts can defeat an
otherwise useful confidentiality boundary. A native private pool does not create
anonymous network transport or an IBC/asset bridge automatically.

## Proposed native private-state model

Use one coherent note/proof/state-transition specification. This proposal draws
on Penumbra's [notes/nullifiers/tree model](https://protocol.penumbra.zone/main/concepts/notes_nullifiers_trees.html),
[nullifier requirements](https://protocol.penumbra.zone/main/sct/nullifiers.html),
[spend description](https://protocol.penumbra.zone/main/shielded_pool/action/spend.html)
and [action conservation](https://protocol.penumbra.zone/main/transactions/invariants.html).
Those are mutable protocol-spec pages, read on the date above. The following
1soft-specific extensions are design hypotheses.

The chain would commit to a note/state tree, consumed nullifiers, versioned
authorization/revocation commitments, receipt identities and validator state.
Wallets would hold note openings, viewing capabilities, witnesses and the exact
signed/proved transaction bytes. A spend must prove membership in an accepted
authenticated root, correct unique nullifier derivation and linkage, and the
required authorization. Invalid proofs or duplicate nullifiers, including
duplicates within one transaction/block, must fail before any monetary effect.

Conservation must be an integer statement with explicit range checks, not only a
field equality susceptible to wraparound. For each supported native asset:
consumed value equals created value plus the native fee transfer under the chosen
unchanged monetary rule. A fee credited to a public fee account is leakage to
state plainly. Shield/unshield must debit one domain and credit the other
atomically, with replay identities and total supply reconciled. Mint/burn or
external backing must not be introduced through a proof-library example.

Public inputs and transcript/signature domains must bind exact successor genesis,
protocol/circuit/parameter versions, asset identifier, accepted root, expiry,
proof commitments, fee, authorization/revocation root and complete transaction.
An administrative/validator proof is never payer consent. Existing Ed25519
signatures cannot silently become another signature type; a new authorization
scheme requires reviewed versioning, custody support and exact consent vectors.

## Private grants and overlapping shared budgets

Preserve the current semantics in [native budgets](NATIVE_BUDGETS.md):
`grant_spent + units + fee <= grant_cap`,
`budget_spent + units + fee <= budget_cap`, and the parent lifetime spending
equals the sum of its linked grants' lifetime spending. Agent limits overlap;
they are not separate escrow allocations. Direct owner spending remains outside
agent-budget ceilings while still consuming real account value.

The selected design spike should evaluate a **single committed private budget
state fragment**, consumed and recreated on every delegated spend alongside the
relevant grant state and value notes. A proof must certify all of the following:

- Grant and budget share the authorized owner/authority epoch, immutable parent
  link and eligible asset; only the owner can create/revoke authority.
- Grant cap/expiry/recipient policy is no broader than the parent. Hidden recipient
  membership must bind the actual output recipient, not a merchant's asserted label.
- Grant and aggregate budget counters include the same exact units plus fee, remain
  in native integer bounds, and cannot decrease, refill or reset on revocation.
- Both state fragments have unique nullifiers and authorized successors.
  A public commitment to a remaining number without state consumption is
  insufficient to prevent concurrent overcommit.
- Current authenticated revocation/epoch/expiry rules apply at ordered execution.
  An agent cannot choose an old root to bypass a later revocation; allowable
  historical value-note anchors and live authority state need different rules.
- No valid transition recreates a consumed cap, swaps parent identity or makes
  two independently spendable copies of the shared budget state.

This preserves overlap by serializing consumption of one parent state. Its
throughput, witness distribution, agent authorization and privacy costs are open.
All supported local grants still use one durable signer/reservation journal.
Across copied journals/devices, competing proofs can target the same budget
fragment; consensus can accept at most one, but rejection does not retrospectively
make the other signed obligation safe to replace.

Public payer/grant/budget IDs or public recipient lists on every payment would
reveal relationships. A confidential design therefore needs committed policy
membership and revocation verification that avoid those stable per-payment IDs,
or must explicitly weaken its privacy claim. That extra proof system is
unimplemented. Disjoint per-agent allowance notes are a plausible simpler
alternative, but change today's overlapping budget semantics and need an explicit
product/protocol decision; they are not a silent optimization.

## Consent, original wires and failure continuity

The trusted local consent view must show actual recipient, exact units, fee,
expiry, grant/budget and disclosure consequences before signing. The private
proof transaction must bind that view. An authenticated invoice is data, not a
merchant signature or proof of payment.

Keep the P4 invariants as conformance requirements for any successor:

1. Preparation neither signs nor reserves. Approval rechecks exact review,
   current authenticated authority and every unresolved local debit under one
   serialized writer transaction before key access and before durable return.
2. Commit exact original signed/proved bytes and reservations before exposing
   them. A failed output or process death recovers those bytes, without new
   signing, re-proving, altered randomness or a replacement payment.
3. Claim one submission attempt durably before key-free I/O. Admission/HTTP
   success and a lost response do not establish execution or permission to retry.
4. Collect authenticated positive execution evidence separately from wallet
   reconciliation. Retain unknown, revoked, expired and conflicting obligations;
   no timeout, missing scan result or grant revocation releases a hold.
5. Authenticate complete relevant validator/state ancestry. Match the original
   wire, signer, proof/receipt identity and executed state transition before
   reconciliation; successful note decryption alone is not an execution receipt.

A proof tied to an expired anchor or a spent note may make an original transfer
unexecutable. The existing default still retains its obligation. Any future
non-execution retirement proof, replacement authorization or cancellation
requires a separate specification and acceptance gate; no convenience
`refresh-and-resend` hook is authorized.

## Trust renewal, indexing and scoped receipts

Validator turnover must not renew trust. Preserve an independently selected
external genesis/policy, fixed deadline and authenticated checkpoint continuity.
Historical retained-byte inspection may remain available after expiry; current
signing, submission, collection and reconciliation require valid current trust.
A renewal design must authenticate a new anchor/policy, fence old devices and
transfer every unresolved obligation without inventing a clean journal or
discarding evidence. Long outages and post-expiry archive verification need
their own threat model. Removing the current 64-block RPC/512-block offline/
16-MiB limits would not solve this.

Private indexing must scan authenticated committed ciphertext/commitment history,
verify roots and replay nullifier/state changes, and build only the wallet's
decrypted view. Persist checkpoint, witness progress and original decisions
atomically with recoverable interruption boundaries. An RPC balance, detection
hint, scan omission or restored index is not authority. Catch-up/pruning must
provide authenticated completeness and retained witness data; losing history
must remain unavailable, not zero balance/unpaid. Bounded incremental/compact
proofs, scan storage and restoration need their own versions and tests.

Separate spend, incoming/outgoing viewing, nullifier derivation and scoped
disclosure capabilities. Ordinary receipts should disclose only the selected
transaction/output and information needed to verify the customer's claim.
Full-viewing-key export can reveal past and future activity; neither a UI revoke
nor later key rotation makes learned plaintext disappear. Today's full-history
P4 capsule remains transparent evidence, not a privacy-preserving receipt.
A new scoped receipt must bind actual execution, public anchor and selected
openings/proofs without exporting unrelated state. Its verifier/trust/expiration
rules must be independently specified and qualified.

## Application-data envelope and caller obligations

`tools/private-payments/src/invoice_privacy.py` implements:

```python
encrypt_invoice(content, *, key, genesis_sha256, request_sha256) -> bytes
decrypt_invoice(envelope, *, key, genesis_sha256, request_sha256) -> dict
validate_envelope(envelope, *, genesis_sha256, request_sha256) -> bytes
```

`key` is exact `bytes` of length 32, supplied by a trusted caller and separate
from every payment key. Content is exactly three UTF-8 strings:
`description` (1,024 bytes), `contact` (512 bytes) and `content` (8,192 bytes).
Description/contact reject control characters. Content permits newline/tab only.
Total canonical plaintext is bounded to 10,000 bytes; the envelope to 14,000 bytes.

Canonical encoding is UTF-8 JSON with sorted keys, no insignificant whitespace,
unescaped Unicode and no NaN/Infinity. Duplicate and unknown fields, wrong exact
types, invalid UTF-8, alternate canonical bytes and noncanonical padded standard
base64 are refused. Digests are exact lowercase 64-character SHA256 text.

AES-256-GCM uses a fresh secure-random 96-bit nonce and the library's full 128-bit
tag. The fixed canonical AAD is exactly
`{algorithm, format, genesis_sha256, request_sha256, schema}`, with
`algorithm="AES-256-GCM"`, `format="1soft/private-invoice/v1"` and integer
`schema=1`. The envelope adds `nonce_b64` and `ciphertext_b64`; the tag is
appended inside the ciphertext. Context is authenticated but visible.
The [versioned AESGCM documentation](https://cryptography.io/en/46.0.4/hazmat/primitives/aead/)
explains nonce reuse and tag-failure behavior. This module provides no configurable
nonce or reuse registry. Test fixtures alone replace the random source.

The caller must calculate `request_sha256` with the existing
`payment_requests.request_id` over the exact canonical unsigned request,
validate its genesis against independent local trust, and retain explicit
recipient/units for consent. The request's public `note` must contain only an
intentionally public label; copying a description/contact there defeats this
slice. Do not publish low-entropy invoice-content hashes as supposed confidentiality.

Persist exact envelope bytes and their request/key association before reporting
retention. Restart retrieves the same envelope; re-encryption changes identity
and is not payment recovery. Module decryption must receive expected trusted
context, rather than learning it from the untrusted envelope. Tag/shape failure
returns a generic `InvoicePrivacyError(ValueError)` and no plaintext.

A key-free catalog may call `validate_envelope` with the trusted genesis/request
digests. It returns the exact canonical envelope bytes after structural, version,
context, nonce, base64 and ciphertext-bound checks. It does not authenticate the
AES-GCM tag, hidden content, sender or payment. A changed but well-shaped
ciphertext can pass this check; only key-based decryption authenticates data.
Decryption and catalog validation share the same structural parser.

The module owns no key generation/storage/distribution, filesystem, signer,
network, payment status or browser route. Parent integration owns the dedicated
invoice-only encrypted software vault and durable book. A browser must never
choose/supply the raw data key. Vault seed, password, plaintext and data key stay
out of command arguments, environment, logs, ledger/request notes and receipts.

Prefer a fresh independent invoice data key per account/security scope, or
per-invoice keys when narrow sharing is required. A single key shared to decrypt
one invoice exposes every ciphertext protected by that key. Track a bounded
encryption count in the caller and rotate well before high-volume use; a proposed
conservative operational cap is at most 2^20 envelopes per key, not an enforced
module or cryptographic certification. Randomness can collide or fail; repeating
a key/nonce pair is unsafe. Retaining a ciphertext does not consume another nonce.

Lost invoice keys/backups mean lost content; there is no decrypt-with-payment-key,
password bypass, automatic reset or recovery service. Keep original ciphertext,
key version and tested protected backup/recovery together. Rotation must retain
old keys until required history is migrated or deliberately abandoned under an
explicit policy. Anyone holding the symmetric key can create authentic envelopes,
so AES-GCM is not merchant non-repudiation. Software vaults and private file
permissions do not protect unlocked memory, hostile OS, full rollback, screenshots,
clipboard/history or voluntarily disclosed plaintext. Python erasure is unqualified.

## Migration and next-spike acceptance

The next spike is a source-pinned design and adversarial transition model, not a
deployment. Its completion condition is a defensible proof-obligation map for
one native transfer, two overlapping grants, revocation, duplicate/concurrent
state consumption, unknown submission, restart and one scoped receipt. A model
using transparent witnesses must be labeled a model; it is not a privacy proof.

| Gate | Required deliverable before promotion |
| --- | --- |
| Foundation / license | Exact complete candidate sources, dependencies, release/advisory/parameter provenance, license and notice map; no ad hoc crypto or consensus collage |
| Semantic preservation | Conformance vectors for P4 conservation, fees, overlap, immutable grant links/epochs, owner control and ordered atomic rejection; explicit approval for any changed rule |
| Cryptographic design | Named proof/signature/encryption system, public/private statements, integer ranges, nullifier uniqueness, live revocation, binding/hiding claims and independent specialist review |
| Native version / state | New exact genesis/domain/circuit/parameter identities and tables/AppHash; reject opening existing P4 DBs under them. Any future live migration must prove supply and pending-obligation continuity |
| Failure and custody | Original-byte persistence, one attempt, retained holds, stale witness, crash/rollback/device-loss and protected key recovery evidence; no raw browser signing/data key |
| Long history / trust | Bounded authenticated compact/incremental receipts, pruning/witness completeness, explicit renewal and post-expiry recovery policy; existing limits unchanged until separately qualified |
| Cost / UX | Measured local proving/verification/scan/restore time and memory on target devices after inspected dependency approval; rendered consent and novice/human tests |
| External operation | Independent cryptographic/custody review, independent operator/network fault qualification, economics/governance and separately authorized public pilot |

A path that can only preserve private budgets by dropping holds, auto-retrying
uncertain payments, giving an agent unrestricted spend authority, resetting
aggregate expenditure or inventing new cryptography fails this spike. Resource
costs are presently unknown; no acquired code was built, no proving benchmark ran,
and no on-chain privacy, anonymity, zero-knowledge receipt, independent review,
public network, production custody or commercial adoption is claimed.

