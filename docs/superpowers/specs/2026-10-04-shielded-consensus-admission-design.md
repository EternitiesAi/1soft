# Shielded consensus admission design

Date: 4 October 2026

Status: approved implementation specification for a fresh, finite development chain. This design does not modify Protocol 4, deploy a public network, handle real funds, establish production privacy, select production custody, or claim independent cryptographic review.

## Objective

Turn the qualified benchmark semantics into a newly identified and freshly qualified Halo2 consensus rule on a new application version. Four local CometBFT validators must admit actual proofs, order nullifiers and output commitments globally, commit an authenticated note-tree history, recover exactly after process interruption, and state-sync a fresh node by replaying the same verifier.

The application is Protocol 5 with a fresh genesis. Existing Protocol 4 source, state bytes, AppHash, snapshots, evidence, and network behavior remain byte-stable. The first Protocol 5 chain is intentionally finite: its depth-four note tree has sixteen leaves, exactly two outputs are appended per successful spend, and genesis allocates only a small set of synthetic development notes. It is a consensus and recovery qualifier, not a scalable payment pool.

## Architectural boundary

The implementation has three layers with one definition of the Protocol 5 cryptographic relation:

1. A dedicated Rust shielded-chain profile owns the new consensus circuit, canonical public statement, Poseidon note tree, deterministic parameters and verifying key, proof verification, development-only proving, and all runtime Poseidon operations.
2. A verifier-only Rust worker exposes the pinned profile, tree-root calculation, and proof-plus-append transition to the Python application over a bounded inherited pipe.
3. A new Python Protocol 5 application owns CometBFT lifecycle, deterministic transaction ordering, global uniqueness, SQLite durability, queries, receipts, and state sync. Python stores canonical field bytes and treats Rust-returned Poseidon roots as the consensus result; it does not reimplement Poseidon.

The existing Halo2 benchmark relation remains historically intact under circuit ID 1soft/privacy-proof-benchmark/halo2-pasta/v1. Its height/expiry meaning, verifying-key identity, receipts, and evidence may not be reinterpreted as Protocol 5 evidence. The new relation is 1soft/shielded-consensus/halo2-pasta/v1 in a separate component. Source may be adapted from the benchmark, but only the shielded-chain crate defines the Protocol 5 circuit. The new profile receives its own K, proof-size, verifying-key, mutation, and performance qualification.

The application may reuse unchanged generic transport and safety helpers: the bounded ABCI server, the pinned CometBFT 0.38.25 protobuf subset, strict canonical JSON loading, StoreLock, transaction byte accounting, fixed validator-set parsing, and state-sync result constants. It must not subclass or mutate Protocol4Application, reuse the Protocol 4 AppHash or snapshot format, reuse the transparent SHA-256 state tree, or import the shielded-note lab's Ed25519 authorization and witness model.

## Frozen versions and limits

The first chain freezes these independent versions:

| Domain | Value |
| --- | --- |
| CometBFT application | 5 |
| shielded transaction wire | 1 |
| Protocol 5 Halo2 relation | 1 in the new shielded-consensus namespace |
| profile descriptor | 1 |
| deployment binding | 1 |
| verifier worker protocol | 1 |
| state-sync format | 1 |
| circuit power | K = 13; the new circuit must freshly fit this bound or implementation stops for a design amendment |
| note-tree depth | 4 |
| note-tree capacity | 16 commitments |
| outputs per accepted transaction | exactly 2 |
| proof backend | Zcash Halo2 IPA over the Pasta cycle |
| transcript | Blake2b, as pinned by halo2_proofs 0.4.0 |
| hash gadget | Poseidon P128Pow5T3 |
| validators | exactly 4 fixed genesis validators |

Immutable protocol hard ceilings are: chain ID 64 ASCII bytes; four validators; power 1 through 1,000,000 per validator and 4,000,000 total; height 512; eight transactions per block; sixty-four proposal candidates; 4 MiB proposal inspection; 64 KiB transaction; 60 KiB proof; 512 KiB protobuf transaction data per block; 2 MiB FinalizeBlock request wire; sixty-four retained transaction entries and 2 MiB retained raw transaction-wire bytes across the chain; u64 maximum fee total; 8 MiB snapshot payload; 64 KiB snapshot chunks; 128 chunks; 1 MiB worker frame; 120-second worker startup; and 30-second worker request watchdog. Genesis may select only equal or smaller values and fixes the newly measured exact proof length. Every arithmetic total has an explicit unsigned bound. The finite note-tree capacity is a consensus rule, not a default that operators may raise.

If genesis contains g initial commitments, it must satisfy:

maximum_accepted_transactions <= floor((16 - g) / 2)

Genesis validation also proves that g is at most sixteen; every commitment is canonical, unique, and nonzero; max_accepted_transactions is at most max_history_transactions; exact proof length is at most max_proof_bytes; 534 plus exact proof length is at most max_tx_bytes; the largest VerifyAndAppendV1 request is at most max_worker_frame_bytes; fixed fee multiplied by max_accepted_transactions is at most max_fee_total and max_fee_total is at most u64::MAX; the maximum root-history and receipt counts fit the state and snapshot limits; and a deterministically constructed maximum-shape canonical state and snapshot fit the selected history, payload, and chunk bounds.

## Genesis and verifier identity

Genesis is strict canonical JSON with exactly these members:

- chain_id: 1 through 64 printable ASCII bytes;
- protocol_version: integer 5;
- profile_descriptor: canonical padded standard-base64 ProfileDescriptorV1 bytes;
- profile_id: lowercase 64-hex domain-separated profile identity;
- deployment_binding: canonical padded standard-base64 DeploymentBindingV1 bytes;
- deployment_id: lowercase 64-hex domain-separated deployment identity;
- genesis_field, asset_field, context_field, and policy_field: canonical field hex;
- authority_epoch: positive u64;
- fee: positive u64;
- validators: four entries {"public_key":lowercase_64_hex,"power":positive_integer}, with equal powers and sorted lexicographically by public-key bytes;
- initial_commitments: ordered canonical field-hex list;
- limits: a closed object containing max_height, max_accepted_transactions, max_txs_per_block, max_candidates, max_candidate_inspect_bytes, max_tx_bytes, max_proof_bytes, max_block_bytes, max_finalize_request_bytes, max_history_transactions, max_history_tx_bytes, max_snapshot_bytes, snapshot_chunk_bytes, max_snapshot_chunks, max_worker_frame_bytes, max_total_voting_power, max_fee_total, worker_startup_timeout_seconds, and worker_request_timeout_seconds.

The hashes must match the decoded descriptor and binding bytes. Validator keys are unique, nonzero Ed25519 encodings. Unknown members are rejected.

ProfileDescriptorV1 binds the cryptographic behavior:

- backend and new relation identity;
- circuit ID, K, depth, public-input count and ordered names;
- curve, commitment scheme, transcript, and Poseidon identity;
- parameter derivation and parameter hash;
- circuit-source, Cargo.lock, profile-manifest, and public-schema hashes;
- exact proof-byte length;
- pinned verifying-key binding;
- KatV1 SHA-256.

DeploymentBindingV1 binds one executable deployment:

- exact ProfileDescriptorV1 hash;
- worker-protocol version;
- verifier-worker binary SHA-256;
- Rust toolchain-manifest SHA-256;
- post-initialization sandbox-policy SHA-256.

The binary encodings deliberately separate cryptographic identity from executable identity. The worker never embeds or reports a hash of itself. The parent measures the worker file and constructs DeploymentBindingV1 externally.

Halo2 0.4.0 exposes no portable verifying-key serialization. The pinned verifying-key binding is version-bound and cannot support a cross-platform reproducibility claim. Any incompatible circuit, parameter, key, dependency, toolchain, worker, or sandbox-policy change creates a different identity and requires a fresh genesis.

KatV1 is a profile-level fixture, not a live TransactionV1. It contains magic 1SFTKAT1, u16 version 1, exactly fourteen canonical public-instance fields using a fixed synthetic test genesis field, u32 proof length, exact proof bytes, u8 expected status 0 Ok, u32 proof-relative mutation offset, and u8 nonzero XOR mask. The mutation offset must lie inside the proof. It contains no live genesis hash or deployment hash. ProfileDescriptorV1 binds SHA-256("1soft/shielded-kat/v1\0" || exact_kat_bytes). Startup requires the original to verify and the prescribed mutation to return InvalidProof. This construction has no field that depends recursively on its own hash.

The public live genesis field is:

H2F("genesis", canonical_json(genesis with only the genesis_field member removed))

ProfileDescriptorV1, DeploymentBindingV1, limits, validators, commitments, and all other genesis fields remain in that projection. After the derived field is inserted and validated, SHA-256 is computed over the final canonical genesis bytes. That digest is not stored inside the genesis document. It is bound in every transaction header, committed database checkpoint, and AppHash.

At startup, the parent opens the worker with no symlink following, verifies safe ownership and mode, hashes that open file, records its device/inode, and launches that same open inode through a passed /proc/self/fd handle. It refuses path replacement, broad write permission, or identity drift. The worker returns its exact ProfileDescriptorV1 bytes. The parent requires its domain-separated hash and bytes to match genesis, constructs DeploymentBindingV1 from measured artifacts and requires exact agreement with genesis, checks the external KatV1 file hash, verifies the KatV1 proof through VerifyProofV1, verifies that mutation of the frozen proof-byte offset returns InvalidProof, and refuses to start if any identity or observation differs.

## Normative encodings

All fixed integers use little-endian encoding. All strings in binary identities are length-prefixed ASCII and reject non-ASCII, embedded NUL, overlong, or alternate forms. Every binary document has a unique eight-byte magic, explicit version, fixed field order, exact lengths, complete consumption, and no trailing bytes.

ProfileDescriptorV1 is:

- magic 1SFTPFD1;
- u16 descriptor version;
- u16 backend ID;
- u32 relation version;
- u16 K, u16 depth, u16 public-input count;
- u32 exact proof length;
- u16 circuit-ID byte length and exact ASCII circuit ID;
- nine ordered 32-byte hashes: parameter, verifying-key binding, circuit source, Cargo.lock, profile manifest, public schema, KatV1, curve/commitment identity, and transcript/Poseidon identity.

Its identity is SHA-256("1soft/shielded-profile/v1\0" || exact_profile_descriptor_bytes).

DeploymentBindingV1 is:

- magic 1SFTDEP1;
- u16 binding version;
- u16 worker-protocol version;
- 32-byte ProfileDescriptorV1 identity;
- 32-byte worker binary SHA-256;
- 32-byte toolchain-manifest SHA-256;
- 32-byte sandbox-policy SHA-256.

Its identity is SHA-256("1soft/shielded-deployment/v1\0" || exact_deployment_binding_bytes).

Canonical JSON is exactly the ASCII bytes produced by json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False). Every canonical input boundary requires encode(parse(raw)) == raw and rejects duplicate keys, floats, exponent syntax, negative zero, non-integer numeric forms, alternate whitespace, alternate key order, alternate Unicode escapes, and strings containing non-scalar Unicode values.

A JSON field value is lowercase hexadecimal of the exact 32 little-endian to_repr bytes. It is not conventional big-endian integer hex. The Pallas base-field modulus, interpreted as a conventional integer, is:

0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001

Python canonical-field validation requires int.from_bytes(raw32, "little") < modulus and exact 32-byte round trip. Rust independently uses from_repr and to_repr.

Opaque identifiers map to fields only through:

H2F(label, payload) =
int.from_bytes(
  SHA-512(
    "1soft/shielded-field/v1\0" ||
    u16le(label_length) || label ||
    u32le(payload_length) || payload
  ),
  "little"
) mod PALLAS_BASE_MODULUS

The Rust from_uniform_bytes implementation and the independent Python arithmetic must match frozen vectors, including zero, one, modulus-minus-one, modulus rejection, and multi-byte labels and payloads.

## Public statement and circuit relation

The new circuit ID is 1soft/shielded-consensus/halo2-pasta/v1. The ordered public instance vector has exactly fourteen Pallas base-field elements:

1. relation version;
2. genesis field;
3. asset field;
4. context field;
5. authority epoch;
6. valid-from height;
7. valid-until height;
8. policy field;
9. accepted anchor root;
10. nullifier;
11. output commitment 0;
12. output commitment 1;
13. fee;
14. authorization digest.

The profile publishes golden vectors for all fourteen positions. Relation version, epoch, heights, expiries, values, and fee are independently range-checked to unsigned 64 bits.

The authorization digest is Poseidon P128Pow5T3 over domain field 105 followed by public inputs 1 through 13 in order. It binds the complete public statement; it is not a MAC or signature. Possession of the hidden spend secret and satisfaction of the circuit relation remain the authorization boundary.

The circuit proves valid_from < valid_until without field-wrap comparison. It range-checks a 64-bit witness equal to valid_until - valid_from - 1. It requires the hidden input-note expiry and both hidden output-note expiries to be at least valid_until by range-checking each 64-bit difference note_expiry - valid_until. Tests cover equality, valid_until equal to u64::MAX, each endpoint boundary, and attempted field-wrap witnesses.

Consensus admits the proof only when valid_from <= candidate_block_height < valid_until. This permits bounded propagation without letting a wallet choose the block height after proving.

The remaining relation is:

- one hidden input and exactly two positive hidden outputs;
- exact input = output0 + output1 + fee conservation with bounded values;
- hidden spend-key derivation;
- an input commitment shared with the output commitment formula;
- depth-four membership under the public historical anchor root;
- a position-bound nullifier;
- input commitment, output commitment 0, and output commitment 1 each algebraically nonzero;
- distinct output commitments;
- public authorization binding.

The nonzero constraints exist in the circuit as well as in genesis and consensus validation. An empty tree leaf can never be opened as a spendable note.

The prior benchmark's height/expiry circuit, K, key, proof size, and receipts do not qualify this relation. Protocol 5 must newly qualify K = 13, exact proof length, parameters, verifying-key binding, KatV1, valid and invalid proofs, range boundaries, nonzero commitments, and performance before genesis is frozen.

## Canonical transaction and witness wires

Consensus transactions use one fixed binary envelope. JSON is used for genesis, committed state, receipts, and evidence, but never for the transaction wire.

TransactionV1 is:

- magic 1SFTSHD1;
- u16 wire version, equal to 1;
- u16 backend ID, equal to 1 for Halo2/Pasta;
- u32 relation version, equal to 1;
- 32-byte canonical genesis-document SHA-256;
- 32-byte DeploymentBindingV1 identity;
- u16 instance count, equal to 14;
- fourteen canonical 32-byte public field elements;
- u32 proof length;
- exact proof bytes.

The decoder requires the genesis-fixed proof length, protocol hard ceiling, genesis transaction bound, complete consumption, and no trailing bytes. It rejects alternate encodings before proof verification. The transaction ID is:

SHA-256("1soft/shielded-txid/v1\0" || exact_transaction_bytes)

WitnessV1 is accepted only by the development prover:

- magic 1SFTWIT1;
- u16 witness version and u32 relation version;
- u16 input position;
- u64 input value and u64 input expiry;
- 32-byte input blinding, spend secret, and note secret;
- four ordered 32-byte authentication-path fields;
- u64 output value 0 and output value 1;
- u64 output expiry 0 and output expiry 1;
- 32-byte output recipient-key field 0 and field 1;
- 32-byte output note secret 0 and note secret 1;
- 32-byte output blinding 0 and blinding 1.

Every 32-byte witness field is a canonical Pallas field element. Position must be below sixteen. The document is exactly 480 bytes and rejects trailing bytes. Witness bytes are never accepted by ABCI, persisted in the application database, emitted in logs or receipts, included in snapshots, or sent to the verifier-only worker. Validator processes cannot invoke the development prover.

## Verifier worker and failure semantics

The Rust verifier runs as one long-lived single-threaded child per application process over inherited stdin/stdout. It is built without Halo2 multicore or prover features. It loads and constructs the pinned parameters and verifying key, closes every file descriptor except the framed input and output, applies no_new_privs, installs the pinned x86_64 Linux seccomp policy denying open/openat/openat2/creat, socket/connect/bind/listen/accept/accept4, execve/execveat, fork/vfork/clone/clone3, and io_uring_setup, and performs post-sandbox probes. Startup fails unless a seeded-file open and socket creation both return the expected denial and stdout has emitted only complete protocol frames. The deployment binding commits the exact sandbox policy. Non-Linux or unenforced execution is outside this chain profile.

Each frame begins with a u32 byte length that excludes the prefix and is bounded by the profile hard ceiling.

WorkerRequestV1 is:

- magic 1SFTVRQ1;
- u16 worker-protocol version;
- u16 opcode;
- nonzero u64 request ID;
- 32-byte ProfileDescriptorV1 identity;
- u32 payload length;
- exact payload.

WorkerResponseV1 is:

- magic 1SFTVRS1;
- u16 worker-protocol version;
- u16 echoed opcode;
- echoed u64 request ID;
- echoed 32-byte profile identity;
- u16 status;
- u32 payload length;
- exact payload.

Opcodes are 1 Profile, 2 TreeRootV1, 3 VerifyAndAppendV1, and 4 VerifyProofV1. Statuses are 0 Ok, 1 InvalidStatement, 2 InvalidProof, and 65535 InternalFailure. Any other value is a fatal protocol error. Request IDs increase by one and the parent must restart cleanly before u64 exhaustion; wrapping is forbidden.

Profile has an empty request payload and returns exact ProfileDescriptorV1 bytes.

TreeRootV1 request payload is u16 commitment count followed by zero through sixteen canonical commitments. Its Ok response is one canonical 32-byte root.

VerifyProofV1 request payload is fourteen canonical public fields, u32 proof length, and exact proof bytes. The worker recomputes the authorization digest, checks the public relation fields, and performs actual Halo2 verification. It is used for KatV1 and direct proof-boundary tests.

VerifyAndAppendV1 request payload is u16 current commitment count, the complete ordered canonical commitment vector, fourteen canonical public fields, u32 proof length, and exact proof bytes. The worker performs the same statement and proof verification, recomputes root_before, appends output 0 then output 1, and returns root_before, root_after, u16 output position 0, and u16 output position 1.

The parent requires root_before to equal stored current root and positions to equal the current count and current count + 1. It then calls TreeRootV1 on the appended vector and requires exact equality with root_after. Any mismatched Rust-returned root or position is fatal internal divergence.

InvalidStatement maps only to deterministic result code 8 when the current committed state supplied to the worker has already passed its audit. InvalidProof maps to code 9. A TreeRootV1 refusal, InternalFailure, child death, timeout, EOF, truncated or oversized frame, request-ID or profile mismatch, malformed response, unsolicited bytes, or failed sandbox probe raises VerifierUnavailable.

VerifierUnavailable produces no ABCI transaction result. The active callback fails locally, no pending state is retained, the child is quarantined, and the application exits or refuses every later callback until an exact clean restart. A wall-clock timeout is solely a node-local watchdog and never influences a consensus result code. Committed state remains unchanged.

The process boundary amortizes key construction while containing Rust panics and ABI risk. The development prover is a different binary and is never reachable from the worker protocol.

## Append-only note tree

The Protocol 5 Rust profile and pinned worker define the sole Poseidon tree implementation:

- zero is a reserved invalid note commitment;
- an empty leaf is Poseidon(domain 101, zero);
- a present leaf is Poseidon(domain 101, commitment);
- each branch is Poseidon(domain 102, left, right);
- empty roots for levels zero through four are frozen as golden vectors;
- genesis commitments are unique, canonical, nonzero, and appended in listed order;
- each accepted transaction appends output 0 and then output 1.

Python stores the ordered canonical commitments and worker-returned root. InitChain, every accepted transition, restart audit, and state-sync replay call TreeRootV1 and require equality with the stored root. Consensus never deletes or rewrites leaves. Output positions are deterministic. An accepted transaction requires at least two remaining positions. Global output uniqueness is checked against all committed commitments and earlier accepted transactions in the same block.

The accepted-root set is frozen at block start. A transaction may anchor to any authenticated committed historical root retained by the chain, including the current committed root. A root created by an earlier transaction in the candidate block is not eligible until commit. Nullifier and output uniqueness, capacity, and fee totals still advance sequentially within the block.

This permits two independent notes under one earlier root to spend in the same block while forbidding same-block output chaining. The finite chain retains every committed root; no pruning policy exists in this phase.

## Deterministic admission and errors

One evaluator is used by CheckTx, proposal callbacks, FinalizeBlock, startup replay, and state-sync replay. Transaction-local checks occur in this order:

1. per-transaction hard and genesis byte bounds;
2. envelope shape, canonical fields, exact proof length, and complete consumption;
3. wire, backend, relation, genesis SHA, deployment identity, and public version/genesis/asset/context/policy/epoch equality;
4. 64-bit public numeric bounds and exact fixed fee;
5. valid_from < valid_until and valid_from <= candidate height < valid_until;
6. membership of the anchor in the immutable block-start committed-root set;
7. nullifier freshness against committed and earlier same-block state;
8. nonzero, distinct, globally fresh output commitments;
9. remaining tree capacity, accepted-transaction count, and bounded fee-total arithmetic;
10. VerifyAndAppendV1, mapping InvalidStatement to code 8 and InvalidProof to code 9;
11. Rust root/position cross-check, deterministic receipt construction, and closed-state audit.

The closed transaction results are:

| Code | Fixed log | Exact cause |
| --- | --- | --- |
| 0 | empty | accepted; data is lowercase transaction ID |
| 1 | malformed shielded transaction | transaction bytes fail canonical parsing |
| 2 | shielded transaction identity differs | header identity or public version/domain/epoch differs from genesis |
| 3 | shielded validity window differs | interval is malformed or candidate height is outside it |
| 4 | unknown shielded anchor root | anchor is absent from the block-start root set |
| 5 | shielded nullifier already spent | nullifier is committed or already accepted in this block |
| 6 | invalid shielded output commitment | output is zero, equal to its sibling, or already present/accepted |
| 7 | shielded development capacity exceeded | note, accepted-transaction, or bounded fee-total capacity would be exceeded |
| 8 | invalid shielded public statement | public numeric/fee rule or worker statement check fails |
| 9 | invalid shielded proof | actual Halo2 verification fails |

Each result is exactly {"code": integer, "log": fixed ASCII string, "data": ASCII string}. Failure data is empty. No result echoes untrusted input.

Block-container invalidity is separate: wrong callback height, non-byte transaction entries, excess count, aggregate retained-history count or raw-wire bytes beyond the remaining bound, excess framed byte size, invalid CometBFT context, or excess request wire aborts or rejects the whole callback according to ABCI method. It is never assigned to an arbitrary transaction. History counters include every raw transaction retained in execution_blocks, successful or rejected.

Database, lock, worker availability, canonical-state serialization, impossible root/position response, and internal state invariant failures are fatal exceptions. There is no transaction code for corrupted durable state or implementation failure.

## InitChain and CometBFT lifecycle

InitChain requires exact canonical genesis bytes, matching chain ID, protocol version 5, initial_height equal to 1, and exactly the four genesis public keys and powers. It rejects duplicate or zero keys, nonpositive or excessive power, wrong order-independent roster, changed app-state bytes, and any total above the protocol hard ceiling. It returns no validator updates and returns the independently golden-tested genesis AppHash. The four genesis validators must have equal power.

Protocol hard ceilings cap validators, total voting power, height, candidates, transactions, transaction bytes, block bytes, proof bytes, snapshot bytes, chunks, and replay work. Genesis may choose only equal or smaller limits.

CheckTx evaluates one transaction against committed state at height + 1 and never reserves a nullifier or output. It returns code 7 if retaining that wire would exceed the committed global history count or raw-byte budget. Different randomized proofs for the same note may independently pass. A verifier failure aborts the callback without a transaction result.

PrepareProposal considers at most the hard candidate count and inspection-byte ceiling. It processes candidates in order on one isolated copy of committed state and the immutable block-start root set. Byte accounting uses the exact protobuf transaction_data_size and min(request.max_tx_bytes, genesis block-byte limit). It stops before the returned proposal would exceed the remaining global history count or raw-wire byte budget, filters transaction-local rejections, and returns only transactions accepted sequentially.

ProcessProposal first rejects a proposal whose complete retained raw transaction set would exceed either remaining history budget. It then independently replays the ordered proposal from committed state and rejects if any transaction is nonzero or the fixed next-validator hash differs.

At height 1, FinalizeBlock requires an empty decided-last-commit. At every later height it requires one row for each genesis validator address with its exact power, accepts only block-ID flags 1 Absent, 2 Commit, and 3 Nil, and requires Commit-flag power multiplied by three to be strictly greater than total genesis power multiplied by two. Only flag 2 contributes voting power.

FinalizeBlock requires the request next_validators_hash to equal the immutable genesis validator hash at every height, including height 1. Before transaction execution or pending-state creation it also requires that retaining the complete decided block stays within the remaining global history count and raw-wire byte budgets.

It hashes the exact bounded deterministic protobuf request submessage supplied by the dispatcher as:

SHA-256("1soft/shielded-finalize-request/v1\0" || exact_request_wire)

It also binds the 32-byte block hash. It replays transactions deterministically and stages the result. Defensive handling remains deterministic if an invalid transaction appears despite ProcessProposal: it receives its fixed nonzero result, mutates nothing, consumes its retained-history count and raw-wire bytes, and valid siblings may continue. Verifier failure aborts with no pending state.

Repeating the exact memory-pending request returns the exact pending response. A pre-commit restart discards memory-only pending state and reexecutes an exact repeated request. Repeating an already committed request with matching block hash and request digest returns retained exact response bytes. A conflict at the same height fails closed.

Commit writes committed genesis, height, AppHash and state; block hash; finalization request digest; raw transaction wires; exact results and response bytes; replay history; and snapshot-marker cleanup in one BEGIN IMMEDIATE SQLite transaction. Only after SQLite COMMIT succeeds does in-memory state advance. Pre-commit faults roll back. Process exit after durable commit is recovered from retained bytes. Commit with no pending finalization is a successful no-op, covering a lost Commit reply.

The validator set is immutable. Protocol 5 emits no validator updates.

## Authenticated state, results, and queries

The closed state JSON schema is exactly:

- version: integer 1;
- profile_id: lowercase 64-hex ProfileDescriptorV1 identity;
- deployment_id: lowercase 64-hex DeploymentBindingV1 identity;
- commitments: ordered list of canonical field hex;
- current_root: canonical field hex;
- root_history: ordered closed-variant entries;
- spent_nullifiers: lexicographically byte-sorted unique canonical field hex;
- fee_total: integer from zero through genesis max_fee_total;
- accepted_transaction_count: integer equal to the number of successful receipts and at most max_accepted_transactions;
- history_transaction_count: number of all raw wires retained in execution_blocks;
- history_transaction_bytes: sum of len(raw_wire) for all retained transactions;
- execution_blocks: one ordered entry for every height;
- receipts: successful receipts in execution order.

A genesis root-history entry is exactly {"kind":"genesis","height":0,"tx_index":0,"root":field_hex} and contains no transaction ID. An ordinary entry is exactly {"kind":"transaction","height":positive_integer,"tx_index":zero_based_integer,"txid":lowercase_64_hex,"root":field_hex}. The all-zero transaction ID is prohibited for ordinary entries.

Each execution block is exactly {"height":integer,"transactions":[canonical_base64_wires],"results":[ExecTxResult_objects]}. Base64 is RFC 4648 standard alphabet with padding and must round-trip exactly. Transaction and result list lengths match. These records are application execution history, not fabricated CometBFT block hashes, votes, request wires, or FinalizeBlock responses.

Every successful receipt is exactly:

- txid, profile_id, and deployment_id as lowercase 64-hex;
- height and zero-based tx_index as integers;
- anchor_root, tree_root_before, tree_root_after, nullifier, output_commitment_0, and output_commitment_1 as canonical field hex;
- output_position_0 and output_position_1 as integers;
- fee as a bounded integer.

Anchor root is the historical root proven by the spend; tree_root_before is the latest sequential append root. They may differ.

AppHash is:

SHA-256(
  "1soft/shielded-development/apphash/v1\0" ||
  canonical_json({
    "genesis_sha256": exact_genesis_sha256,
    "height": committed_height,
    "state": closed_state
  })
)

The retained finalization record is exactly {"height":integer,"app_hash":lowercase_64_hex,"tx_results":[ExecTxResult_objects],"validator_updates":[],"last_commit_votes":[closed vote objects]}. Height-one votes are empty. Later vote objects contain only lowercase address hex, positive power, and block_id_flag. Deterministic ResponseFinalizeBlock protobuf bytes contain the 32-byte AppHash, ordered ExecTxResults, no events, no gas values, and no validator updates; each nonzero result uses codespace one-shielded-development and success uses an empty codespace.

Golden vectors freeze empty/genesis state and AppHash, one accepted transaction, a defensive block with rejected and accepted siblings, root-history JSON, receipt JSON, base64 transaction storage, CheckTx response, retained finalization JSON, and deterministic FinalizeBlock response bytes.

State audit replays every execution block from genesis through the real worker and recomputes commitments, each root, nullifiers, fees, accepted count, retained-history count and raw bytes, transaction IDs, results, receipts, and AppHash. TreeRootV1 must equal stored current root at genesis, every append, restart, and state sync.

Queries require empty request data, prove=false, and height equal to zero or current committed height. They expose /info, /state, /root-history, /tx/<lowercase txid>, /nullifier/<canonical little-endian field hex>, and /block/<height>. The block query returns only the AppHash-committed execution_blocks projection. It is not a historical CometBFT response. Invalid path, data, proof request, or historical query context returns a fixed error.

Query projections are not Merkle proofs. The signed next-height CometBFT header authenticates the AppHash produced by the prior Commit. The nullifier query returns the winning transaction ID and receipt so a wallet can reconcile a consumed note even if it regenerated different randomized proof bytes.

## Restart and hostile boundaries

On open, the application obtains the store lock; validates database path, sidecars, schema, expected genesis, worker, profile, deployment, sandbox, and KatV1; loads one committed checkpoint; replays execution history through the real worker; audits state and AppHash; and validates every locally present exact block-response row.

A normal local checkpoint at positive height requires an exact response row for the current height. A snapshot-only checkpoint instead requires a marker exactly matching committed genesis, deployment, height, AppHash, and payload hash, with no block-response rows. After the first ordinary post-sync commit, the new current-height response row is authoritative and the snapshot marker is deleted; older historical response rows remain absent and are never invented.

The application refuses missing or extra execution history, altered transaction/proof/root/nullifier/output/fee/receipt/result bytes, inconsistent response rows, changed genesis or profile, partial snapshot state, unsafe storage, and a second writer.

Fault tests cover exit before SQLite commit, exit immediately after commit, worker death or stall after several successes, truncated or mismatched worker response, corrupted state/history/response rows, wrong worker binary or profile, changed genesis, and callback retry. Failure leaves committed state and pending finalization unchanged unless SQLite Commit had already completed.

## State sync

Protocol 5 uses domain 1soft/shielded-development/state-sync/v1 and snapshot format 1. Protocol 4 snapshots are rejected.

The bounded canonical payload contains exactly genesis, height, AppHash, and closed state. The state's execution_blocks are the ordered transaction-only replay history from which database history rows are derived. The payload contains no CometBFT block hash, votes, FinalizeBlock request identity, exact historical response, or locally observed process data. Metadata binds format, profile ID, deployment ID, genesis digest, height, AppHash, payload bytes, chunk bytes, chunk count, and domain-separated payload SHA-256.

A recipient has an externally pinned expected genesis, DeploymentBindingV1, worker, and trusted AppHash supplied through CometBFT's light-client path. Before installation it:

1. parses canonical bounded payload and metadata;
2. validates expected genesis, profile, deployment, worker sandbox, and KatV1;
3. replays every retained execution block from genesis through VerifyAndAppendV1 and TreeRootV1;
4. reproduces transaction results, roots, global nullifiers, outputs, receipts, fees, state, and AppHash;
5. requires equality with the light-client-supplied AppHash;
6. atomically installs committed state, history rows derived from execution_blocks, and a state-sync marker;
7. installs no historical block-response rows;
8. exposes state only after SQLite Commit.

An uninitialized store may install. A marker-only store may recover only when it has no block-response rows and its committed checkpoint matches the marker. A same-height offer is eligible only when genesis, profile, deployment, height, AppHash, and payload hash are byte-identical to the marker. A different same-height fork is rejected. A strictly newer offer requires its own externally trusted AppHash and may atomically replace the marker checkpoint. Older height is rejected.

Partial chunks are process-local. An identical duplicate chunk returns Accept without adding bytes. A conflicting duplicate rejects the snapshot. An out-of-order future chunk returns Retry with the exact next index. Sender identity is bounded diagnostic input, not a trust root; changing sender does not alter the outcome for identical authenticated chunks. A short nonfinal chunk, excess bytes, corrupt final chunk, or payload/hash mismatch rejects the snapshot.

After successful installation, the process retains one bounded completed-offer record so an exact duplicate final chunk returns Accept and a conflicting duplicate rejects. After process restart that volatile record is absent; a final chunk without an active offer returns Abort, and the pinned CometBFT 0.38.25 recovery path must re-offer the snapshot. The durable marker then admits only the byte-identical same-height offer. The real state-sync gate must observe and record this call sequence rather than assume it.

The first ordinary post-sync Commit inserts its actual current-height block-response row and deletes the marker. Startup thereafter audits that real row and the complete transaction history; it does not require or invent response rows for pre-sync heights.

State sync establishes replay to a light-client-authenticated AppHash. It does not prove the external light-client input or fabricate historical CometBFT evidence.

## Four-validator and recovery qualification

The real-engine gate owns one exact CometBFT 0.38.25 binary, four exact verifier binaries with equal hashes, four fresh equal-power validator homes, four distinct databases and worker processes, private Unix sockets, synthetic notes, and no public RPC or real funds. The controller records source commit/tree, canonical genesis, profile and deployment identities, binary hashes, process identities, bounded logs, databases, and cleanup.

A passing run must demonstrate:

1. InitChain enforcement and the same independently computed genesis AppHash on all four validators.
2. A real proof commits and all four app/worker pairs record verification; all validators expose identical state, AppHash, root, nullifier, receipt, and output positions.
3. Two randomized valid proofs for one note independently pass CheckTx; sequential PrepareProposal keeps only the first; a manually conflicting proposal is rejected by ProcessProposal.
4. Exact replay and a different valid proof for the consumed note are refused after commit.
5. Repeated nullifiers and repeated output commitments are refused both within one block and across blocks, using valid proofs where the relation permits.
6. Two distinct notes under one historical root spend in one block and append sequentially.
7. A chained proof anchored to a root created earlier in the same candidate block is refused there and becomes eligible only in the next block after that root commits.
8. Unknown and tampered roots are refused without pending or durable mutation.
9. Actual proofs are tested at valid_from, valid_until - 1, and valid_until; only the first two heights are eligible.
10. The signed next-height header binds the prior committed Protocol 5 AppHash.
11. One worker is killed and one bounded stall is induced after successful requests; that validator produces no pending/durable mutation, restarts with the exact worker, catches up, and converges.
12. One application exits before SQLite Commit and one exits immediately after; exact replay recovers the correct single effect and retained response.
13. One application and engine restart normally against the same database/home and rejoin.
14. Four equal powers are recorded and the harness proves arithmetically that three powers times three exceed total power times two before stopping one validator.
15. The chain advances with one validator stopped and all live validators converge exactly.
16. A same-block produced root, duplicate output, changed statement, mutated proof, wrong profile, wrong deployment, and wrong next-validator hash each produce the specified rejection or fatal boundary without pending or durable mutation.
17. Every worker passes the post-sandbox file-open and socket-denial probes and stdout-frame audit.
18. No witness bytes, secret fields, or development-prover path appear in validator arguments, databases, logs, snapshots, or receipts.

The separate state-sync gate uses the four source validators plus a never-started nonvalidator. It requires exact replay and marker/AppHash equality, no historical response rows, continued execution after install, preserved nullifier/root/receipt history, same-store restart, exact duplicate-final-chunk handling, observed re-offer recovery after lost final Apply reply, rollback refusal, and source/target state equality.

Through the real ABCI caller it also exercises wrong genesis, profile, deployment, and trusted AppHash; altered proof; removed nullifier; changed root history; duplicate, out-of-order, conflicting, and corrupt chunks; same-height different AppHash/payload; newer trusted recovery; local disk failure; and restart during partial transfer.

Reports preserve all negative observations. Passing remains one-host development evidence.

## Test-first sequence

Implementation proceeds in detecting slices:

1. Preserve the existing benchmark relation ID, source behavior, verifying-key evidence, and complete tests byte-for-byte; record the clean Phase 7 baseline and the noninteractive 196-test wallet correction.
2. Add failing Rust and Python golden tests for field bytes, little-endian H2F, fourteen public slots, canonical JSON, ProfileDescriptorV1, DeploymentBindingV1, KatV1, TransactionV1, WitnessV1, worker frames, receipts, closed state, and AppHash. Include a construction test proving no identity depends on its own hash.
3. Implement the new shielded-consensus circuit with range-safe validity intervals and algebraic nonzero input/output commitments. Newly qualify K, proof length, parameters, key, KatV1, positive proof, mutations, boundary witnesses, and old-versus-new profile separation.
4. Freeze Poseidon empty roots, genesis roots, append transitions, capacity, and output positions in the new Rust profile.
5. Build the verifier worker and attack Profile, TreeRootV1, VerifyProofV1, and VerifyAndAppendV1 framing, status precedence, request-ID exhaustion, concurrency serialization, malformed/oversized input, wrong profile, invalid proof, wrong returned root/position, child death, timeout, truncation, unsolicited output, and seccomp probes.
6. Build the strict Python transaction/genesis parser and InitChain contract. Prove canonical round trips, hard ceilings, arithmetic consistency, roster/power checks, and exact genesis AppHash.
7. Implement the pure consensus evaluator. Test block-start root freezing, same-root independent spends, nullifier/output uniqueness in both scopes, validity boundaries, physical and genesis-selected accepted capacity, fees, exact accepted/history counters, deterministic results/receipts, Rust root equality, and failed-state invariance.
8. Implement proposal/finalization lifecycle and atomic persistence. Test exact protobuf byte accounting, an exact remaining history budget, one-over-limit ProcessProposal and FinalizeBlock with no pending/durable change, rejected finalized siblings consuming retained history, speculative CheckTx, conflicting proposal and wrong next-validator-hash rejection, height-one and later vote rules, pending replay, no-op Commit, retained response replay, conflicting finalization, and fault injection around SQLite Commit.
9. Implement the ABCI adapter, private server, query contracts, restart audit, storage hostility, and worker quarantine.
10. Implement marker-only state sync and every offer/chunk/install/re-offer outcome, including same-height fork refusal and real-verifier replay.
11. Run the exact four-validator, liveness, worker-loss, commit-interruption, state-sync, and final-Apply recovery gates.
12. Register the new component and scenario validators in the current release gate; rerun the new Rust suite, old Halo2 benchmark, Protocol 4 compatibility, complete Python/JavaScript gate, and exact-source engine scenarios.

Every implementation slice starts with a failing test that detects the absent behavior. Golden-vector tests use independent implementations where practical. Existing checks may not be weakened, bypassed, deleted, renamed out of discovery, or reclassified merely to obtain a pass.

## Evidence boundary

A successful Phase 7 establishes actual local Halo2 verification in consensus, deterministic shared ordering of nullifiers and output commitments, authenticated committed root history, atomic restart behavior, and bounded state-sync replay for one fresh finite development chain.

It still does not establish:

- production cryptographic safety or independent review;
- a scalable note commitment tree or pruning design;
- wallet scanning, viewing keys, recovery, or user-grade private payments;
- network-layer anonymity or resistance to timing and metadata analysis;
- production key custody, hardware signing, or side-channel resistance;
- reproducible cross-platform verifier builds;
- multi-host Byzantine fault behavior;
- public-network, exchange, market, economic, or real-funds readiness.

The current depth-four tree, synthetic allocations, one-host validators, retained full history, exact worker binary binding, and development prover are deliberate limits. Production privacy, network anonymity, production custody, independent review, public network, exchange readiness, and real funds remain false.
