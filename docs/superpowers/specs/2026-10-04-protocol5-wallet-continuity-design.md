# Protocol 5 wallet continuity design

Date: 4 October 2026
Status: accepted implementation design for a bounded development phase

## Outcome and completion condition

This phase adds a finite, trusted-host wallet for the existing Protocol 5
development chain. The wallet owns one synthetic spending secret, imports explicit
private note openings, constructs real Protocol 5 proofs through controller-only
Rust binaries, submits each approved transaction at most once, and changes wallet
state only from a complete Protocol 5 state authenticated by the signed next-height
CometBFT header.

Completion means two independent wallet workspaces, A and B, execute A-to-B and
then B-to-A spends on the real four-validator Protocol 5 loopback network. Both
wallets survive interruption and cold recovery, preserve exact attempted bytes,
and agree with authenticated chain state. The run also proves that an alternate
randomized proof for the same nullifier is reconciled by its public effects rather
than transaction ID alone.

This phase does not change Protocol 5 genesis, TransactionV1, the fourteen public
fields, Halo2 relation, ProfileDescriptorV1, DeploymentBindingV1, AppHash, ABCI,
validator worker, state sync, or consensus limits. It adds an external caller.
Protocol 4 remains byte-for-byte separate.

## Scope and exclusions

The wallet is for synthetic notes on one trusted POSIX host. It supplies no
production custody, hardware isolation, seed phrase, hostile-host protection,
cross-device coordination, public RPC hardening, automatic recipient discovery,
viewing keys, on-chain ciphertext, network anonymity, metadata resistance,
independent review, scalable note storage, multi-host qualification, public
network, exchange integration, economic value, or real-funds safety.

Protocol 5 transactions contain commitments but no recipient ciphertext or scan
hint. A recipient learns an output only through an explicitly transferred private
`NoteCapsuleV1`. Absence of a capsule is unavailable knowledge, not proof of zero
balance. Capsule transfer is outside consensus and outside this phase's network
protocol. Qualification uses owner-only files on the same trusted host.

Protocol 4 contributes only these conformance requirements: preparation does not
reserve; approval persists exact bytes and a reservation before returning;
submission claims one attempt before I/O; admission is not execution; collection
and reconciliation are distinct; unknown retains its obligation; authenticated
execution precedes expiry; and recovery never silently signs, reproves, retries,
or discards an obligation. No P4 byte, database, wallet, backup, receipt, or
certificate is opened, imported, subclassed, migrated, or reinterpreted.

## Fixed Protocol 5 boundary

The authoritative consensus contract remains
`2026-10-04-shielded-consensus-admission-design.md`. The wallet accepts only
protocol 5, relation/backend/wire version 1, the exact configured canonical
application and engine genesis files with expected SHA-256 values, the genesis
profile/deployment, the immutable four-validator trust anchor, state accepted by
`verify_protocol5_state_certificate`, and the exact measured controller client
and prover binaries selected by the wallet release manifest.

ABCI is never a wallet interface. The wallet uses bounded CometBFT HTTP RPC as
untrusted transport and never connects to an ABCI socket, validator worker,
validator database, private-validator key, or signing state.

Python never implements Poseidon, owner-key derivation, note commitments,
authentication paths, nullifiers, or witness construction. Those remain in the
exact Rust development client. Proof construction remains in the exact Rust
development prover. Secrets enter through bounded stdin only. Successful stdout
contains only the specified binary result and stderr is empty. Failure returns
nonzero, empty stdout, and a bounded non-secret error.

## Authority model

Four authorities remain distinct:

1. External trust configuration supplies exact application genesis, engine
   genesis, expected hashes, and a minimum trusted bootstrap height. RPC cannot
   replace it.
2. Wallet authority is one spend secret plus its durable journal. That journal is
   the sole supported prover and submission caller for its notes.
3. Consensus authority is a signed next-height header from strictly more than
   two-thirds of fixed genesis power. RPC data is untrusted until the complete
   state hashes to that header's AppHash.
4. Capsule possession supplies a candidate opening. It is neither inclusion nor
   ownership. The wallet derives its own owner key, recomputes the commitment in
   Rust, and finds the exact origin in authenticated state before use.

The trusted-host assumption covers the OS user, process memory, kernel,
filesystem, binaries, and operator. A same-user attacker can steal authority.
This phase does not claim resistance to that attacker.

## Controller-only Rust extension

Existing client opcodes 1 and 2 remain byte-for-byte. Two additive version-1
opcodes support the wallet without changing the circuit or ProverRequestV1. All
integers are little-endian and fields are canonical 32-byte Pallas base-field
representations. Requests start `1SFTCLI1 | u16 version=1 | u16 opcode`; the
existing 1,966-byte ceiling remains.

### Opcode 3: DeriveOwnerKeyV1

Exact 44-byte request:

```text
1SFTCLI1 | u16 1 | u16 3 | nonzero spend_secret[32]
```

Exact 42-byte output:

```text
1SFTOWN1 | u16 1 | nonzero owner_key[32]
```

The result is the relation's existing `SpendKey(spend_secret)`. Only this public
owner key may leave the wallet.

### Opcode 4: SpendWithOwnerKeysV1

This has the existing Spend layout, except outputs contain public owner keys:

```text
1SFTCLI1 | u16 1 | u16 5
| genesis_sha256[32] | deployment_id[32]
| SpendHeaderV1[8 x 32]
| u16 commitment_count | commitments[commitment_count x 32]
| u16 input_position
| InputNoteV1
| PublicOutputNoteV1[2]

InputNoteV1 =
  u64 expiry | u64 value | spend_secret[32] | note_secret[32] | blinding[32]

PublicOutputNoteV1 =
  u64 expiry | u64 value | owner_key[32] | note_secret[32] | blinding[32]
```

Length is `672 + 32 * commitment_count`, 704 through 1,120 bytes. Output is the
unchanged exact 1,010-byte ProverRequestV1. The client reconstructs the input,
path, fourteen public fields and outputs, then runs existing native relation
checks. It rejects invalid count/position, zero values/owner keys, noncanonical
fields, trailing bytes, bad balance/expiry, zero/equal outputs, or identity drift.

`development_client.rs` is outside the descriptor's frozen circuit-source list.
Implementation must still prove the descriptor, KAT, worker, worker profile
response, DeploymentBindingV1, genesis, and ProverRequest bytes remain identical.
The new client hash and freshly measured prover hash belong to a wallet release
manifest and wallet database. Any mismatch is fatal before authority opens.

## Canonical formats

JSON uses existing P5 canonical rules: ASCII, sorted keys, no whitespace, floats,
duplicate or unknown members. Hex is lowercase. Integers are bounded JSON
integers. Identities hash complete canonical bytes.

### NoteCapsuleV1

The closed object has exactly:

```json
{
  "blinding":"canonical_nonzero_field_hex",
  "capsule_id":"lowercase_64_hex",
  "commitment":"canonical_field_hex",
  "deployment_id":"lowercase_64_hex",
  "expiry":512,
  "format":"1soft/protocol5-note-capsule/v1",
  "genesis_sha256":"lowercase_64_hex",
  "note_secret":"canonical_nonzero_field_hex",
  "origin":{"kind":"transaction","output_index":0,"txid":"lowercase_64_hex"},
  "owner_key":"canonical_nonzero_field_hex",
  "profile_id":"lowercase_64_hex",
  "value":20,
  "version":1
}
```

Origin is exactly one closed variant:

```json
{"kind":"genesis","position":0}
{"kind":"transaction","output_index":0,"txid":"lowercase_64_hex"}
```

Genesis position is 0..15; output index is 0 or 1; value and expiry are
1..`u64::MAX`. Capsule ID is:

```text
SHA-256("1soft/protocol5-note-capsule-id/v1\0" ||
        canonical_json(capsule without capsule_id))
```

The ceiling is 2,048 bytes. A capsule is sensitive spendable note material and is
created new mode 0600 in an owner-only directory. It never appears in argv,
environment, URL, stdout, report, log, validator artifact, snapshot, or receipt.
It contains no spend secret and provides no sender authentication by itself.

For genesis, certified state must contain the commitment at the exact initial
position. For a transaction, certified state must contain the named successful
receipt; its named output and position, and the retained transaction, must match.
The wallet's opcode-3 owner key and an existing opcode-1 one-note commitment recomputation must match before admission.

### SpendReviewV1

Preparation creates no secret, proof, reservation, obligation, or I/O. Its closed
review is:

```json
{
  "anchor_root":"canonical_field_hex",
  "change_value":75,
  "checkpoint_app_hash":"lowercase_64_hex",
  "checkpoint_height":20,
  "fee":5,
  "format":"1soft/protocol5-wallet-review/v1",
  "input_capsule_id":"lowercase_64_hex",
  "input_expiry":512,
  "input_value":100,
  "payment_value":20,
  "recipient_owner_key":"canonical_nonzero_field_hex",
  "review_id":"lowercase_64_hex",
  "valid_from":21,
  "valid_until":53,
  "version":1,
  "wallet_id":"lowercase_64_hex",
  "wallet_revision":7
}
```

Review ID is SHA-256 over
`1soft/protocol5-wallet-review-id/v1\0` plus the canonical object without its
ID. Fee equals genesis fee; change equals input minus payment minus fee and is
positive. Outputs inherit input expiry. Valid-from is checkpoint height plus one.
Valid-until is at least checkpoint plus three and at most input expiry and
`max_height`. Any revision/checkpoint change supersedes it. Approval repeats the
exact recipient, amounts, fee and validity. Ceiling is 4,096 bytes.

### WalletRecoveryV1

The private canonical JSON has exactly these top-level keys:

```text
format, version, recovery_id, wallet_meta, wallet_secret, checkpoint,
notes, reviews, obligations, attempts, outgoing_capsules
```

Format is `1soft/protocol5-wallet-recovery/v1`, version 1. Arrays sort by binary
primary key. Every member is the exact closed logical row projection of the schema
below: BLOBs are canonical padded RFC-4648 base64, u64le BLOBs become JSON
integers, and nullable columns become JSON null. Checkpoint contains parsed state
and signed-header objects plus their exact canonical bytes in base64; re-encoding
must match.

Recovery ID hashes domain `1soft/protocol5-wallet-recovery-id/v1\0` and the
document without its ID. Ceiling is 16 MiB. It is plaintext synthetic authority,
created new mode 0600, never overwritten. There is no password, encryption, cloud
upload, key escrow, reset, or production recovery claim.

Restore requires separately supplied trusted genesis files/hashes, verifies every
row and the saved H+1 certificate into a fresh workspace, and opens
`recovery_required`. Signing, proving, submission, export, and reconciliation
remain disabled until a live certificate at or above the saved height installs.
Lower or conflicting same-height state is fatal.

## Filesystem and process boundary

Workspace is a new owned POSIX directory mode 0700. Database, lock, WAL, SHM,
capsules, and recovery files are regular owned non-symlink files mode 0600.
Existing parents from filesystem root are checked against the no-symlink and
ownership policy. Creation refuses an existing database. One nonblocking exclusive
`.lock` covers all operations.

SQLite uses WAL, `synchronous=FULL`, foreign keys, trusted schema off, defensive
mode when available, and `BEGIN IMMEDIATE` for authority changes. A successful
transaction receives its durability barrier before useful success is returned.
Memory advances only after commit.

Client and prover are opened no-follow, checked for file type, owner, mode and
hash, then launched from the measured inode with minimal environment. Stdin write
and stdout read share a deadline. Wrong length, stderr on success, trailing bytes,
timeout, signal, nonzero exit, path replacement, or output mismatch is fatal for
the operation with no partial authority retained.

## Exact SQLite schema

Database has `PRAGMA user_version=1` and exactly these tables/indexes, with no
triggers, views, virtual tables, unknown objects or columns. Startup audits
normalized `sqlite_master` SQL, `table_info`, foreign keys and indexes; it
never repairs drift. `u64le` is an exact eight-byte little-endian BLOB.

```sql
CREATE TABLE wallet_meta(
 singleton INTEGER PRIMARY KEY CHECK(singleton=1),
 schema_version INTEGER NOT NULL CHECK(schema_version=1),
 wallet_id BLOB NOT NULL UNIQUE CHECK(length(wallet_id)=32),
 genesis_sha256 BLOB NOT NULL CHECK(length(genesis_sha256)=32),
 engine_genesis_sha256 BLOB NOT NULL CHECK(length(engine_genesis_sha256)=32),
 profile_id BLOB NOT NULL CHECK(length(profile_id)=32),
 deployment_id BLOB NOT NULL CHECK(length(deployment_id)=32),
 client_sha256 BLOB NOT NULL CHECK(length(client_sha256)=32),
 prover_sha256 BLOB NOT NULL CHECK(length(prover_sha256)=32),
 source_commit TEXT NOT NULL CHECK(length(source_commit)=40),
 source_tree TEXT NOT NULL CHECK(length(source_tree)=40),
 revision INTEGER NOT NULL CHECK(revision>=0),
 mode TEXT NOT NULL CHECK(mode IN ('active','recovery_required','fatal'))
) STRICT;

CREATE TABLE wallet_secret(
 singleton INTEGER PRIMARY KEY CHECK(singleton=1),
 spend_secret BLOB NOT NULL CHECK(length(spend_secret)=32),
 owner_key BLOB NOT NULL UNIQUE CHECK(length(owner_key)=32)
) STRICT;

CREATE TABLE checkpoint(
 singleton INTEGER PRIMARY KEY CHECK(singleton=1),
 state_height INTEGER NOT NULL CHECK(state_height BETWEEN 0 AND 511),
 app_hash BLOB NOT NULL CHECK(length(app_hash)=32),
 header_height INTEGER NOT NULL CHECK(header_height=state_height+1),
 header_hash BLOB NOT NULL CHECK(length(header_hash)=32),
 state_json BLOB NOT NULL,
 signed_header_json BLOB NOT NULL,
 installed_revision INTEGER NOT NULL CHECK(installed_revision>=0)
) STRICT;

CREATE TABLE notes(
 capsule_id BLOB PRIMARY KEY CHECK(length(capsule_id)=32),
 capsule_json BLOB NOT NULL,
 commitment BLOB NOT NULL UNIQUE CHECK(length(commitment)=32),
 owner_key BLOB NOT NULL CHECK(length(owner_key)=32),
 expiry_u64le BLOB NOT NULL CHECK(length(expiry_u64le)=8),
 value_u64le BLOB NOT NULL CHECK(length(value_u64le)=8),
 note_secret BLOB NOT NULL CHECK(length(note_secret)=32),
 blinding BLOB NOT NULL CHECK(length(blinding)=32),
 origin_kind TEXT NOT NULL CHECK(origin_kind IN ('genesis','transaction')),
 origin_position INTEGER,
 origin_txid BLOB,
 origin_output_index INTEGER,
 chain_position INTEGER,
 state TEXT NOT NULL CHECK(state IN ('unconfirmed','spendable','reserved','spent','expired')),
 reserved_by BLOB,
 admitted_revision INTEGER NOT NULL CHECK(admitted_revision>=0),
 CHECK((origin_kind='genesis' AND origin_position BETWEEN 0 AND 15 AND
        origin_txid IS NULL AND origin_output_index IS NULL) OR
       (origin_kind='transaction' AND origin_position IS NULL AND
        length(origin_txid)=32 AND origin_output_index IN (0,1))),
 CHECK(chain_position IS NULL OR chain_position BETWEEN 0 AND 15),
 CHECK(reserved_by IS NULL OR length(reserved_by)=32)
) STRICT;

CREATE TABLE reviews(
 review_id BLOB PRIMARY KEY CHECK(length(review_id)=32),
 review_json BLOB NOT NULL,
 base_revision INTEGER NOT NULL CHECK(base_revision>=0),
 checkpoint_height INTEGER NOT NULL CHECK(checkpoint_height BETWEEN 0 AND 511),
 input_capsule_id BLOB NOT NULL CHECK(length(input_capsule_id)=32),
 state TEXT NOT NULL CHECK(state IN ('open','superseded','approved')),
 FOREIGN KEY(input_capsule_id) REFERENCES notes(capsule_id)
) STRICT;

CREATE TABLE obligations(
 obligation_id BLOB PRIMARY KEY CHECK(length(obligation_id)=32),
 review_id BLOB NOT NULL UNIQUE CHECK(length(review_id)=32),
 input_capsule_id BLOB NOT NULL CHECK(length(input_capsule_id)=32),
 input_nullifier BLOB NOT NULL CHECK(length(input_nullifier)=32),
 expected_txid BLOB NOT NULL UNIQUE CHECK(length(expected_txid)=32),
 prover_request_sha256 BLOB NOT NULL CHECK(length(prover_request_sha256)=32),
 transaction_bytes BLOB NOT NULL,
 payment_capsule_json BLOB NOT NULL,
 change_capsule_json BLOB NOT NULL,
 valid_until INTEGER NOT NULL CHECK(valid_until BETWEEN 1 AND 512),
 state TEXT NOT NULL CHECK(state IN ('ready','attempt_claimed',
   'executed_exact','executed_equivalent','conflicting_spend',
   'expired_unexecuted')),
 winning_txid BLOB,
 resolved_height INTEGER,
 created_revision INTEGER NOT NULL CHECK(created_revision>=0),
 resolved_revision INTEGER,
 FOREIGN KEY(review_id) REFERENCES reviews(review_id),
 FOREIGN KEY(input_capsule_id) REFERENCES notes(capsule_id),
 CHECK(winning_txid IS NULL OR length(winning_txid)=32),
 CHECK((resolved_height IS NULL AND resolved_revision IS NULL) OR
       (resolved_height BETWEEN 1 AND 511 AND resolved_revision>=0))
) STRICT;

CREATE TABLE attempts(
 obligation_id BLOB PRIMARY KEY CHECK(length(obligation_id)=32),
 claimed_revision INTEGER NOT NULL CHECK(claimed_revision>=0),
 outcome TEXT NOT NULL CHECK(outcome IN ('claimed','rpc_returned','transport_failed')),
 response_json BLOB,
 response_sha256 BLOB,
 FOREIGN KEY(obligation_id) REFERENCES obligations(obligation_id),
 CHECK((response_json IS NULL AND response_sha256 IS NULL) OR
       (response_json IS NOT NULL AND length(response_sha256)=32))
) STRICT;

CREATE TABLE outgoing_capsules(
 obligation_id BLOB NOT NULL CHECK(length(obligation_id)=32),
 output_index INTEGER NOT NULL CHECK(output_index IN (0,1)),
 capsule_json BLOB NOT NULL,
 exported INTEGER NOT NULL CHECK(exported IN (0,1)),
 export_revision INTEGER,
 PRIMARY KEY(obligation_id,output_index),
 FOREIGN KEY(obligation_id) REFERENCES obligations(obligation_id),
 CHECK((exported=0 AND export_revision IS NULL) OR
       (exported=1 AND export_revision>=0))
) STRICT;

CREATE UNIQUE INDEX notes_reserved_by_unique
 ON notes(reserved_by) WHERE reserved_by IS NOT NULL;
CREATE INDEX obligations_nullifier_index ON obligations(input_nullifier);
CREATE INDEX obligations_state_index ON obligations(state);
```

`wallet_id = SHA-256("1soft/protocol5-wallet-id/v1\0" || genesis_sha256 ||
owner_key)`. `obligation_id = SHA-256("1soft/protocol5-obligation-id/v1\0" ||
wallet_id || review_id || expected_txid)`. Transaction bytes are bounded by
genesis `max_tx_bytes` and decode exactly. All redundant columns are recomputed
on every open.

## Authenticated checkpoint installation

Sync is exact:

1. Fetch `/abci_query?path="/state"&height=0&prove=false` from configured
   loopback RPC under a 12 MiB response bound.
2. Require successful ABCI response, empty proof operations, canonical base64,
   and at most 8 MiB decoded canonical witness JSON.
3. Parse the closed `{genesis,height,app_hash,state}` and require the configured
   genesis, profile, deployment, chain and closed state schema.
4. Fetch the signed header at `height+1`, bounded to 256 KiB. Missing H+1 is
   unavailable, never success.
5. Reconstruct trust only from configured genesis files and call
   `verify_protocol5_state_certificate`.
6. Validate retained transactions, receipts, roots, commitments, nullifiers,
   positions, counters and transaction identities used by the wallet. Other P5
   query paths are hints only.
7. Refuse lower height. Same height accepts only byte-identical witness and header;
   conflict sets mode `fatal`. Higher state supersedes open reviews and
   recomputes every note and obligation.
8. Commit checkpoint, classifications, revision and supersession atomically.

The certificate is authenticated as-of state, not global freshness. Bootstrap also
requires externally configured minimum height; later state cannot fall below the
high-water mark.

State 512 cannot have required header 513. Wallet validity uses the exclusive
`valid_until <= max_height`. Certified state at `valid_until-1` covers every
eligible block, so state 512 is never installed or needed.

## State machines

### Notes

`unconfirmed` is a retained opening without certified origin. `spendable`
means local owner key, recomputed commitment, origin/position, nullifier absence,
expiry margin and no reservation all pass. `reserved` belongs to one
nonterminal obligation. `spent` has a certified nullifier. `expired` cannot
form the wallet's future validity window.

A new review requires a spendable note and
`checkpoint_height + 3 <= min(expiry,max_height)`. The wallet reports
authenticated available, reserved, spent and unconfirmed values separately. It
never calls their sum a latest public balance.

### Review and approval

Preparation selects one note only, deterministically by lowest chain position then
capsule ID. Output 0 is payment; output 1 is change to the wallet owner key. Both
inherit input expiry.

Approval reopens one exact review in `BEGIN IMMEDIATE`, requires unchanged
revision/checkpoint and repeated facts, generates independent nonzero output
secrets/blindings from OS CSPRNG, invokes opcode 4, validates all ProverRequest
fields, invokes the exact prover, and decodes TransactionV1. It requires exact
genesis, deployment, public fields, proof length, nullifier, outputs, fee and txid.

One commit inserts the obligation, ProverRequest SHA-256, exact transaction,
two unexported capsules and input reservation; approves the review and increments
the revision. Crash before commit leaves nothing; crash after commit recovers
identical transaction bytes. The raw ProverRequest is wiped after proving and is
never persisted. Return values exclude witnesses and note secrets.

Approval is the point of no return for the input reservation. There is no
cancellation or release merely because the transaction has not been submitted;
the exact proved bytes may already have escaped through a lost response or
recovery path. Only authenticated execution, a conflicting spend, or certified
post-validity absence resolves the obligation.

### Exact one-attempt submission

Submission from `ready` inserts the sole attempt and commits
`attempt_claimed` before RPC. It sends the exact stored transaction once.
No later path sends it again. Timeout, disconnect, HTTP error, malformed response,
or nonzero CheckTx changes only the attempt observation; obligation remains
`attempt_claimed`. There is no automatic retry, alternate endpoint, reproving,
replacement or refresh-and-resend.

### Certified reconciliation and precedence

For every higher certificate:

1. Decode stored transaction/public fields.
2. Find the unique successful receipt for its input nullifier in complete state,
   then decode the winning retained transaction at the receipt height/index.
   Missing, duplicate or inconsistent relations are fatal.
3. Exact winning bytes produce `executed_exact`.
4. Different bytes with all fourteen identical public fields produce
   `executed_equivalent`; randomized proof and txid may differ.
5. Same nullifier with different public fields produces `conflicting_spend`.
   The input is spent, intended payment is not successful, and expected capsules
   are never exportable.
6. With no winner, `certified_height + 1 >= valid_until` produces
   `expired_unexecuted` and releases input for a new review.
7. Otherwise preserve state and reservation.

Winning execution precedes expiry. Txid query, CheckTx, broadcast result, timeout,
clock, capsule import and absence from an uncertified response never decide.

Exact/equivalent execution recreates transaction-origin capsules with winning
txid. Change is admitted internally. Payment becomes exportable once. Lost export
response may reproduce byte-identical capsule at a fresh path; chain state does not
change.

## Startup and cold recovery

Startup acquires lock, audits files/schema, verifies stored hashes/IDs, rederives
owner key, reparses all canonical objects and exact binary requests, verifies saved
H+1 certificate, and recomputes classifications from full saved state. Any change
or impossible transition sets `fatal` and exposes no signing/submission.

Recovery export checkpoints SQLite, reads one transactionally consistent snapshot,
constructs/self-verifies WalletRecoveryV1 and writes create-new. Restore targets a
new empty workspace, never merges or overwrites. Duplicate restore creates a clone
with the same authority; each clone is `recovery_required` until explicit operator
selection and equal/newer live certification. This local flag does not fence the
other clone.

## Resource ceilings

| Resource | Ceiling |
|---|---:|
| owner keys | 1 |
| notes | 16 |
| reviews / open reviews | 64 / 8 |
| obligations / attempts | 64 / 64 |
| outgoing capsules | 128 |
| NoteCapsuleV1 / SpendReviewV1 | 2 KiB / 4 KiB |
| decoded state witness / signed header | 8 MiB / 256 KiB |
| complete RPC / broadcast response | 12 MiB / 64 KiB |
| WalletRecoveryV1 | 16 MiB |
| SQLite main / main plus sidecars | 32 MiB / 64 MiB |
| client request/output | 1,966 / 1,010 bytes |
| transaction | genesis max, never above 64 KiB |
| client / prover / RPC watchdog | 30 / 300 / 15 seconds |

No operation trims authority/history to fit. A ceiling refuses before secret
access, proving, I/O or mutation as applicable. Watchdogs are local availability
controls and never establish chain result.

## Failure precedence

1. Unsafe storage, second writer, schema/corruption or source/binary drift: fatal.
2. Invalid trust/certificate: no mutation; same-height conflict is fatal.
3. Client/prover failure before durable approval: no obligation/reservation.
4. SQLite failure: rollback and retain prior memory.
5. Durable obligation without attempt: recover exact bytes; retain the reservation.
6. Durable attempt: never resend regardless of transport result.
7. Certified winner: exact, equivalent or conflicting execution.
8. Certified validity end with no winner: expired unexecuted.
9. Everything else: unavailable/unknown with obligation retained.

## Real four-validator acceptance matrix

The runner uses pinned CometBFT 0.38.25, four existing P5 apps/workers, unchanged
profile/deployment and fresh synthetic genesis, plus two wallet processes and
measured client/prover. RPC remains loopback and ABCI private. The strict report
and checker require each row separately:

| Area | Detecting requirement |
|---|---|
| Source | commit/tree, P5 identities, genesis, engine/worker/client/prover hashes, wallet manifest and schemas match |
| Preservation | descriptor, KAT, worker/deployment, TransactionV1, P5 consensus/state-sync, P4 and historical benchmark stay passing |
| Owners | A/B derive independent public keys; neither side nor any validator artifact sees the other's secret |
| Genesis | A imports exact genesis capsule; B reports unavailable rather than inferred zero |
| Review | A reviews 20 from 100, fee 5, change 75; checkpoint/revision change invalidates it |
| Approval faults | before commit leaves nothing; after commit recovers identical request, txid, nullifier, outputs and capsules |
| Attempt | durable before RPC; lost response, timeout and nonzero CheckTx each make one attempt and no resend |
| A to B | real proof commits; H+1 certificate authenticates receipt/output; capsule exports only afterward |
| Import hostility | wrong owner/secret/blinding/commitment/txid/index/profile/deployment/genesis and uncommitted capsule fail |
| B spend | B spends 7, fee 5, change 8 back to A; certificate authenticates and A imports returned note |
| Exact | exact winner yields executed_exact and admitted change |
| Equivalent | randomized winner with same fourteen fields yields executed_equivalent by nullifier/effects |
| Conflict | same nullifier with different outputs yields conflicting_spend, no payment success/export |
| Expiry | absence through certified valid_until-1 yields expired_unexecuted; winner takes precedence |
| Certificates | altered state/receipt/tx/AppHash/header/signature/validator/chain/height, rollback and fork cause no authority mutation |
| Capsules | malformed/noncanonical/oversized/duplicate/wrong-position/spent capsules never become available |
| Storage | symlink/mode/owner/lock/schema/object/type corruption and write faults preserve prior state |
| Restart | every lifecycle boundary preserves rows and performs no implicit network call |
| Recovery | fresh restore verifies saved certificate, refuses rollback/fork, activates only on equal/newer state, and reproduces notes/obligations/attempts |
| Clone | two restores remain recovery-required; evidence makes no fencing claim |
| Leakage | secrets, capsules and ProverRequest absent from public output, argv, env, URLs, validator homes, app DBs, snapshots, receipts and logs |
| Convergence | four validators agree; A/B projections match authenticated history; negative evidence retained |

Failed reports/private artifacts are preserved without overwrite. The runner owns
all processes and actual exit codes. The checker rejects missing, skipped,
umbrella, unassessed, dirty-source, identity-drifted or overclaiming results.

## Test-first order

1. Freeze existing P5 artifacts/vectors; add failing opcode tests.
2. Implement opcodes 3-4 and prove consensus artifacts byte-identical.
3. Add strict capsule/review/recovery parsers and mutations.
4. Add hardened storage/schema audit, checkpoint install and restart audit.
5. Add note import/classification and certificate hostility tests.
6. Add prepare/approval atomic persistence and fault injection.
7. Add attempt claim/transport no-retry tests.
8. Add nullifier precedence, equivalent/conflict/expiry, export and cold recovery.
9. Run the real A-to-B-to-spend matrix and bind a strict wallet checker.
10. Rerun P5 consensus/state sync, P4 preservation, historical Halo2 benchmark and
    complete release gate.

Fixtures cover parser/fault paths only. Exact Rust binaries and the real
four-validator runner alone establish proof, execution, certificate and recovery
qualification.

## Evidence boundary

Passing establishes a source-bound finite trusted-host synthetic-note wallet for
one explicit recipient workflow, durable one-attempt continuity, authenticated
reconciliation and cold restore. It does not establish production privacy or
custody, automatic scanning, safe capsule transport, multi-device authority,
independent review, anonymity, scalable storage, demand, public deployment or
real-funds readiness. All such claims remain false.
