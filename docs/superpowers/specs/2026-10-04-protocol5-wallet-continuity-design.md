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

Existing client opcodes 1 and 2 remain byte-for-byte. Three additive version-1
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
1SFTKEY1 | u16 1 | nonzero owner_key[32]
```

The result is the relation's existing `SpendKey(spend_secret)`. Only this public
owner key may leave the wallet.

### Opcode 4: SpendWithOwnerKeysV1

This has the existing Spend layout, except outputs contain public owner keys:

```text
1SFTCLI1 | u16 1 | u16 4
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

### Opcode 5: DeriveNoteNullifierV1

This bounded operation derives the relation's position-bound nullifier without
constructing a future spend. It is required for valid low-value, expired, and
final-capacity notes that cannot satisfy opcode 4's spend shape.

Exact 270-byte request:

```text
1SFTCLI1 | u16 1 | u16 5
| relation_field[32] | genesis_field[32] | asset_field[32]
| context_field[32] | authority_epoch_field[32]
| u16 input_position
| nonzero input_commitment[32]
| nonzero spend_secret[32]
| nonzero note_secret[32]
```

Exact 42-byte output:

```text
1SFTNUL1 | u16 1 | nonzero nullifier[32]
```

Position is 0 through 15. The Rust client calls the existing relation nullifier
function; Python performs no hash or field arithmetic. It rejects zero,
noncanonical, overbound, or trailing input and consumes the request exactly.

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

### Exact transaction recovery

An approved decision durably stores its canonical review, input lineage,
ProverRequest SHA-256, exact TransactionV1 bytes, payment capsule, and change
capsule in one authority row. `recover(decision_id)` returns those exact
transaction bytes without invoking the client or prover. This is the recovery
boundary for this stage.

No wallet-clone export, password wrapping, cloud backup, device migration, or
hostile-host rollback-resistance claim is made. Those require a separate design
with clone fencing and key custody rather than an implicit extension of the
local journal.

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
and stdout/stderr reads share one elapsed deadline: 30 seconds for the client and
300 seconds for the prover. Capture is bounded while the process runs rather than
after it exits. Wrong length, stderr on success, trailing bytes, timeout, signal,
nonzero exit, path replacement, or output mismatch is fatal for the operation
with no partial authority retained.

The local CLI takes explicit wallet, application-genesis, engine-genesis, and
expected-digest arguments on every command. Commands that can invoke Rust also
take explicit client/prover paths and trusted SHA-256 values, and validate both
executables before opening the wallet or accepting secret input. Structural
owner-key lookup, review preparation, exact recovery, and delivery inspection do
not require either executable. `status()` and the commands that derive or verify
cryptographic facts keep the full controller audit.

Secret-bearing command values use closed canonical JSON envelopes read only from
a nonterminal stdin stream or an owned regular one-link mode-0600 file in an
owned private directory. Public review values may be emitted as canonical JSON.
Recovered TransactionV1 and released NoteCapsuleV1 bytes are created only at a
new exclusive no-follow mode-0600 output. Ordinary refusals return no private
value, no exception or path, and no reflected argument token.

Approval can commit before its randomized decision ID reaches the caller. The
controller-free continuity projection therefore exposes bounded public
`decision_id`, `review_id`, txid, and state tuples. Recovery accepts either the
decision ID or the unique review ID known before approval, so a process lost
after commit can reopen and recover the identical transaction with the client
and prover unavailable.

## Exact SQLite schema

The wallet database has application ID `0x31503557`, user version 1, and exactly
four `STRICT` tables: `config`, `observations`, `notes`, and `decisions`.
Reviews are mutation-free values until approval. Approval persists the reviewed
facts, exact proved transaction, and both private output capsules in one
`decisions` row. Delivery attempts live in the separate delivery journal.

`config` contains the fixed external identities, one spend secret and owner key,
a monotonic revision, exact row counts, and an authority digest over every
authority-bearing cell. Every mutation increments the revision and reseals the
counts and digest in the same transaction. Startup compares exact
`sqlite_master.sql`, rejects every extra table/index/view/trigger, runs
`quick_check` and `foreign_key_check`, and never repairs drift.

```sql
CREATE TABLE config(
 id INTEGER PRIMARY KEY CHECK(id=1),
 version INTEGER NOT NULL CHECK(version=1),
 wallet_id TEXT NOT NULL UNIQUE,
 genesis_sha256 TEXT NOT NULL,
 engine_genesis_sha256 TEXT NOT NULL,
 profile_id TEXT NOT NULL,
 deployment_id TEXT NOT NULL,
 spend_secret BLOB NOT NULL CHECK(length(spend_secret)=32),
 owner_key BLOB NOT NULL CHECK(length(owner_key)=32),
 revision INTEGER NOT NULL CHECK(revision>=0),
 created_ns INTEGER NOT NULL CHECK(created_ns>=0),
 observation_count INTEGER NOT NULL CHECK(observation_count BETWEEN 0 AND 32),
 note_count INTEGER NOT NULL CHECK(note_count BETWEEN 0 AND 16),
 decision_count INTEGER NOT NULL CHECK(decision_count BETWEEN 0 AND 16),
 authority_digest TEXT NOT NULL CHECK(length(authority_digest)=64)
) STRICT;

CREATE TABLE observations(
 seq INTEGER PRIMARY KEY,
 observation_id TEXT NOT NULL UNIQUE,
 height INTEGER NOT NULL UNIQUE CHECK(height BETWEEN 0 AND 511),
 payload BLOB NOT NULL
) STRICT;

CREATE TABLE notes(
 capsule_id TEXT PRIMARY KEY,
 payload BLOB NOT NULL,
 nullifier BLOB NOT NULL CHECK(length(nullifier)=32),
 chain_position INTEGER NOT NULL CHECK(chain_position BETWEEN 0 AND 15),
 imported_revision INTEGER NOT NULL CHECK(imported_revision>=0)
) STRICT;

CREATE TABLE decisions(
 decision_id TEXT PRIMARY KEY,
 review_id TEXT NOT NULL UNIQUE,
 review BLOB NOT NULL,
 input_capsule_id TEXT NOT NULL,
 nullifier BLOB NOT NULL CHECK(length(nullifier)=32),
 txid TEXT NOT NULL UNIQUE,
 transaction_bytes BLOB NOT NULL,
 prover_request_sha256 TEXT NOT NULL,
 payment_capsule BLOB NOT NULL,
 change_capsule BLOB NOT NULL,
 valid_until INTEGER NOT NULL CHECK(valid_until BETWEEN 1 AND 512),
 created_revision INTEGER NOT NULL CHECK(created_revision>=0),
 FOREIGN KEY(input_capsule_id) REFERENCES notes(capsule_id)
) STRICT;
```

`wallet_id = SHA-256("1soft/protocol5-wallet-id/v1\0" || genesis_sha256 ||
owner_key)`. Decision ID binds wallet ID, review ID, and exact transaction ID.
All redundant identities, openings, public fields, receipts, output positions,
and request lineage are recomputed on explicit cryptographic audit. Structural
recovery remains possible when the client/prover is unavailable.

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
7. Refuse lower height. Same height accepts only a byte-identical observation.
   A conflict raises without mutation. Higher state extends every retained
   commitment, root, receipt, execution block, and spent-nullifier fact.
8. Verify and derive any executed change outside the write transaction, then
   recheck revision/extension and commit the observation, change notes, revision,
   counts, and authority digest atomically.

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

One commit inserts the decision, canonical review, ProverRequest SHA-256,
exact transaction, both private capsules, and increments the revision. The hold
is derived from the unresolved decision rather than a mutable reservation row.
Crash before commit leaves nothing; crash after commit recovers identical
transaction bytes. The raw ProverRequest is not persisted. Return values exclude
witnesses and note secrets.

Approval is the point of no return for the input reservation. There is no
cancellation or release merely because the transaction has not been submitted;
the exact proved bytes may already have escaped through a lost response or
recovery path. Only authenticated execution, a conflicting spend, or certified
post-validity absence resolves the obligation.

### Exact one-attempt submission

Preparation is mutation-free and returns a confirmation over the wallet ID,
wallet revision, delivery-journal ID and revision, decision, protocol txid,
plain Comet wire hash and exact loopback endpoint. Submission from `ready`
revalidates that closed review, inserts the sole attempt and commits
`attempt_claimed` before RPC. After the claim it rechecks the exact wallet
decision; any drift consumes the attempt as unresolved before network I/O. It
sends the exact stored transaction once through a key-free literal-IPv4
loopback client with one elapsed deadline and a 64 KiB complete-response bound.
No later path sends it again. Timeout, disconnect, HTTP error, malformed response,
or nonzero CheckTx changes only the attempt observation; obligation remains
`attempt_claimed`. There is no automatic retry, alternate endpoint, reproving,
replacement or refresh-and-resend.

Collection authenticates and stores the exact H+1 state observation as the
portable receipt without opening or mutating the wallet. Reconciliation first
checks the revision-bound wallet ID, decision, protocol txid, wire hash and exact
transaction against the durable attempt. It then syncs the selected observation
and reads the resulting decision at exactly the revision returned by that sync.
The delivery marker is written only from that bound record. Repeating a completed
reconciliation still validates the supplied wallet and its current decision
state before returning the stored result.

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

Exact/equivalent execution recreates transaction-origin capsules with the
winning txid and admits change atomically with the authenticated observation.
Output 0 becomes exportable as a byte-identical payment capsule; output 1 remains
internal. Repeating export is recovery of the same authority and does not change
chain or journal state.

## Startup and transaction recovery

Startup acquires the exclusive lock, audits paths, exact schema, row counts,
authority digest, canonical objects, saved certificates, transaction bytes, and
lineage. Structural open, review preparation, and exact transaction recovery do
not invoke the controller or prover. `status()` and capsule export perform the
cryptographic audit, including owner-key, commitment, nullifier, complete
ProverRequest reconstruction, receipt, and output checks.

A decision committed before a lost return is found after restart and returns the
same TransactionV1 without reproving. This stage has no wallet clone/restore
operation; adding one requires explicit duplicate-authority fencing semantics.

## Resource ceilings

| Resource | Ceiling |
|---|---:|
| owner keys | 1 |
| observations / total observation bytes | 32 / 8 MiB |
| notes | 16 |
| decisions | 16 |
| NoteCapsuleV1 / SpendReviewV1 | 4 KiB / 4 KiB |
| decoded state witness / signed header | 8 MiB / 256 KiB |
| complete RPC / broadcast response | 12 MiB / 64 KiB |
| SQLite main / main plus sidecars | 32 MiB / 64 MiB |
| client request / prover request | 1,966 / 1,010 bytes |
| transaction | genesis max, never above 64 KiB |
| client / prover / RPC watchdog | 30 / 300 / 15 seconds |

No operation trims authority/history to fit. A ceiling refuses before secret
access, proving, I/O or mutation as applicable. Watchdogs are local availability
controls and never establish chain result.

## Failure precedence

1. Unsafe storage, second writer, schema/corruption or source/binary drift: fatal.
2. Invalid trust/certificate: no mutation; same-height conflict is fatal.
3. Client/prover failure before durable approval: no decision or derived hold.
4. SQLite failure: rollback and retain prior memory.
5. Durable decision without attempt: recover exact bytes; retain the derived hold.
6. Durable attempt: never resend regardless of transport result.
7. Certified winner: exact, equivalent or conflicting execution.
8. Certified validity end with no winner: expired unexecuted.
9. Everything else: unavailable/unknown with the decision hold retained.

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
| Approval faults | before commit leaves nothing; after commit recovers the identical transaction, txid, nullifier, and private output capsules without reproving |
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
| Recovery | a lost approval return or process exit after commit recovers the exact stored transaction with the controller and prover unavailable |
| Leakage | secrets, capsules and ProverRequest absent from public output, argv, env, URLs, validator homes, app DBs, snapshots, receipts and logs |
| Convergence | four validators agree; A/B projections match authenticated history; negative evidence retained |

Failed reports/private artifacts are preserved without overwrite. The runner owns
all processes and actual exit codes. The checker rejects missing, skipped,
umbrella, unassessed, dirty-source, identity-drifted or overclaiming results.

## Test-first order

1. Freeze existing P5 artifacts/vectors; add failing opcode tests.
2. Implement opcodes 3-5 and prove consensus artifacts byte-identical.
3. Add strict capsule/review parsing and exact transaction recovery mutations.
4. Add hardened storage/schema audit, checkpoint install and restart audit.
5. Add note import/classification and certificate hostility tests.
6. Add prepare/approval atomic persistence and fault injection.
7. Add attempt claim/transport no-retry tests.
8. Add nullifier precedence, equivalent/conflict/expiry, payment export and restart recovery.
9. Run the real A-to-B-to-spend matrix and bind a strict wallet checker.
10. Rerun P5 consensus/state sync, P4 preservation, historical Halo2 benchmark and
    complete release gate.

Fixtures cover parser/fault paths only. Exact Rust binaries and the real
four-validator runner alone establish proof, execution, certificate and recovery
qualification.

## Evidence boundary

Passing establishes a source-bound finite trusted-host synthetic-note wallet for
one explicit recipient workflow, durable one-attempt continuity, authenticated
reconciliation and restart recovery. It does not establish production privacy or
custody, automatic scanning, safe capsule transport, multi-device authority,
independent review, anonymity, scalable storage, demand, public deployment or
real-funds readiness. All such claims remain false.
