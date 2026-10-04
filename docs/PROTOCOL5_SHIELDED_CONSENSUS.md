# Protocol 5 shielded consensus

Protocol 5 is a newly identified, fresh-genesis experimental chain profile. It
uses actual Halo2 proof verification for a one-input/two-output shielded-note
relation and makes the application responsible for deterministic consensus
admission, append-only note state, global uniqueness, receipts, crash recovery,
and state sync. It is separate from Protocol 4: there is no migration, shared
AppHash, shared snapshot format, transparent-native bridge, or mutation of a
Protocol 4 database.

The source exercised by the final qualification runs is commit
`6a8f33c9e5e6fa53ff2cb13ae66df9c81d7d79ff`, tree
`f98000a92e780c8cc54338345db18696a55cd8d0`. The authoritative byte-level and
state-machine contract is the [accepted design](superpowers/specs/2026-10-04-shielded-consensus-admission-design.md).
The [component manifest](../tools/shielded-consensus/COMPONENT_MANIFEST.json)
records the exact profile, deployment, binaries, generated inputs, and final
receipt hashes.

## Identities and trust boundary

Three identities have different jobs:

1. **ProfileDescriptorV1** binds relation version 1, circuit ID
   `1soft/shielded-consensus/halo2-pasta/v1`, K=13, tree depth 4, fourteen
   ordered public fields, exact proof length 3,136, parameters, pinned
   verifying-key binding, circuit source, Cargo lock, public schema, KAT,
   curve/commitment identity, and transcript/Poseidon identity. Its qualified
   profile ID is
   `272f8ea5ea7e04fa24b27c5125650150760b618229f2f3fbe0b7cc95bbca3eef`.
2. **DeploymentBindingV1** binds that profile to worker protocol 1, the exact
   verifier-worker binary, Rust toolchain manifest, and sandbox policy. Its
   qualified deployment ID is
   `76129871a4659caf919ccdb32c545b0330b4ba1018cf6b1ec85ac61582eb3cac`.
3. The final canonical **genesis SHA-256** binds the complete chain instance,
   including its inserted initial commitments. Every TransactionV1 carries the
   final genesis digest and deployment ID.

`genesis_field` is derived before initial notes:

```text
H2F("genesis", canonical_json(genesis without genesis_field and initial_commitments))
```

The Rust development client then derives spendable initial commitments using
that field. Inserting both members and hashing the final canonical genesis
breaks the dependency cycle while still binding the commitment list.

The profile and deployment split is deliberate. A circuit, parameter, key,
dependency, or source change creates a new profile identity. A worker,
toolchain, or sandbox-policy change creates a new deployment identity. Either
change requires fresh genesis and fresh qualification. The version-bound
verifying-key binding is not a portable cross-platform serialization claim.

## Canonical transaction boundary

Every consensus transaction is binary TransactionV1:

```text
1SFTSHD1 | u16 wire=1 | u16 backend=1 | u32 relation=1
| 32-byte genesis SHA-256 | 32-byte deployment ID
| u16 instance_count=14 | 14 canonical 32-byte fields
| u32 proof_length | exact proof bytes
```

The fixed prefix is 534 bytes. All integers are little-endian. Field encodings
are the exact 32-byte little-endian `to_repr` form of the Pallas base field.
Decoders require the genesis-fixed 3,136-byte proof, complete consumption, and
no alternate or trailing encoding. The transaction ID is domain-separated
SHA-256 over the complete transaction bytes.

The fourteen public fields, in order, are relation version, genesis field,
asset field, context field, authority epoch, valid-from height, valid-until
height, policy field, accepted anchor root, nullifier, output commitment 0,
output commitment 1, fee, and authorization digest. The proof binds a hidden
input note and membership path, position-bound nullifier, two positive hidden output values with distinct
nonzero commitments, exact fee-inclusive conservation, validity interval, and
authorization digest. Consensus additionally requires
`valid_from <= candidate_height < valid_until`, an authenticated historical
anchor, global nullifier freshness, global output uniqueness, and remaining
tree/history/fee capacity.

WitnessV1 is exactly 480 bytes and exists only between the controller client and
the development prover. It is never an ABCI payload or worker operation. The
final TransactionV1 contains no witness, spend secret, note secret, or blinding.

## Validator and controller separation

A validator application is configured with the exact genesis, descriptor, KAT,
toolchain manifest, sandbox policy, and `shielded-verifier-worker`. It opens the
worker without following symlinks, checks ownership and mode, measures the open
inode, and launches that inode with zero arguments. The worker constructs the
pinned parameters and verifying key, validates the KAT and prescribed mutated
KAT, closes every descriptor except framed stdin/stdout, enables `no_new_privs`, installs the recorded
x86_64 Linux seccomp deny policy, and proves that file-open and socket probes
are denied.

The long-lived worker is single-threaded and exposes only Profile, TreeRootV1,
VerifyProofV1, and VerifyAndAppendV1. It has no prover or witness opcode. A
canonical invalid statement returns deterministic code 8 and an invalid Halo2
proof returns code 9. Worker death, timeout, malformed or oversized framing,
identity mismatch, internal-root divergence, unsolicited output, or sandbox
failure is local verifier unavailability: the active callback produces no
consensus result, pending state is discarded, and the process refuses later
callbacks until an exact clean restart.

`shielded-development-client` and `shielded-development-prover` run only under
the external controller. The client reads a bounded request containing public
domain fields, a commitment vector, one input note opening/position, and two
output definitions; it derives the path, public statement, and WitnessV1. The
prover reads the resulting ProverRequestV1 and emits only TransactionV1. Do not
install either controller binary in validator homes or expose them through a
validator service.

## Finite chain limits

Protocol hard ceilings are:

| Resource | Ceiling |
| --- | ---: |
| chain ID | 50 printable ASCII bytes |
| validators | exactly 4 fixed equal-power validators |
| validator power | 1,000,000 each; 4,000,000 total |
| height | 512 |
| note-tree capacity | 16 commitments |
| outputs per accepted transaction | exactly 2 |
| transactions per block | 8 |
| proposal candidates | 64 |
| proposal bytes inspected | 4 MiB |
| transaction bytes | 64 KiB |
| proof bytes | 60 KiB |
| maximum cumulative accepted fees | `u64::MAX` |
| protobuf transaction data per block | 512 KiB |
| FinalizeBlock request | 2 MiB |
| retained transaction entries | 64 |
| retained raw transaction bytes | 2 MiB |
| snapshot payload | 8 MiB |
| snapshot chunks | 128 chunks of at most 64 KiB |
| worker frame | 1 MiB |
| worker startup/request watchdog | 120 / 30 seconds |

Genesis may choose only equal or smaller values. If it contains `g` initial
commitments, `max_accepted_transactions` cannot exceed
`floor((16 - g) / 2)`. The qualified settings select six accepted transactions,
eight transactions per block, sixty-four retained entries, 2 MiB retained raw
wire bytes, fixed fee 5, and maximum fee total 1,000. These finite limits are
consensus rules, not production scaling parameters.

## Deterministic admission and persistence

CheckTx evaluates against committed state. PrepareProposal starts from committed
state and stages candidates sequentially. It freezes the block-start root set,
so a root produced earlier in the same candidate block cannot anchor a later
transaction in that block. ProcessProposal independently replays the complete
ordered proposal. FinalizeBlock repeats the same evaluator and validates the
exact fixed next-validator hash. At height 1 it requires an empty decided last
commit; at later heights it requires the complete fixed roster and strict
greater-than-two-thirds flag-2 commit power. It binds the bounded request bytes
and block hash, then stages one deterministic response.

Global history count and raw-wire byte budgets include rejected transactions
that appear in a decided block. Accepted transactions append output 0 then
output 1, record the winning nullifier, increase the fee accumulator, extend
root history, and create a receipt. The immutable validator set produces no
validator updates.

Commit stores state, execution history, exact transaction results, response
bytes, request digest, block hash, receipts, and AppHash in one SQLite
`BEGIN IMMEDIATE` transaction. In-memory state advances only after SQLite
commit. A crash before durable commit reexecutes. After durable commit, an exact
repeat of the already-committed FinalizeBlock returns the retained response
bytes. Commit with no pending finalization returns Info as a safe no-op. Startup
replays every retained transaction through the real worker and
refuses any changed genesis, profile, deployment, tree, nullifier, output, fee,
receipt, history, response row, or AppHash.

## Queries and authentication

Queries require empty data, `prove=false`, and height zero or the current
committed height. The closed paths are:

- `/info`
- `/state`
- `/root-history`
- `/tx/<lowercase transaction ID>`
- `/nullifier/<canonical little-endian field hex>`
- `/block/<height>`

The block projection is AppHash-committed execution history, not a fabricated
CometBFT block response. Query responses are not Merkle proofs. The signed
next-height CometBFT header authenticates the AppHash produced by the preceding
Commit. Nullifier lookup returns the winning transaction ID and receipt so a
controller can reconcile a spent note even when it regenerated different
randomized proof bytes.

## Marker-only state sync

A Protocol 5 snapshot contains canonical genesis, height, AppHash, and closed
application state. It carries replayable transaction history but no fabricated
historical CometBFT response rows, votes, request identity, or local process
data. A recipient accepts only its independently configured genesis,
deployment, worker/KAT/sandbox, and the AppHash supplied by CometBFT's light
client. It replays every retained transaction through the verifier before one
atomic install.

The installed checkpoint has one durable state-sync marker and zero historical
response rows. The first ordinary post-sync commit writes its real response row
and deletes the marker. Duplicate chunks are idempotent only when byte-identical;
out-of-order chunks request the exact missing index; conflicting, corrupt,
short, excessive, or unauthenticated content is refused. After a lost final
Apply response and process restart, CometBFT must re-offer the same snapshot;
the marker admits only the byte-identical same-height offer. Older snapshots
and same-height forks are rejected. A strictly newer offer still needs its own
externally authenticated AppHash.

The final state-sync gate froze the snapshot at H while independent light
providers continued to H+2, observed the target process exit with code 96 after
the final Apply was durably committed, observed re-offer, continued all five
applications, and restarted the same target store. This demonstrates the
bounded one-host recovery path; it does not independently prove the external
light-client trust input.

## Building qualified inputs

Build and test Rust worker and `dev-prover` feature profiles separately as
shown in the [component README](../tools/shielded-consensus/README.md). Then use
the measured worker and tracked profile inputs to create a new binding and an
empty-note canonical genesis template. Outputs must be fresh files outside the
repository.

```sh
python -B scripts/build_protocol5_inputs.py \
  --worker "$P5_WORKER" \
  --profile tools/shielded-consensus/profile/profile-descriptor-v1.bin \
  --toolchain tools/shielded-consensus/profile/toolchain-manifest-v1.json \
  --policy tools/shielded-consensus/profile/sandbox-policy-v1.json \
  --settings reference/protocol5-qualification-settings-v1.json \
  --binding-output "$P5_PRIVATE/deployment-binding-v1.bin" \
  --genesis-output "$P5_PRIVATE/protocol5-template.json"
```

The source-bound qualification runners require the exact CometBFT, worker,
client, prover, descriptor, KAT, toolchain, policy, and template, plus externally
pinned client/prover hashes. Each report path must be new and outside the
repository. Replace `run_protocol5_engine.py` with
`run_protocol5_state_sync.py` for the state-sync profile.

```sh
PYTHONPATH=src:tests:scripts:tools/release python -B scripts/run_protocol5_engine.py \
  --engine "$COMETBFT" --worker "$P5_WORKER" \
  --client "$P5_CLIENT" --prover "$P5_PROVER" \
  --profile tools/shielded-consensus/profile/profile-descriptor-v1.bin \
  --kat tools/shielded-consensus/profile/kat-v1.bin \
  --toolchain tools/shielded-consensus/profile/toolchain-manifest-v1.json \
  --policy tools/shielded-consensus/profile/sandbox-policy-v1.json \
  --genesis "$P5_PRIVATE/protocol5-template.json" \
  --expected-client-sha256 "$P5_CLIENT_SHA256" \
  --expected-prover-sha256 "$P5_PROVER_SHA256" \
  --output "$P5_PRIVATE/consensus.json"

PYTHONPATH=src:tests:scripts:tools/release python -B tools/release/check_protocol5.py \
  "$P5_PRIVATE/consensus.json"
```

The checker requires the sibling artifact directory, exact process receipts,
source binding, input hashes, complete scenario roster, actual proof admission,
and all production-readiness booleans false. It returns a nonzero exit when a
report is unassessed, failed, incomplete, skipped, changed, or overclaims.

## Qualified evidence and remaining limits

Final consensus receipt `consensus-05.json` has SHA-256
`6ef26345af2654f3553b6a884eeef81b11ef1bb26c361c46bb82c0de05b8bd42`.
Final state-sync receipt `state-sync-03.json` has SHA-256
`5ba80ad83b17d57935edb8e9985b0df0e5deab6912693625204fbff1421713d4`.
Both report `completed-awaiting-external-validation`; their separate strict
checker receipts qualify the complete expected check rosters. Raw evidence and
private process paths remain external. Exact sizes and hashes for reports,
checker receipts, and artifact manifests are in the component manifest.

The evidence establishes actual local Halo2 verification, deterministic
four-validator admission, authenticated root and receipt history, atomic
restart behavior, and verifier-replayed marker-only state sync for one finite
synthetic development chain on one host. It does not establish production
security or privacy, anonymity or network-metadata privacy, independent
security or cryptographic review, production custody or side-channel safety,
wallet scanning/recovery, scalable storage, multi-host Byzantine behavior,
public-network or exchange readiness, real-funds safety, or economic value. All
such claims remain false.
