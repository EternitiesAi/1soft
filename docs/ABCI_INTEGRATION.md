# Native application → consensus boundary

4 October 2026 · protocol-scoped development boundary

## Purpose

Turn the prior standalone monetary ledger into a block-aware deterministic application without inventing a consensus algorithm. CometBFT v0.38.25 is the current adapter target, not an irrevocable decision about the final network architecture.

The interface and field mappings were inspected in the upstream `abci/types/application.go`, `abci/types/messages.go`, `proto/tendermint/abci/types.proto`, `cmd/cometbft/commands/testnet.go`, `go.mod`, and `rpc/core/types/responses.go`. The full engine was not audited. Source inspection does not establish binary interoperability; the upstream-codec and real-engine gates must pass before claiming it.

## Protocol scope

Unless a paragraph names Protocol 4 or Protocol 5, the original lifecycle below
describes the transparent Protocol 1 through Protocol 3 application. Protocol 4
is a separate fresh-genesis transparent application with its own exact
[development scope](PROTOCOL4_DEVELOPMENT.md) and
[state-sync qualification](PROTOCOL4_STATE_SYNC_QUALIFICATION.md). Protocol 5 is
another separate fresh-genesis application described below. It does not change,
upgrade, migrate or reinterpret Protocol 1 through Protocol 4 state, AppHash,
snapshots, clients or historical evidence.

## Genesis-version compatibility

The native genesis explicitly pins protocol 2 or defaults to protocol 1 when its version field is omitted. `Info` reports the chosen native version, not merely the newest version the binary knows. Existing state cannot reopen under another genesis. Protocol 2 enables signed onboarding, root-key rotation and owner-scoped grants without changing the snapshot row format or AppHash domain. This is a fresh-genesis feature, not a live chain upgrade.

Lifecycle operations follow exactly the same isolated proposal, staged execution and atomic commit boundary as transfers. Pending accounts/keys are not query-visible. Ordered execution can open an account and then apply a correctly signed transaction from it; standalone mempool admission still evaluates against committed state, so clients should not assume dependent transactions are independently admissible before onboarding commits.

## Request lifecycle

`InitChain` accepts only the expected native genesis and matching engine chain ID. This version supports initial height 1 (an omitted/zero ABCI initial height normalizes to that intent). Initial genesis state is stored at height zero. A fresh, uninitialized `Info` response has no application hash.

`CheckTx` evaluates a transaction against an isolated committed-state copy. It does not reserve money or provide a global mempool guarantee. Two conflicting transactions can individually pass admission; proposal processing resolves them by ordered execution.

`PrepareProposal` evaluates the ordered candidates on a fresh copy, filters invalid/conflicting/replayed entries, and enforces byte and transaction-count limits. The byte budget includes each repeated protobuf transaction field tag and its varint length; v0.3 incorrectly counted only raw transaction bytes. No proposal attempt changes committed state.

`ProcessProposal` independently executes the proposed list on an isolated copy. A candidate containing an invalid, expired, replayed or conflicting transaction is rejected. Repeated/alternate proposals for the same height cannot accumulate deductions.

`FinalizeBlock` receives an already-decided block from the trusted engine. It stages execution in memory and produces an AppHash plus per-transaction results. Repeated calls for the same pending block are stable; conflicting pending identities fail closed. As a defensive fallback, invalid transactions in an already-decided block produce failures without spending. Honest proposal validation rejects such candidates earlier.

`Commit` writes the resulting native snapshot, committed block height, application hash and block execution record in **one SQLite transaction** before acknowledging success. A failed write leaves the old durable state. A process dying after commit but before acknowledgment reopens at the new durable height. The optional fault parameter is an internal test hook, not an ABCI request field.

`Info` and `Query` expose committed state only. `/block/<height>` additionally returns already-committed block metadata, including its AppHash and execution results; pending or nonexistent heights are rejected. This is a metadata lookup, not an authenticated proof. In-memory staging is never represented as settled. Empty blocks advance the application height and hash even when native balances do not change.

## State commitment

The AppHash is SHA-256 over a domain-separated canonical JSON object containing the native genesis digest, committed block height and all native metadata, accounts, grants and receipts. It is a full-snapshot hash, **not a Merkle tree or a query-proof implementation**.

The receipts are important: they determine whether a transaction has already executed. Leaving them outside consensus state would allow identical committed state hashes to describe different replay-acceptance behavior. The prior native model's balance-oriented state hash remains unchanged inside its receipt format; this adapter adds a broader consensus commitment around it.

`NativeLedger.apply` supports offline idempotent replay. The chain-facing wrapper deliberately rejects already-executed transaction IDs instead. Canonical wire bytes are required, so alternate whitespace/encodings cannot turn an identical signed body into another accepted chain transaction.

Transaction consent remains bound to the native chain ID and genesis hash. Expiry is evaluated at the proposed/decided block height, not local wall-clock time. Fees, grants, nonce rules and supply invariants are the prior original monetary rules, not rules supplied by a language model.

## Recovery

Before commit, a process restart discards the pending copy and reports the previous committed height. The engine must replay the decided block. After commit, a restart reports the new height. Application and engine databases are deliberately separate; their reconciliation requires a real-engine acceptance receipt for the exact source revision.

The node application database has an exclusive process lock. Reopening with another genesis fails. A mismatched stored hash or incomplete latest block record fails validation. These checks do not protect against a privileged operator rewriting all state and verification data together.

## Transport and trust

The adapter uses Google's protobuf runtime and unsigned-varint length-delimited messages. It defines the relevant v0.38.25 wire-field subset; unused request fields are handled as unknown protobuf fields. Frames are limited to 2 MiB; transaction bytes to 16,384; application block bytes to 1 MiB; transactions per application block to 64. The 1 MiB application limit now covers encoded `Data.txs` framing, not just transaction payload sums. The consensus engine separately budgets the rest of its block.

ABCI is a **trusted engine-to-application control interface**, not a public wallet API. The Unix socket is placed in an owner-only directory and restricted to the same operating-system user. A same-user attacker could invoke authoritative ABCI methods. Production engine/application isolation and signer custody remain required. Agents must not receive this socket capability.

ABCI snapshot serving/restoration is a bounded development path. A fresh application accepts format-1 snapshots only with an explicit expected native genesis; an untouched snapshot-only checkpoint can also recover a lost final ABCI reply before CometBFT bootstraps its state store. Recovery is restricted to the exact marker-matching committed state with no local block rows, and accepts only the same or a newer trusted snapshot. Every restore recomputes the complete native AppHash before committing. Snapshot metadata and peer chunks are untrusted; CometBFT's independently light-client-verified RequestOfferSnapshot.app_hash is the external commitment. A local marker records bootstrap provenance without becoming consensus state or inventing block metadata. Current snapshots are complete-state/receipt snapshots capped at 16 MiB, so this is a bootstrap mechanism, not the final pruning/scaling design. See STATE_SYNC.md.

Proof queries and unsupported historical queries explicitly fail rather than returning unproved data as if it were authenticated. Vote extensions are empty; this application does not add a new vote-extension protocol.

## Protocol 5 fresh-genesis profile

Protocol 5 has dedicated `protocol5_*` encodings, state, application, database,
AppHash, certificate and state-sync code. It may reuse generic bounded protobuf
transport, but it neither subclasses Protocol 4 nor accepts Protocol 4 genesis,
transactions, snapshots or evidence. Its depth-four note tree has sixteen leaves,
exactly two outputs per accepted spend and a finite configured transaction/history
budget. This is a consensus and recovery qualifier, not a scalable payment pool.

`InitChain` requires canonical Protocol 5 genesis bytes, the matching chain ID,
initial height one and exactly four fresh equal-power validators. The validator
set is immutable. `CheckTx` evaluates one public transaction and actual Halo2
proof against committed state without reserving a nullifier or output.
`PrepareProposal` executes candidates in order on an isolated state copy and an
immutable block-start root set. `ProcessProposal` independently replays the
complete proposal and rejects any nonzero result, exhausted retained-history
budget or changed next-validator hash. `FinalizeBlock` checks the immutable
next-validator hash at every height, including height one, validates the later
commit quorum, binds the exact bounded request and block hash, and stages a
deterministic result.

`Commit` replays the staged history through the verifier worker, then stores state,
AppHash, raw transaction history, exact finalization response and marker cleanup
in one SQLite transaction. Memory advances only after durable commit. Repeating
the exact FinalizeBlock after the durable write returns the retained response; a
Commit with no pending finalization succeeds without changing state. Crash hooks exist only in the
run-token-gated test server. The production application exposes no fault
parameter. Validator workers implement verification and tree operations only;
witness construction and proving remain external controller capabilities.

Protocol 5 queries accept empty data, `prove=false`, and height zero or the current
committed height. The closed paths are `/info`, `/state`, `/root-history`,
`/tx/<lowercase-txid>`, `/nullifier/<canonical-little-endian-field-hex>` and
`/block/<height>`.
They return AppHash-committed projections, not Merkle query proofs or fabricated
historical CometBFT responses. A signed header at the next height authenticates
the preceding Commit's AppHash.

Protocol 5 state sync uses snapshot format 1 under its own
`1soft/shielded-development/state-sync/v1` domain. It remains incompatible with
the legacy Protocol 1 through Protocol 3 format-1 schema, while Protocol 4 uses
format 2 separately. Before installation, the recipient checks genesis, profile
and deployment identities, replays every retained transaction through the real
verifier worker, recomputes the complete state and requires the
light-client-supplied AppHash. Installation atomically writes current state,
derived transaction history and one marker, with no invented historical
FinalizeBlock response rows.

The real recovery topology freezes the snapshot provider at height H while the
other three source validators advance to at least H+2. Two expose the target's
light-client RPC endpoints and the third contributes to the advancing quorum.
This gives CometBFT the H+1 and H+2 headers needed to authenticate the height-H
snapshot instead of treating the snapshot peer as its own trust source. A restored target initially has
application state at H and a marker but no height-H local block or response row.
The runner therefore keeps that marker-only target process live while source
validators reconnect. The first ordinary post-sync Commit writes a real current
response row and deletes the marker; only after ordinary block progress is a
same-store engine restart exercised.

Same-height recovery accepts only the byte-identical genesis, profile, deployment,
AppHash and payload hash. A different same-height payload or fork, an older
snapshot, altered proof/nullifier/root history, malformed/conflicting chunks and a
failed atomic install fail without replacing the old checkpoint. A lost
final Apply reply is recovered by an observed CometBFT re-offer; the event evidence
binds the application exit and exact accepted initial/re-offer sequence.

See the [component boundary](../tools/shielded-consensus/README.md) and complete
[Protocol 5 guide](PROTOCOL5_SHIELDED_CONSENSUS.md).

## Honest test taxonomy

1. Unit tests establish selected local application and wire behaviors.
2. Four OS application processes receiving scripted ABCI delivery establish transport/process consistency and selected recovery behavior. **They do not establish BFT consensus.**
3. The official-Go wire probe is a separate compatibility gate whose result must be bound to the exact source revision.
4. Independent certificate tests check signatures, header hashes, transaction inclusion and full-state witnesses against a static pinned genesis. Delivered packets are synthetic; those tests are not consensus evidence. The production-facing development CLI requires expected transaction IDs.
5. The real four-validator CometBFT runner has passed multiple pinned one-host scenarios in later checkpoints, including protocol-3 wallet/delivery flows. Those results apply only to their exact tested source revisions. The new ABCI state-sync changes require their own opt-in `run_state_sync.py` real-engine gate; old network results are not reused as state-sync evidence.
6. Public deployment requires substantially more: independent operators, economic/security design, threat-driven testing, audits, operational controls and applicable issuer/custody arrangements.

## Signed receipt verification

`commit_verifier.py` independently reconstructs the header hash, verifies all validator signature slots and strict >2/3 voting power, and checks the target transaction against the signed data hash. Its trust anchor is a separately pinned exact genesis file, not a server-supplied validator set.

The state produced by block h is bound through the signed header at h+1. The full state hash must match that header, and the requested transaction must have a matching execution receipt in the authenticated state. Inclusion alone is not success. These checks do not independently reexecute all historical monetary rules.

The verifier supports an unchanged Ed25519 validator set, not arbitrary dynamic networks. It neither proves freshness nor distinguishes a synthetic quorum-signed packet from one produced by a live engine. See `RECEIPT_VERIFICATION.md`. `prove=true` queries still fail explicitly; full-state certificate verification does not add Merkle query-proof support.

## Known engineering limitations

The original full-state proof/rebuild bottlenecks have since gained a persistent sparse-Merkle proof index, bounded execution images and a bounded ABCI state-sync snapshot path. Complete native receipt history is still carried in state and state-sync snapshots, so deliberate pruning/history semantics and a long-term scalable bootstrap design remain unresolved. Protocol-2 onboarding and controlled key rotation are implemented, but owner-key recovery, a parent budget tree, external payment accounting integration, validator updates and production governance remain absent.

## v0.5 lifecycle evidence and engine boundary

The new application-process exercise records 65 checks across four scripted application processes. It executes account funding, same-named grants for different owners, rotation, explicit new authority and stale-key/grant rejections, including process loss before/after commit. This supplements, not replaces, the legacy 39-check process exercise. Neither uses validator voting.

Later source checkpoints executed the pinned engine on one-host four-validator
Protocol 1 through Protocol 3 networks and independently verified signed receipts.
Protocol 4 has separately scoped real-engine and state-sync evidence. Those
historical results do not automatically qualify modified ABCI code or Protocol 5.

Protocol 5's source-bound consensus and state-sync checkers passed on one loopback
host for implementation commit `6a8f33c9e5e6fa53ff2cb13ae66df9c81d7d79ff`,
tree `f98000a92e780c8cc54338345db18696a55cd8d0`, pinned CometBFT
SHA-256 `218628da07bed5d27e178d38d0bef9ecf46f21b214c8e9fea402fd215fccc024`,
profile ID `272f8ea5ea7e04fa24b27c5125650150760b618229f2f3fbe0b7cc95bbca3eef`
and deployment ID
`76129871a4659caf919ccdb32c545b0330b4ba1018cf6b1ec85ac61582eb3cac`.
The checked consensus report SHA-256 is
`6ef26345af2654f3553b6a884eeef81b11ef1bb26c361c46bb82c0de05b8bd42`;
the checked state-sync report SHA-256 is
`5ba80ad83b17d57935edb8e9985b0df0e5deab6912693625204fbff1421713d4`.

That evidence covers four equal-power validators, actual proof acceptance,
proposal conflicts, global nullifier/output uniqueness, immutable-validator
binding, quorum continuation, worker failure, atomic commit recovery, marker-only
state sync, hostile offers/chunks and post-sync continuation. It remains one-host
development evidence with synthetic notes. It establishes no public-network or
real-funds readiness, anonymity or metadata resistance, production custody,
exchange readiness, scaling, production proof-system selection or independent
cryptographic review.
