# Native application → consensus boundary

24 September 2026 · v0.3 · development-only

## Purpose

Turn the prior standalone monetary ledger into a block-aware deterministic application without inventing a consensus algorithm. CometBFT v0.38.25 is the current adapter target, not an irrevocable decision about the final network architecture.

The interface and field mappings were inspected in the upstream `abci/types/application.go`, `abci/types/messages.go`, `proto/tendermint/abci/types.proto`, `cmd/cometbft/commands/testnet.go`, `go.mod`, and `rpc/core/types/responses.go`. The full engine was not audited. Source inspection does not establish binary interoperability; the upstream-codec and real-engine gates must pass before claiming it.

## Request lifecycle

`InitChain` accepts only the expected native genesis and matching engine chain ID. This version supports initial height 1 (an omitted/zero ABCI initial height normalizes to that intent). Initial genesis state is stored at height zero. A fresh, uninitialized `Info` response has no application hash.

`CheckTx` evaluates a transaction against an isolated committed-state copy. It does not reserve money or provide a global mempool guarantee. Two conflicting transactions can individually pass admission; proposal processing resolves them by ordered execution.

`PrepareProposal` evaluates the ordered candidates on a fresh copy, filters invalid/conflicting/replayed entries, and enforces byte and transaction-count limits. No proposal attempt changes committed state.

`ProcessProposal` independently executes the proposed list on an isolated copy. A candidate containing an invalid, expired, replayed or conflicting transaction is rejected. Repeated/alternate proposals for the same height cannot accumulate deductions.

`FinalizeBlock` receives an already-decided block from the trusted engine. It stages execution in memory and produces an AppHash plus per-transaction results. Repeated calls for the same pending block are stable; conflicting pending identities fail closed. As a defensive fallback, invalid transactions in an already-decided block produce failures without spending. Honest proposal validation rejects such candidates earlier.

`Commit` writes the resulting native snapshot, committed block height, application hash and block execution record in **one SQLite transaction** before acknowledging success. A failed write leaves the old durable state. A process dying after commit but before acknowledgment reopens at the new durable height. The optional fault parameter is an internal test hook, not an ABCI request field.

`Info` and `Query` expose committed state only. In-memory staging is never represented as settled. Empty blocks advance the application height and hash even when native balances do not change.

## State commitment

The AppHash is SHA-256 over a domain-separated canonical JSON object containing the native genesis digest, committed block height and all native metadata, accounts, grants and receipts. It is a full-snapshot hash, **not a Merkle tree or a query-proof implementation**.

The receipts are important: they determine whether a transaction has already executed. Leaving them outside consensus state would allow identical committed state hashes to describe different replay-acceptance behavior. The prior native model's balance-oriented state hash remains unchanged inside its receipt format; this adapter adds a broader consensus commitment around it.

`NativeLedger.apply` supports offline idempotent replay. The chain-facing wrapper deliberately rejects already-executed transaction IDs instead. Canonical wire bytes are required, so alternate whitespace/encodings cannot turn an identical signed body into another accepted chain transaction.

Transaction consent remains bound to the native chain ID and genesis hash. Expiry is evaluated at the proposed/decided block height, not local wall-clock time. Fees, grants, nonce rules and supply invariants are the prior original monetary rules, not rules supplied by a language model.

## Recovery

Before commit, a process restart discards the pending copy and reports the previous committed height. The engine must replay the decided block. After commit, a restart reports the new height. Application and engine databases are deliberately separate; their reconciliation is the engine's handshake responsibility and **has not yet been tested against a real engine here**.

The node application database has an exclusive process lock. Reopening with another genesis fails. A mismatched stored hash or incomplete latest block record fails validation. These checks do not protect against a privileged operator rewriting all state and verification data together.

## Transport and trust

The adapter uses Google's protobuf runtime and unsigned-varint length-delimited messages. It defines the relevant v0.38.25 wire-field subset; unused request fields are handled as unknown protobuf fields. Frames are limited to 2 MiB; transaction bytes to 16,384; application block bytes to 1 MiB; transactions per application block to 64.

ABCI is a **trusted engine-to-application control interface**, not a public wallet API. The Unix socket is placed in an owner-only directory and restricted to the same operating-system user. A same-user attacker could invoke authoritative ABCI methods. Production engine/application isolation and signer custody remain required. Agents must not receive this socket capability.

Snapshot offers are rejected; no state-sync support is claimed. Proof queries and unsupported historical queries explicitly fail rather than returning unproved data as if it were authenticated. Vote extensions are empty; this application does not add a new vote-extension protocol.

## Honest test taxonomy

1. Unit tests establish selected local application and wire behaviors.
2. Four OS application processes receiving scripted ABCI delivery establish transport/process consistency and selected recovery behavior. **They do not establish BFT consensus.**
3. The official-Go wire probe is a separate unassessed compatibility gate.
4. The real four-validator CometBFT runner is a separate unassessed integration gate.
5. Public deployment requires substantially more: independent operators, economic/security design, threat-driven testing, audits, operational controls and applicable issuer/custody arrangements.

## Known engineering limitations

Full snapshots, full receipt verification and cloning are intentionally simple and will not scale as the final state store. The next storage design needs bounded execution cost, authenticated key/value proofs and deliberate pruning/history semantics. No owner-key recovery, dynamic account onboarding, parent budget tree, external payment accounting integration, validator updates or production governance was added in this release.
