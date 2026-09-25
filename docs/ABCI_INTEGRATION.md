# Native application → consensus boundary

24 September 2026 · v0.5 · development-only

## Purpose

Turn the prior standalone monetary ledger into a block-aware deterministic application without inventing a consensus algorithm. CometBFT v0.38.25 is the current adapter target, not an irrevocable decision about the final network architecture.

The interface and field mappings were inspected in the upstream `abci/types/application.go`, `abci/types/messages.go`, `proto/tendermint/abci/types.proto`, `cmd/cometbft/commands/testnet.go`, `go.mod`, and `rpc/core/types/responses.go`. The full engine was not audited. Source inspection does not establish binary interoperability; the upstream-codec and real-engine gates must pass before claiming it.

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

Before commit, a process restart discards the pending copy and reports the previous committed height. The engine must replay the decided block. After commit, a restart reports the new height. Application and engine databases are deliberately separate; their reconciliation is the engine's handshake responsibility and **has not yet been tested against a real engine here**.

The node application database has an exclusive process lock. Reopening with another genesis fails. A mismatched stored hash or incomplete latest block record fails validation. These checks do not protect against a privileged operator rewriting all state and verification data together.

## Transport and trust

The adapter uses Google's protobuf runtime and unsigned-varint length-delimited messages. It defines the relevant v0.38.25 wire-field subset; unused request fields are handled as unknown protobuf fields. Frames are limited to 2 MiB; transaction bytes to 16,384; application block bytes to 1 MiB; transactions per application block to 64. The 1 MiB application limit now covers encoded `Data.txs` framing, not just transaction payload sums. The consensus engine separately budgets the rest of its block.

ABCI is a **trusted engine-to-application control interface**, not a public wallet API. The Unix socket is placed in an owner-only directory and restricted to the same operating-system user. A same-user attacker could invoke authoritative ABCI methods. Production engine/application isolation and signer custody remain required. Agents must not receive this socket capability.

Snapshot offers are rejected; no state-sync support is claimed. Proof queries and unsupported historical queries explicitly fail rather than returning unproved data as if it were authenticated. Vote extensions are empty; this application does not add a new vote-extension protocol.

## Honest test taxonomy

1. Unit tests establish selected local application and wire behaviors.
2. Four OS application processes receiving scripted ABCI delivery establish transport/process consistency and selected recovery behavior. **They do not establish BFT consensus.**
3. The official-Go wire probe is a separate unassessed compatibility gate.
4. Independent certificate tests check signatures, header hashes, transaction inclusion and full-state witnesses against a static pinned genesis. Delivered packets are synthetic; those tests are not consensus evidence. The production-facing development CLI requires expected transaction IDs.
5. The real four-validator CometBFT runner is a separate unassessed integration gate; it now requires independently verified certificates in addition to its original quorum and state checks.
6. Public deployment requires substantially more: independent operators, economic/security design, threat-driven testing, audits, operational controls and applicable issuer/custody arrangements.

## Signed receipt verification

`commit_verifier.py` independently reconstructs the header hash, verifies all validator signature slots and strict >2/3 voting power, and checks the target transaction against the signed data hash. Its trust anchor is a separately pinned exact genesis file, not a server-supplied validator set.

The state produced by block h is bound through the signed header at h+1. The full state hash must match that header, and the requested transaction must have a matching execution receipt in the authenticated state. Inclusion alone is not success. These checks do not independently reexecute all historical monetary rules.

The verifier supports an unchanged Ed25519 validator set, not arbitrary dynamic networks. It neither proves freshness nor distinguishes a synthetic quorum-signed packet from one produced by a live engine. See `RECEIPT_VERIFICATION.md`. `prove=true` queries still fail explicitly; full-state certificate verification does not add Merkle query-proof support.

## Known engineering limitations

Full snapshots, full receipt verification and cloning are intentionally simple and will not scale as the final state store. The next storage design needs bounded execution cost, authenticated key/value proofs and deliberate pruning/history semantics. Protocol-2 onboarding and controlled key rotation are implemented, but owner-key recovery, a parent budget tree, external payment accounting integration, validator updates and production governance remain absent.

## v0.5 lifecycle evidence and engine boundary

The new application-process exercise records 65 checks across four scripted application processes. It executes account funding, same-named grants for different owners, rotation, explicit new authority and stale-key/grant rejections, including process loss before/after commit. This supplements, not replaces, the legacy 39-check process exercise. Neither uses validator voting.

The actual-engine runner now creates separate fresh protocol-1 and protocol-2 networks. Unit tests validate their signed operation plans, but both engine runs and the official Go codec remain unassessed due to dependency retrieval failure. Handshake/version reporting, RPC details and engine recovery still require empirical verification.
