# SIP-0001: Validator evolution and explicit upgrade boundaries

Status: Draft; NOT activated. Date: 28 September 2026.
Base: PR #23 / 289a78056b86ebdd5878d285027f5c78562e0767.

## Purpose and implemented first slice

A future 1soft network should be able to replace operators and change voting power
without asking clients to trust a replacement list supplied by a server. The first
executable slice is tools/validator-evolution: adjacent-header verification,
durable historical continuity and an execution-free update preview. Today's node
still uses static validators; wallet proofs still reject changes. P1/P2/P3 and
smt-v1 bytes remain intact. This is not governance approval or a protocol-4 spec.

## Required contract before native activation

1. Authority must be explicit. Specify who may approve an update, signature domain,
   chain/genesis identity, sequence, validity interval and exact base pending-set
   hash. Peer lists, agent grants and budgets convey no validator governance.
   Options include a declared operator multisignature testnet or on-chain staking/
   governance. The former is simpler but permissioned; the latter needs economics,
   delegation, exit and slashing rules that are not specified yet. This draft
   chooses neither and authorizes no founder master key.

2. Execution must be deterministic. Updates finalized in H apply to the set already
   scheduled for H+1 and become active at H+2. H+1 commits their next-set root;
   changed last-commit inputs appear at H+3. Updates must bind the precise base,
   execute in block order and refuse conflicts rather than use arrival order.
   Replayed FinalizeBlock/Commit must reproduce output and persist exactly once.
   The preview models these heights but never enqueues or authorizes an update.

3. State must commit the decision. Authority policy, pending updates, update nonces
   and validator checkpoints require a versioned consensus-state schema and AppHash
   commitment, persisted alongside monetary state. An uncommitted proposal cannot
   change power. Returning an ABCI update without durable provenance is insufficient.

4. Software upgrades are separate. Specify supported versions and activation.
   Old clients must reject incompatible state; never disguise changed validator or
   AppHash semantics as old P3. A fresh-genesis development chain is simpler than
   migrating a live chain, but still needs explicit vectors/specification. This
   contribution creates neither a new genesis nor a live upgrade.

5. Clients verify authority continuity instead of discovering trust from RPC.
   Pin an initial checkpoint externally, verify current/next roots, every commit
   slot, strict quorum and adjacent ancestry. Stop when trust expires or versions
   change. Integrate a new opted-in wallet/explorer proof path only after state and
   receipt semantics are specified. Header continuity cannot establish balance,
   governance validity or off-chain payment.

6. Bootstrap must preserve authority history. Dynamic-validator state sync needs
   the committed active/pending sets and evidence for their history. Snapshots
   cannot choose their own validators. Historical receipts must identify the exact
   verified history authenticating their commitment. Missing history stays unknown,
   not proof that a payment never executed.

## Qualification required before activation

Freeze a candidate after choosing the authority/version model. Add vectors for
addition, removal, reweighting, empty sets, overflow, conflicting updates and delayed
activation. Run real pinned CometBFT checks of H/H+1/H+2/H+3 roots and vote ordering;
exercise joins, removals, state sync, and crashes before/after update commit.
Integrate wallet/explorer/archive proofs across repeated transitions and test stale
software, expired trust and unavailable history. Repeat monetary/account/payment
regressions without rewriting results. Qualify separately administered operators
and independent review before anyone relies on customer value.

## Non-claims

Implemented: verification, durable history and a preview. Not implemented: native
governance transaction, staking/slashing, ABCI update emission, production wallet
integration or a changing-validator engine run. Fixtures sign chosen committees
over actual native application states; no validator engine performs those changes.

Timing/verification references are pinned in the component README. Local policy
bounds, persistence design and sequencing are project choices, not upstream
requirements. Security/custody review, monetary policy, reserve backing/cards,
public deployment and real funds remain outside this proposal.
