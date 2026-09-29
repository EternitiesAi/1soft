# SIP-0003 — Explicit administrative validator registry experiment

Status: Draft experiment, not approved public governance or an activated upgrade.
Date: 28 September 2026. Builds on the local SIP-0002 transition foundation.

## Decision for this experiment only

Use `1soft/validator-registry-experiment/v1` with its own genesis and state hash
domain. Do not label it protocol 4 or feed it to P1/P2/P3 wallet/node entry points.
All existing monetary protocol and commitment bytes remain unchanged.

Use a genesis-pinned n-of-m list of separate administrative Ed25519 keys. The demo's
2-of-3 policy is explicitly centralized test authority, not validator voting, proof
of stake or token governance. Administrative signatures must also obey pinned delay,
minimum set size and per-key power limits. Consensus keys have no implicit governance
role. Key-count constraints are not independent-operator guarantees.

## Command and state contract

Canonical envelope: body and approvals. Body: schema, dedicated format, chain_id,
genesis_sha256, authority_epoch, nonce, base_epoch, base_set_hash, valid_from,
valid_until and operation. The signature covers the dedicated domain plus exact
canonical body bytes. Approvals are unique key/signature pairs sorted by key;
all supplied approvals verify and meet the pinned threshold. Numeric fields reject
booleans, floats and numeric strings.

Schedule operation selects exact emission_height and complete canonical validators.
Cancellation selects exact proposal_id. That ID hashes the body preimage, not a
particular signature subset. Accepted commands append exact envelopes to hash-linked
receipts and consume one administrative nonce. Their validity deadline limits
acceptance, not the later authorized activation. Invalid commands do neither.

State commits genesis identity, height, active epoch/roster, nonce, optional pending
proposal/emission flag, last activation height and complete accepted receipt history.
Replay reproduces those fields. Accepted at A, a change emits at E >= A + pinned
delay (at least two), announces the next set at E+1, and activates at E+2. E+3
last-commit inputs and proposer priority need subsequent real-engine validation.

At most one schedule is pending. Cancellation requires height < E and preserves the
prior receipt. An activation-height cooldown disallows a new schedule at E+2.
Complete replacement is possible only under the same threshold and roster rules;
it remains powerful administrative authority, not a guarantee against takeover.

Finalize is non-durable. Commit atomically advances its exact prior checkpoint.
Reopening reconstructs state and the last block output. Fresh snapshot import
requires an external exact root, replays every accepted administrative signature
and cancellation, and preserves pending versus emitted versus active phases.
It is not a dynamic-validator light client or native state-sync implementation.

## Not decided or implemented here

Public governance, staking/slashing, authority rotation/recovery, fee/rate policy,
existing-chain upgrade, composite money/registry root, full ABCI adapter, proposer
priority audits, dynamic wallet/receipt/explorer adapters and dynamic state sync
remain separate. Registry hashes are not coin-state proofs. Existing static
verification must continue rejecting unrecognized validator changes.

Next, integrate an explicit fresh experimental monetary protocol with a shared
atomic boundary. Then exercise actual CometBFT addition/removal/reweight/cancellation,
unauthorized and stale commands, quorum loss, absent new validators, recovery around
emission/activation and an observer restoring across the boundary. Wallet obligations
must survive or refuse unsupported evidence without being released.

No source test is production custody, independent review, network qualification or
deployment authorization. Parallel PR #24 is a distinct witness implementation;
proposal numbering must be reconciled before those branches are combined.
