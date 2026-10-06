# P8 authenticated node recovery

6 October 2026. A separate bounded recovery store and private ABCI server for the
frozen P8 recipient relation. The original P8 application, profile, circuit,
genesis, state and AppHash rules remain unchanged. Existing stores are refused
across the two schemas; there is no automatic migration.

## Authentication and history

Snapshot format8 uses domain `1soft/protocol8-recipient-recovery/snapshot/v1`.
Its canonical payload contains the exact full genesis, height, AppHash and complete
P8 consensus state/history. Metadata pins the full genesis SHA, bootstrap,
profile, worker and KAT, plus exact payload hash and geometry. The full genesis
includes the static validator roster and initial notes; the bootstrap digest
alone cannot authenticate these excluded fields.

The engine supplies an independently light-client-verified AppHash in the private
ABCI OfferSnapshot callback. The callback has no signed-header field; the
application trusts the owner-only engine control boundary, and compares metadata
against that external AppHash. Peer descriptors and hashes are corruption checks,
never consensus authority. Direct application tests do not establish light-client
verification; the actual CometBFT gate is a separate requirement.

Before import, every historical block and native proof is replayed from the exact
externally pinned genesis. The resulting AppHash must match the trusted offer.
The snapshot includes accepted and refused decided transactions and empty blocks.
It never supplies historical private FinalizeBlock requests/responses.

The recovery schema keeps `p8_snapshot_origin` with the immutable canonical base
payload, height, AppHash and domain-separated payload hash. Real `p8_blocks`
responses exist only from origin+1 onward. Reopening replays the origin and audits
each contiguous local response/transition in that suffix. The marker stays as
local provenance, outside the consensus AppHash. It is not a remote certificate.

## Bounded import and crash recovery

Payloads are capped at544,768bytes, metadata at4,096bytes, chunks at4,096bytes and
133chunks, served cache at two snapshots. Height64, sixteen notes and32 retained
transaction attempts remain the original finite P8 limits. This complete-history
model is a development qualifier, not pruning or long-term scale.

Only a fresh uninitialized store or an untouched marker-exact checkpoint with no
local response rows and no pending finalization can accept an offer. Exact
same-height re-offers are idempotent. Newer trusted snapshots must extend the
entire known origin history. Lower snapshots, conflicting same-height payloads,
ordinary initialized stores and stores with local progress refuse replacement.
Identical duplicate chunks are stable; changed duplicates reject; future indices
request the missing chunk. Partial chunks are process-local and disappear on restart.

Checkpoint and origin install in one SQLite transaction. Database failure rolls
back both. A post-commit/pre-refresh exception closes the application and requires
reopening; stale in-memory state cannot be served. The production server has no
fault argument. A separate run-token-gated test server can exit96 after durable
import but before the final Apply response, or record callback events.

## Verification

`tests/test_protocol8_recovery.py` uses an explicitly fake verifier for schema,
suffix, chunk, rollback and crash mechanics. It makes no proof/consensus claim.
`scripts/run_protocol8_recovery.py` requires the pinned actual CometBFT0.38.25
binary, actual verifier/helper/prover and fresh synthetic notes/validator keys.
Four validators commit a received note. Provider0 freezes atH while validators1–3
supply H+1/H+2 headers to two light-client RPC sources. A fresh nonvalidator4 imports,
crashes after snapshot commit, then recovers through an observed real-engine
re-offer from its unchanged application/engine stores. Native replay and signed
AS-OF state verification supplement the actual callback/engine logs.

The target must rejoin, supply authenticated state for a genuine recipient wallet
import/spend, agree with all four validators on the payment, retain only real
post-origin responses, and survive a same-store restart. The runner retains failed
reports and sanitized bounded raw logs/public proofs; no private request, opening,
AES key, wallet store, validator key or node home is included.

The closed report checker inspects receipt consistency and artifact hashes.
Separate native replay verifies public proofs and signed state independently.
Qualification receipts must name the exact clean source and engine SHA; this design
document alone is not an executed result.

Independent operators/hosts, signer recovery and double-sign fencing, hostile
networks/hosts, pruning, dynamic validators, power-loss durability, production
light-client policy, privacy/custody, scale, economics, public launch and external
specialist review remain open. Existing P1–P7 receipts are not relabeled.
