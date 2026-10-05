# P7 owner treasury development profile

This successor gives one immutable Ed25519 owner canonical enrollment, revocation
and key rotation over two stable spending-grant slots. It preserves the frozen
P1-P6 contracts and receipts. Candidate implementation/tests exist; actual clean
four-validator qualification and delivery must be registered before calling this
consensus-qualified. Public deployment and production custody remain unassessed.

## Exact network and proof identity

Every payment contains30 public fields and a3200-byte Halo2/Pasta proof in a4168-byte
wire. Owner sequence, grant generation, owner epoch/key commitment and selected
agent key participate in the relation/context. The new VK is
`a02861479050d671419f1e2146410ab3130d3766185898de0140bac4743c17f2`.
Universal deterministic K14 parameters match the earlier profile, which does
not make profiles or proofs interchangeable. `tools/owner-treasury-lab/PROFILE_V1.json`
defines the fresh identity. P7 additionally requires the native Poseidon532
network field derived from the versioned immutable public bootstrap core.

The exact external full genesis pins the profile, worker binary, KAT, roster,
owner state and initial synthetic value. Chain/roster/worker/public bootstrap
changes stale every proof; a valid laboratory KAT from another domain is refused.
Full-state certificates authenticate stateH using a quorum-signed headerH+1 and
independently replay owner/payment rules with the actual pinned worker. This is
AS-OF evidence; no freshness or independent-operator claim follows.

## Lifecycle and value safety

Commands require exact current sequence/context, expected old generation and
commitment, effective height, profile/genesis/chain/owner identities and a real
Ed25519 signature. Enrollment is0->1 once; rotation old+1; revoke clears only
active commitment and retains the last key as quarantine metadata. Commands
cannot change parent, notes, fees or nullifiers. Payments consume authority and
value atomically. Both transaction orders serialize; two competing commands
prepared from one state have one successor. Global sequence stales prepared
proofs without relabeling unrelated notes. Old-generation notes remain unusable;
no migration, automatic replay/retry, owner-key recovery or minting exists.

Finalization is staged until a FULL-sync WAL SQLite commit. Restart requires exact
genesis and full replay of state, signed command/payment receipts, results,
request identity and byte-exact response. A unavailable or changed worker stops
the operation instead of becoming an ordinary invalid transaction. The worker
executes a remeasured inode with CPU/address-space/wall/output limits on a trusted
POSIX host. It is verifier-only; there is no seccomp/hostile-host claim.

## Local reproduction

Build `tools/owner-consensus-bridge/Cargo.toml` and the separate synthetic prover
`tools/owner-treasury-lab/halo2/Cargo.toml` with locked offline dependencies and
bounded build jobs. Provide the exact CometBFT0.38.25 binary, measured worker,
synthetic prover and template laboratory directory to `scripts/run_protocol7_engine.py`.
Select `--scenario rotate`, `reactivate` or `enroll`, and a fresh output path.
Each run owns loopback-only nodes, generates a fresh roster/domain/proof set,
records process exits and exports public receipts/raw sanitized logs without
validator private keys or live databases. `--candidate` can diagnose a dirty
checkout but never produces a qualified status.

Verify each clean report with `tools/release/check_protocol7.py REPORT --worker BINARY`.
The checker requires the qualified Git objects, exact current/committed dependency
source, measured binary, all12 actual proofs, exact artifact/process rosters,
typed startup/check results and independently replayed signed-state receipt.
Missing or changed evidence refuses qualification.

Limits: four equal-power static validators, two grants,64 heights/history
transactions,16 notes,32 typed receipts,262144-byte state,8192-byte transactions,
two transactions per block. These deliberately finite limits are development
gates, not a throughput or production supply model. Synthetic fixtures use a
preseeded generation2 note. Privacy does not hide owner/topology/validator metadata.

Next integration: certified P7 client recovery/holds, then safe proving/note
discovery/redemption and custody, scaling, independent audit/operator rehearsal
and selected production economics. P6 wallet receipts do not certify P7.
