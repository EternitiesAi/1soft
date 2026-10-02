# 1soft validator registry — isolated development application

This isolated reference is the execution side of the validator-transition
foundation: authenticated administrative actions, delayed update emission, epoch
activation, durable replay and a registry-specific evidence adapter. Its own
application remains **registry-only** and activates no existing chain. The pure
rules are also promoted to `src/registry_rules_core.py` for a separate opt-in
fresh-genesis P4 money-and-registry development application; see
[`docs/PROTOCOL4_DEVELOPMENT.md`](../../docs/PROTOCOL4_DEVELOPMENT.md). Static
wallet, explorer and archive paths still refuse P4.

Base: local candidate `7d860457fa85950f81aaa67f7cd3c98a979d5bbc`, tree
`24b7a034b26616ee9a6e824da3b7b5e7910e72fb`, directly above published PR #23
`289a78056b86ebdd5878d285027f5c78562e0767`. The separate PR #24 verifier line is
not used or merged. Prior static-validator engine receipts stay on their revisions.

## What the application executes

An explicit `1soft/validator-registry-genesis/v1` defines a registry-only chain,
initial roster, separate administrative public keys, threshold, minimum scheduling
delay, cooldown, minimum validator count and concentration limit. These parameters
are committed through the genesis digest. They cannot be replaced by a transaction,
local configuration edit, supplied snapshot or endpoint response.

The only administrative actions are `schedule` and `cancel`. An action binds the
exact chain and genesis, administrative-policy digest, next sequence number,
expected current epoch and roster, height validity window, and complete operation.
At least the genesis threshold of distinct administrators must sign the exact
canonical, domain-separated body. Every supplied signature is checked, even after
the threshold is reached. Approval order is canonical; duplicates and unknown keys
are rejected. There is no private-key input or signing command in this component.

For this **proposed development policy**, the threshold exceeds two-thirds of 3–16
administrator keys, the roster contains at least four validators, and no validator
may exceed the explicitly configured limit (at most 33.33% of voting power). Admin
keys and every accepted current/future validator roster must be disjoint. These
choices are not a final governance design, proof of independent operators, staking,
slashing, a secure key ceremony or a guarantee of liveness. Compromised threshold
administrators can authorize harmful changes or replace every validator with their
own distinct keys. The protocol cannot infer common key ownership or operator
readiness. Administrative key rotation/recovery and policy amendments are not yet
implemented; losing enough admin keys can permanently block future updates.

One proposal may be pending. Successful actions consume a monotonically increasing
administrative sequence and extend the receipt commitment with the exact submitted
wire digest. Invalid actions consume nothing. Replaying an earlier body or using a
new valid signature subset for that already-executed body does not schedule it a
second time. Ordered conflicting requests cannot both consume the same sequence.
There are no fees, balances, token votes or economic incentives in this profile.

## Timing and cancellation

A proposal included at S must choose emission E at least the configured delay
later (minimum two blocks), and no more than 1,024 blocks later. Its transition is:

| Height | Application behavior | Validator schedule |
|---|---|---|
| S | Record authenticated queued proposal | Existing set unchanged |
| E | Return deterministic `validator_updates` | Existing set still active |
| E+1 | Queue remains emitted | New set appears in `NextValidatorsHash` |
| E+2 | Advance registry epoch and active set | New set active |
| E+3 | Continue with new epoch | Last-commit inputs use new set |

This follows the pinned CometBFT v0.38.25 timing, not immediate activation on receipt
of an approval. Zero power is used only in update deltas for removals. Complete
rosters contain positive power. Proposer priorities are CometBFT state and are not
reimplemented by this application.

Cancellation needs the same administrative threshold, current sequence/base and
exact pending proposal ID. It succeeds **only before E**. Height-driven emission
runs before block transactions, so cancellation in E is too late. After emission,
rolling it back would contradict the engine's schedule; it is rejected. To undo
an active change, administrators must authorize a new forward transition after the
cooldown. Cancelling a queued update does not erase its signed receipt or reuse its
sequence. An approval's validity limits its inclusion, not the life of an already
accepted schedule; approval expiry never silently cancels a committed proposal.

## Determinism and persistence

`RegistryRules` is pure execution. `RegistryApplication` stores its own database,
never a wallet/node database. `check_tx` and `process_proposal` operate on copies.
`finalize_block` computes a candidate and full result; repeated identical calls
return that candidate, while a competing finalized block is refused. No finalized
but uncommitted output activates the saved registry. `commit` atomically records
exact action wires, the response (including updates), state and AppHash. A second
connection cannot overwrite a checkpoint that advanced after its finalization.

Opening or reading the store replays every retained administrative block from the
exact pinned genesis, revalidates signatures, recomputes the state and compares the
saved responses. Rehashing an edited state does not bypass replay. `committed_result`
recovers the old response without executing or emitting it again. An output error
after commit is not a rollback; callers must inspect the persisted height/result.

The database is exclusively initialized, has its own SQLite application ID and
schema, and requires private owned POSIX files/directories. Existing empty or other
databases, unsafe sidecars, symlinks and hard links are refused, not repaired. This
is a trusted-local-filesystem model, not hostile-host or rollback-proof custody.
Read-only SQLite access is not promised to be a forensic no-filesystem-write view.

## Snapshots and evidence

The separate `1soft/validator-registry-snapshot/v1` format retains the genesis and
all administrative blocks. A new store can restore it only after replay and exact
external expected height/AppHash checks. It preserves queued/emitted updates at
restart: a snapshot taken after emission does not emit the update twice. No existing
store is replaced. An I/O failure during a fresh restore may leave an initialized
empty development store, not an automatically retryable overwrite target.

Snapshot hashes alone do not establish who supplied trusted pins. Block identities
in a bare registry snapshot are local records, not authenticated header inclusion.
`verify_registry_history` supplies that additional check: it combines full
administrative replay with the existing bounded, externally pinned dynamic header
witness. It verifies every exact block identity and transaction-data root, prior
AppHash, authorized roster schedule and final H+1 state root. It requires height-one
coverage, registry application version **4001**, and an unexpired witness policy.
It returns registry-authorization evidence separately from the parent's deliberately
unchanged `native_state_verified: false` field. This does not validate native money
state or grant a wallet permission to spend.

The experimental FinalizeBlock codec serializes execution results, validator updates
and AppHash with the official field numbers. It is not wired into the current ABCI
server. The new Go probe checks those bytes against upstream when dependencies are
available. A local protobuf round trip is not an upstream or actual-engine pass.

## Bounds

At most 8 actions and 512 KiB of action wires per block, 64 KiB per action, 512 local
blocks, 512 accepted actions, and 8 MiB of retained registry history/snapshot. Full
replay is intentionally simple and expensive; it is not a scalable production
store. Capacity exhaustion refuses further work without deleting history. It can
halt this development profile and is not a safe public-chain retention policy.
Header witnesses retain their separate 256-header bound, so combined evidence
needs at most 255 executed registry blocks. This adds no native receipt pruning,
CometBFT block pruning, total-disk bound or high-throughput claim.

## Run locally

Use the existing pinned Python dependencies; no dependency installation is performed.
The normal component commands resolve their own source imports.

```sh
python tools/validator-registry/tools/verify.py --native-root .
python tools/validator-registry/scripts/demo.py --output ../new-registry-demo

python tools/validator-registry/scripts/registry.py \
  --genesis /private/registry-genesis.json --genesis-sha256 EXTERNAL_FILE_DIGEST \
  --database /private/new-registry.sqlite init

python tools/validator-registry/scripts/registry.py \
  --genesis /private/registry-genesis.json --genesis-sha256 EXTERNAL_FILE_DIGEST \
  --database /private/new-registry.sqlite inspect
```

The CLI also provides unsigned `draft-schedule` / `draft-cancel`, `check`, offline
`apply-block`, `committed-result`, `export` and fresh-store `restore`. Its
`apply-block` input contains exact `height`, `block_hash` and a canonical base64
`transactions` array. This command executes an explicitly supplied local block;
it neither proposes a block to peers nor claims a consensus decision. Exit 2 on a
rejected action may accompany a persisted block containing that rejection. No
`sign`, `broadcast` or public activation command exists. All new output paths are
exclusive. The demo writes public disposable signed fixtures, never private keys.

## Private CometBFT transition gate

The separate registry-only ABCI adapter can be tested against a local
CometBFT **v0.38.25** binary. It uses protocol version 4001, a disposable
four-validator plus one nonvalidator network on one host, and generated fixture
administrator and validator identities. It never starts the native money app.

```sh
python tools/validator-registry/scripts/run_registry_engine.py \
  --engine /path/to/pinned/cometbft \
  --engine-sha256 EXTERNALLY_VERIFIED_BINARY_DIGEST \
  --output /private/new-run/result.json
```

Choose a fresh output path for each run. The runner verifies a threshold-signed
schedule, its exact three-update FinalizeBlock response, the H+1/H+2 signed
AppHashes, H+1 signed `next_validators_hash`, H+2 signed `validators_hash`
and RPC validator powers,
and actual H+3 last-commit votes. It then stops the retired validator, checks
that the replacement set advances, and restarts a surviving validator using its
same node home and registry database. The report records version/hash, source
revision, public genesis digest, transaction digest, observations and check
results. Process logs are bounded and sanitized; generated private keys and
node homes remain in a temporary private directory and are discarded at exit.

This is same-host real-engine evidence for the isolated registry. The ordinary
restart does not establish crash-replay correctness; there is no atomic native
money-plus-registry state, independent-operator qualification or public network
authorization.

## Remaining integration boundary

Before enabling this functionality on the money chain, decide and review governance,
introduce an explicit versioned native commitment combining registry and money
state atomically, bind engine genesis/InitChain to its registry, add validated
FinalizeBlock and last-commit/next-set handling, and implement handshake/replay
behavior. Then adapt dynamic state sync, wallet, explorer and receipt proofs and
run integrated changing-validator, interruption and quorum tests. There is no
dual-database atomic money/registry commit
in this candidate; the separate test store must not be bolted beside a live money
node and represented as consensus state.

No Actions, paid compute, public deployment, DNS/site, Resident/Luna/Psyche work,
production keys, real funds, merges or force-pushes are performed by these tools.
Independent security review, custody, public economics and value-bearing release
remain separate. See draft SIP-0003 for the next native integration contract.
