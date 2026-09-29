# 1soft validator continuity — development component

Source basis: PR #23, commit `289a78056b86ebdd5878d285027f5c78562e0767`, tree
`bf08af8edd487750ea3476181e96d119febd239c`. This add-on changes no existing
native, ABCI, state-sync, wallet, explorer, archive or release implementation.

## Implemented, not activated

This is the client-verification prerequisite for validator-set evolution. It can
verify adjacent signed CometBFT headers as Ed25519 validators are added, removed,
reweighted or completely replaced. Its separate SQLite store preserves verified
history across interruptions. A pure update preview models announcement and
activation heights.

It does NOT change the chain's validator set. Governance authorization, a new native
transaction/version, ABCI validator-update emission, update persistence/activation,
state-sync through live membership changes and wallet integration remain pending.
The existing static commit_verifier.py still refuses changing sets. Its refusal
is tested, not weakened. This history cannot authorize an old wallet. This is not
a general light client.

## Authentication

The operator independently supplies the exact engine-genesis file digest and an
initial signed header hash/height. Policy fixes supported block/app versions,
trust period and maximum future clock drift. Incoming evidence cannot choose these
pins. Starting at height 1 requires the unchanged genesis set for heights 1 and 2.
Starting later requires an independently trusted checkpoint and current/next sets.

Each step contains exactly format, signed_header, validators and next_validators.
Sets contain lowercase Ed25519 public_key and exact integer power in canonical
descending-power/address order. Addresses are derived. Empty sets, duplicates,
zero/negative member power, overflow, malformed keys and unknown fields refuse.

Existing 1soft protobuf/header/vote serialization is reused. Every signature slot
is checked, including nil votes and slots beyond quorum. Only commits contribute
voting power; strictly more than two thirds is required. Every new header must
extend the complete previous block ID, increase height by exactly one and time
strictly, and use the validator set committed by its predecessor's next-set hash.
Both supplied set roots must match the signed header. No skipping or quorum-overlap
heuristic exists. Adjacent full replacement requires that signed predecessor link.
App/block version changes are not treated as approved software upgrades.

This authenticates historical header continuity under the chosen trust assumptions.
It does not execute blocks, check proposer priority or weighted-median block time,
prove governance authorization, external settlement or independent validators,
detect every fork or guarantee the latest head.

## Time, persistence and limits

The stored trusted tip must remain inside the selected trust period both at start
and commit of a batch. Clock rollback, future drift and expiry during verification
refuse the whole import. Old expired history remains inspectable/exportable without
renewing trust. No reset or automatic reanchor command exists. The allowed period
of 1 second to 7 days and skew of 0 to 300 seconds are development bounds, NOT
recommended production policy or protection after validator keys are compromised.

The store retains canonical evidence, exact height/hash and local acceptance times.
Those times are diagnostics, not independent attestations. Reads reverify the whole
history from the external anchor. Atomic imports require the caller's expected tip
hash; stale/concurrent imports cannot overwrite accepted progress. Process exit
before commit preserves prior history; exit after commit preserves the complete
new batch. A lost return does not imply rollback: inspect before resuming.

Use a new private owned POSIX file separate from node and wallet stores. Existing
empty/unknown databases are not initialized or repaired. Symlinks, hard links and
unsafe sidecars refuse under a trusted local-filesystem model. Hostile same-user
storage, machine power loss and full-workspace rollback remain outside protection.
There is no network access, key access, scheduled task or payment operation.
Capacity: 512 stored headers / 32 MiB without eviction; inputs at most 64 steps /
8 MiB, 256 validators per set and 512 KiB per step. These are not total-disk or
throughput guarantees. Repeated full verification is not a production index design.

## Deterministic preview

preview_update(next_validators, changes, finalized_height) takes the set already
scheduled for H+1. It applies additions, reweighting and removals (power zero) as
one proposed change. Duplicate changes, missing removals, empty final sets and
overflow refuse. Output roots/order are independent of input change order.
It models H+1 next-set announcement, H+2 active validators and H+3 changed
last-commit inputs. It reports governance_authorization_checked=false,
activation_scheduled=false and chain_mutated=false. It does not serialize or submit
ABCI updates.

## Commands

Use the repository's already-installed dependencies:

```sh
python tools/validator-evolution/tools/verify.py --report ../new-validator-tests.json
python tools/validator-evolution/scripts/demo.py --output ../new-validator-demo
python tools/validator-evolution/scripts/validators.py --help
```

The demo combines actual native application execution in flat/SMT modes with
synthetic committee signatures and controlled fixture time. It creates no private
key files, changes no running node and establishes no live validator transition.
Its historic policies are not production configurations.

CLI commands: init, advance, inspect, export, preview. Init requires separate
--genesis, --policy, --store and --anchor inputs. Advance additionally requires
--steps and --expected-tip-hash. Inspect/export are historical. A zero inspection
exit means evidence verified; check continuation_within_local_time_policy separately.
Output is exclusive. No command changes wallet reservations or validator authority.

## Primary references and scope

- Pinned CometBFT v0.38.25 adjacent verification and expiry:
  https://github.com/cometbft/cometbft/blob/v0.38.25/light/verifier.go
- Pinned ABCI++ FinalizeBlock validator-update timing:
  https://github.com/cometbft/cometbft/blob/v0.38.25/spec/abci/abci%2B%2B_methods.md
- Existing serialization/quorum helpers: this checkout's src/commit_verifier.py.

This adds full previous-block-ID and all-signature-slot checks like the existing
project verifier. It is not a byte-for-byte port or qualification of all upstream
light-client modes. SIP-0001 describes pending work; a proposal activates nothing.
No Actions, paid compute, deployment, DNS/site or Resident/Luna changes, real funds,
production keys, force-pushes or merges are part of this contribution.
