# Fresh protocol 4 state-sync qualification

This opt-in development gate uses four new source validators and one never-started
nonvalidator with the exact pinned CometBFT 0.38.25 binary. The ordinary P4
application, wire dispatcher, protocol versions 1/2/3 and historical manifests are
unchanged. Unit coverage does not qualify either engine profile.

The registered profiles are `basic` and `final-apply-crash`. Each profile requires
a new private Linux/WSL output directory outside the checkout and a separate new
public output directory. Never reuse a completed or failed output. Preserve raw
failures and timeouts. The source must be committed and clean, including untracked
files, before any engine runs.

```sh
python scripts/run_protocol4_state_sync.py \
  --engine /absolute/path/to/cometbft \
  --engine-sha256 218628da07bed5d27e178d38d0bef9ecf46f21b214c8e9fea402fd215fccc024 \
  --private-output /private/new-p4-basic-run \
  --public-output /separate/new-public-p4-basic-run \
  --profile basic
```

Run the interruption profile separately with `--profile final-apply-crash` and
different new output directories. An external bounded controller must save the
actual runner return code, timeout flag, stdout/stderr truncation flag and log
digest as a process receipt. The runner writes a canonical private `result.json`.
It preserves fresh node homes, original raw engine/native genesis, fixed original
read policy, signed payment wires, complete signed evidence, format 2 chunks and
ABCI packets, databases, disposable fixture keys and bounded original logs in the
private directory. Group/world permissions, aliases, missing membership and changed
artifact bytes are refused. Public output contains a deliberate result projection
and log digest records; original stdout/stderr and proof payloads stay private.

Independently validate the originals using the external raw genesis and policy
digests selected for that run:

```sh
python tools/release/check_protocol4_state_sync.py \
  --private-output /private/new-p4-basic-run \
  --process-receipt /separate/controller-process-receipt.json \
  --genesis-sha256 EXTERNALLY_SELECTED_RAW_ENGINE_GENESIS_SHA256 \
  --policy-sha256 EXTERNALLY_SELECTED_RAW_POLICY_SHA256 \
  --engine /absolute/path/to/cometbft \
  --engine-sha256 218628da07bed5d27e178d38d0bef9ecf46f21b214c8e9fea402fd215fccc024 \
  --profile basic \
  --output /separate/new-semantic-validation.json
```

The runner selects and records its fresh controlled genesis, trust height/hash and
original policy before starting either the target app or engine. Those pins are
printed as digests before target launch; snapshot metadata cannot choose trust.
Comet's discovery delay is five seconds, meeting the pinned configuration's
nonzero minimum. All RPC/P2P addresses and peers are loopback; ABCI uses private
owner-only Unix sockets. Heights stay within the existing P4 bound of 512 and
snapshots within the unchanged 16 MiB/64 chunk limits.

The validator requires exactly the twelve common IDs:

- `source-controller-identity`
- `pinned-engine-real-consensus`
- `four-sources-fresh-target`
- `external-genesis-fixed-trust`
- `format2-real-abci-transfer`
- `engine-trusted-apphash`
- `signed-next-height-native-history`
- `exact-composite-native-effects`
- `marker-no-fabricated-blocks`
- `ordinary-payment-continuation`
- `original-policy-current-evidence`
- `complete-owned-process-outcomes`

The crash profile additionally requires `durable-commit-before-final-apply-reply`,
`owned-sigkill-observed`, `same-store-home-restart`,
`snapshot-only-restart-audit`, `actual-checkpoint-reoffer-recovery` and
`rollback-refusal-continuation`. Missing, duplicate, extra, skipped or truthy
nonboolean checks cannot pass.

The test-only wrapper calls the unchanged P4 `_install(payload,
checkpoint_recovery)`, independently audits the actual committed SQLite state
and complete history, and records that the transaction is inactive. Its pause
child then waits inside final Apply before response serialization. The supervisor
kills and reaps that exact PID/birth identity with SIGKILL, removes only the
recorded dead socket inode, and waits for deliberate engine restart. Constructor
reopening must audit the same snapshot-only database; the next actual engine
Offer/Apply must show `checkpoint_recovery=True`. Recovery may accept the same
checkpoint or a newer signed, externally trusted checkpoint. The report labels
`recovery_kind` as `same` or `newer` and retains both original checkpoints;
newer recovery is never described as exact same-height restoration. A lower-height
offer must refuse without changing committed state. Original signed post-sync
payment and ordinary continuation remain required.

At install, `snapshot_marker` matches `committed`, history/state audit succeeds
and the local block table is empty. Every application `/block/1..H` query must
return the specific unavailable-response reason. The target's ordinary response
records begin at H+1. P4 retires its marker on ordinary Commit; a retained legacy
marker is not the P4 contract.

The current proof has an explicit mixed origin: actual target ABCI composite
state at a captured H, target durable replay inputs, and separately collected
source-engine blocks and signed headers 1..H+1. The original P4 verifier checks
signatures, complete ancestry, transaction DataHashes, monetary/admin execution,
every intermediate composite AppHash, validator rosters and the fixed trust
policy. It checks the original signed pre/post payments and current checkpoint
freshness within 300 seconds. This does not claim that the target serves the
existing complete-genesis `p4_rpc.collect` path; that target-only read remains
unassessed. Captured equal checkpoints are compared while source tips may advance.
The same database/home restart is separately authenticated, followed by another
ordinary target advance and a fresh captured proof.

Focused tests include synthetic quorum evidence over actual P4 execution and
real private P4 socket/process SIGKILL/reoffer tests. Synthetic signed fixtures
and application process tests establish local behavior, not live consensus. Both
actual engine profiles remain unassessed until independently revalidated receipts
exist for the exact combined source. `check_current.py` registers their test files
and records the actual engine scenarios separately as unassessed.

Queued/emitted/activated snapshot phases, malformed/truncated/reordered real
engine transfers, maximum-bound resources, independent hosts/operators, public
peer/RPC hardening, hardware power loss, production custody, economics/genesis
policy, external security review and on-chain transaction privacy remain separate
unqualified work. This finite one-host gate involves disposable DEV units with no
value, no production keys and no public deployment.
