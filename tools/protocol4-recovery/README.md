# P4 bootstrap and Commit-reply recovery acceptance

29 September 2026. Additive to PR #28, commit
`b73a88ca53666972ae2c8ce35fd9edb7ac0cb41c`, tree
`123e5bfc57d42ee31736969f61aa5a6d32482832`.

This is acceptance instrumentation, not a wallet, governance change, production
service or release approval. Existing P1/P2/P3 and P4 runtime files are unchanged.
Legacy static clients must continue rejecting P4. No public endpoint, Actions,
paid compute, deployment, DNS/site, Resident/Luna work or real funds are involved.

## Local process coverage

The test-only `serve_probe.py` delegates to the ordinary P4 dispatcher and storage.
At an explicitly selected Commit height (or the first actual update emission),
it independently replays the durable checkpoint, atomically writes a bounded
observation, and SIGKILLs **its own process** before the ABCI handler writes the
Commit response. The observation binds run ID, PID, genesis, composite state,
replay history, stored response, epoch, receipt count and the actual socket inode.

The controller reaps that exact process, revalidates its checkpoint from SQLite,
and removes only its recorded dead socket. It reopens the same database. Tests at
scheduling, emission, activation and payment heights require exact saved response
replay, unchanged state on repeated Commit, later ordinary execution, no duplicate
payment and no repeated validator update. This is process interruption, not machine
power loss, malicious-host resilience or global exactly-once submission.

Format-2 bootstrap tests restore queued, emitted and active registry states through
actual private ABCI sockets. The recipient initially has zero locally executed
block records. Historical `/block/H` remains unavailable after import, and later
payments/blocks must match the source. P4 intentionally removes `snapshot_marker`
after ordinary block execution starts; this test does not import P1-P3's different
marker-persistence rule.

## Genuine-engine gate: authored, not executed in the authoring runtime

`run_engine.py` has two separate profiles. It requires an explicit real CometBFT
0.38.25 executable and SHA-256, and an exact clean **complete repository checkout**.
The supplied binary is checked before execution. Missing engine reports unassessed
with zero processes. Test directories are new, private and outside the checkout.

`bootstrap-after-turnover` starts four validators and a replacement validator,
executes a payment, schedules replacement/reweighting, observes activation and
executes another payment. A sixth, fresh nonvalidator boots via format-2 state sync
from the changed-validator chain. Its installed checkpoint is inspected before the
last Apply reply is released, with no block records imported. A third signed
payment is submitted only afterward. The target must continue through normal block
execution and match a source checkpoint.

`commit-reply-loss-at-emission` uses five nodes. One still-active validator's
application dies after committing the update-emission block but before replying.
Its engine is stopped and restarted on the same home, and a new application process
uses the same database inode. Later payments must execute once. The stored emitted
response stays identical and only the original emission height contains updates.

Both profiles retain exact signed payment bytes and all signed headers from the
first controller-pinned block through the matched state's H+1 commitment. The
acceptance checker independently replays native payments and administrative
signatures, derives current/next validator rosters, verifies every commit and block
data root, enforces full predecessor identity, and checks the final state. It uses
a fixed one-hour **test-controller** trust window, not a production light-client
security policy. No static verifier is relaxed and no wallet authority is created.

Matching checkpoints are captured while the local chain is running; they are not
claims that the chain stopped forever at a globally latest height. Genesis and the
first header are pinned by the local test controller, not an independent operator.
Signed fixtures can satisfy the pure report checker in unit tests; only an actual
recorded execution of the runner can support a new real-engine claim.

## Usage

From the full PR28-based checkout with existing pinned dependencies installed:

```sh
python tools/protocol4-recovery/tools/verify.py --native-root . --report ../new-local.json
python tools/protocol4-recovery/tools/verify.py --native-root . --regressions --report ../new-regressions.json
python tools/protocol4-recovery/scripts/demo.py --output ../new-process-demo

python tools/protocol4-recovery/scripts/run_engine.py \
  --cometbft /absolute/path/to/cometbft --engine-sha256 EXPECTED_SHA256 \
  --profile bootstrap-after-turnover --output ../new-p4-bootstrap

python tools/protocol4-recovery/scripts/run_engine.py \
  --cometbft /absolute/path/to/cometbft --engine-sha256 EXPECTED_SHA256 \
  --profile commit-reply-loss-at-emission --output ../new-p4-commit-recovery
```

The package's dependency slice can run the local verifier/demo but is **not** a
complete repository and must not run the engine gate or full release checker.
No current command downloads a binary or dependencies. The ordinary P4 node and
its earlier engine/Go oracle gates remain separate requirements.

## Evidence and remaining limitations

The final local component profile passed 69 distinct tests; 137 selected inherited
native/account/budget/P4-refusal tests also passed. These are 206 distinct Python
cases, not the 1,622-case full P4 release profile. The JavaScript reference passed
30. Four weaker disposable variants were caught by assertion failures. Raw reports,
case IDs and seven actual process demonstrations are delivered with the package.

Every one of the 29 native runtime modules matches PR28's exact `src` Git tree
`7eca75793b8f083216fdfa4a64102c0555713357`. Nine new executable/test files and 43
pinned runtime/helper/regression dependencies match before and after the tests.
The source slice was reconstructed from the previous registry delivery plus exact
published changes; unrelated PR27/28 files were not silently replaced with older
ones. The original P4 handoff ZIP and its raw real-engine logs were not available
in this runtime. Codex's reported 27 engine checks remain evidence for b73a88c,
not executions of this new gate.

The P4 bounded-history limit (512 blocks, 16 MiB snapshots), static-client refusal,
no dynamic verified wallet/explorer/archive, and development-only administrative
policy remain. Real-engine bootstrap at queued/emitted phases is not covered by
the new bootstrap profile; those phases are exercised locally only. Independent
hosts, Byzantine testing, hardware durability, production custody/governance,
economics and value-bearing release remain unassessed.
