# Retained bootstrap and final-Apply crash acceptance

28 September 2026. Parent PR #20: `66e5ead0566b24346224ca99b6f38b821d37031d`,
tree `232562a71a82b71acd1fe8d76e62f9067c39425c`.

This extends acceptance tooling, not the monetary or snapshot protocol. All
`src/` files, wallet/delivery/archive/explorer implementations and transaction
formats remain unchanged. The original nine-profile matrix remains required on
the same exact candidate. Prior results are not inherited as fresh execution.

## Four explicit scenarios

`check_state_sync_faults.py` defines retained P1, retained P3-SMT, final-Apply crash
P1 and final-Apply crash P3-SMT. Retained scenarios set the existing keep-two local
block-result policy on all five applications. A fresh fifth node must restore a
snapshot, execute a specifically signed later payment through ordinary block sync,
and converge with the frozen source state. Source and target must expose exact
retained windows while both native receipts survive. The source snapshot-height
local result must be pruned by the end. Native receipts and engine blocks are not
pruned. Combined retention-plus-crash is not defined here and is explicitly refused.

The snapshot marker is checked against an independently verified signed H+1
commitment, not an unsigned RPC app_hash label. The existing verifier checks all
signature slots, quorum, pinned static genesis and exact height. Only that fixed
height is retried within a bounded wait. The signed commitment is retained so the
supplemental matrix can reverify it rather than trust a status word.

The crash scenarios use `scripts/serve_abci_state_sync_crash.py`, a disposable test
entry point. It wraps the ordinary process-local `_install` call. After the real
method commits and returns, it verifies the durable checkpoint/marker and absence
of ordinary block rows, atomically writes an observation, then SIGKILLs itself
before Apply returns. The production application entry point has no crash flag.

The runner reaps that exact PID, requires -9, revalidates the durable native state,
stops the target engine, removes only the recorded Unix-socket device/inode, and
reopens the same application database and CometBFT home. No database, engine state,
signing state or genesis is reset. The recovery child must observe a successful
`checkpoint_recovery=True` install. Same-height recovery must preserve AppHash;
newer recovery must precede the later signed payment. No manually forced restore
is used when the engine fails to reach the prebound gate. Missing evidence or an
unexpected recovery path cannot become a pass. Initial/restarted logs are separate.

## Commands

Use a clean POSIX checkout and already-installed pinned dependencies/real engine:

```sh
python tools/release/check_release.py --output ../new-local
python tools/release/check_network.py --cometbft /path/to/cometbft \
  --engine-sha256 EXPECTED_SHA256 --output ../new-network
python tools/release/check_state_sync_faults.py --cometbft /path/to/cometbft \
  --engine-sha256 EXPECTED_SHA256 --output ../new-bootstrap-faults
```

Outputs must be new and outside the checkout. The supplemental matrix verifies
clean source commit/tree, tracked bytes/modes, manifests and engine digest, then
rechecks source and binary before scenarios and afterward. Each scenario owns its
directory and public genesis. Failure logs and a failed final report are retained;
missing engine yields unassessed with zero scenarios. No downloads occur in either
matrix. Source/toolchain hashes are not independent host attestation.

Even a pass leaves release_status=blocked, public_network_ready=false and
real_funds_ready=false. These are one-host process tests, not power-loss or hostile-
host custody qualification. Independent operators, partitions, dynamic validators,
security review, custody, economics and public operation remain separate.

## Source-side evidence scope

The uploaded return ZIP matches
`bd53926dc42854eccd3db58e5b986eb1d0141525d984ebe97cd74b6411344d11`.
All 710 manifest entries and 273 source files/modes reconstruct the published tree.
Its 431 evidence files preserve original failures and final results. Returned local
case IDs were reconciled (1,373), nine saved scenario reports revalidated (406
checks), seven saved payment certificates reverified and four archived receipts
cryptographically reverified. That is offline evidence review, not another engine
run or independent observation of Codex's host.

New flat/SMT application tests actually SIGKILL and reopen the target, execute a
nonempty post-snapshot payment and reject replay. Matrix inputs and committee
signatures are synthetic controls, never substituted for actual validators.
Initial test-only header fixtures omitted a required predecessor and then supplied
one at height one; their error logs are preserved, and fixtures were corrected
without weakening signature/header checks. Neither error is an on-chain attack.

This runtime has no pinned CometBFT executable/module cache. An ordinary build
attempt failed during dependency-host DNS lookup before compilation. The new
four-profile matrix therefore remains unassessed until a real-engine run. No
Actions, paid compute, deployment, real funds, DNS/site change, Resident/Luna work,
force-push or merge is performed by these tools.
