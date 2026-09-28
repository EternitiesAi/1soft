# Retained state-sync and final-Apply crash acceptance

28 September 2026. This gate supplements the existing nine-profile one-host
CometBFT matrix. It does not replace or inherit that matrix's results. Any source
change requires both tools to execute again on the exact clean candidate.

## Four real-engine profiles

`check_state_sync_faults.py` runs the pinned `scripts/run_state_sync.py` four ways:

- protocol 1 with `--block-history-keep 2`,
- protocol 3 / `smt-v1` with `--block-history-keep 2`,
- protocol 1 with `--final-apply-crash`,
- protocol 3 / `smt-v1` with `--final-apply-crash`.

Retention is configured on all five applications. The new node must still restore,
commit a post-snapshot transfer through ordinary block sync, converge to source,
preserve complete native receipts, retain only its local two-block result window,
and keep its bootstrap marker. The source snapshot-height block result must be
pruned by the end without preventing state sync. This still does not prune native
receipts or CometBFT's own block/evidence stores.

The crash profile uses `serve_abci_state_sync_crash.py`, a test-only supervisor.
Its first child runs the ordinary BlockApplication/ABCI server but wraps only the
process-local `_install` call. Immediately after SQLite's durable snapshot install
returns and before `ApplySnapshotChunk` constructs a response, the child sends
**SIGKILL to itself**. The supervisor records the observed signal, refuses an
unexpected exit, removes only the crashed child's owned Unix-socket inode, and
waits for the runner's explicit local resume marker.

The runner stops the target CometBFT process, verifies that the application database
contains exactly the marker-matching snapshot checkpoint and no locally executed
block rows, resumes the application, and restarts the SAME node home. The second
child observes the existing checkpoint-only recovery path and records only after
`_install(..., checkpoint_recovery=True)` succeeds. Then normal state sync/block
sync must continue and the target must execute the later native payment.

This test-only wrapper changes no monetary, state-sync, wallet or ABCI wire rule.
It is not a production crash handler and must never be used as a validator service.
A passing one-host SIGKILL test is not hardware power-loss durability, hostile-host
custody, multi-machine availability or independent validator qualification.

## Run

After the current local release profile and the existing nine-profile network
matrix pass on the SAME exact commit:

```sh
python tools/release/check_state_sync_faults.py \
  --cometbft /absolute/path/to/cometbft \
  --engine-sha256 EXPECTED_SHA256 \
  --output ../new-state-sync-fault-results
```

Missing or wrong engine is not simulated. Old reports are not imported. Every
scenario binds the source commit/tree, exact `run_state_sync.py` bytes, root source
manifest and binary digest. Status words or generic checks cannot satisfy the gate.

## Still outside this gate

Independent multi-host validators, simultaneous network partitions during restore,
filesystem/hardware power loss, malicious local OS/storage, dynamic validator-set
upgrades, production key custody/recovery, security review, public economics,
deployment and real funds remain separate. No result here changes the overall
release-blocked status.
