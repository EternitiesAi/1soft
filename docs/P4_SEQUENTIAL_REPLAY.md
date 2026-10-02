# Protocol 4 sequential proof replay

The read-side verifier starts one disposable native ledger from the externally
pinned genesis and executes the complete, ordered history once. It accepts no
snapshot, caller ledger, previous report or persistent cache as a starting point.
Every header's signatures, ancestry, fixed trust period and future-time bound are
verified before monetary inputs execute. Every block still checks signed DataHash,
the prior AppHash, registry roster schedule and the following signed AppHash.

Money uses the same ordered native-operation helper as the node, including exact
signatures, nonce lanes, fees, grant/shared-budget checks and duplicate-execution
refusal. Registry execution and final composite bytes are unchanged. The supplied
checkpoint must equal the complete reconstructed state. The original full state
audit still verifies the complete receipt chain at the end. An unexpected partial
execution failure closes the disposable ledger; it cannot resume the half block.

The node retains its original per-block snapshot restore and receipt checks.
No journal format, native transaction bytes, protocol 1/2/3 behavior, state-sync
format, trust policy, signing authority or development limit changes. Replay is
local historical read evidence, not a claim about independent validator hosts,
actual ABCI observations, current spending authority or latest state.

Parity tests compare every block's state/result and the entire read report with
the original per-block restore path, including two validator handovers and a
committed rejected duplicate. Negative cases check invalid headers, stale trust,
changed checkpoints, skipped/repeated heights, caller genesis mutation, imported
state arguments and interruption after an actual first monetary operation.

`tools/protocol4-client/scripts/profile_replay.py` measures a single local
verification over a pre-existing frozen disposable wallet fixture. It reads no
keys, changes no journal, preserves the original historical clock and binds its
sample to the complete clean Git tree. Counterbalanced measurements and raw
results belong in the run's evidence directory. Receipt signatures no longer
reverify the growing prefix at every block. State snapshots, AppHash serialization,
header verification and bounded complete history remain; this is not constant
space, public throughput qualification or a substitute for history policy.
