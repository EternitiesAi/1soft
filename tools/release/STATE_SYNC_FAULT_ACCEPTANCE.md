# Retained state sync and final-Apply process interruption

28 September 2026. Exact source basis: PR #20 at
`66e5ead0566b24346224ca99b6f38b821d37031d`, tree
`232562a71a82b71acd1fe8d76e62f9067c39425c`.

This change extends acceptance tooling, not the monetary state machine. Existing
native source, ABCI message schema, snapshots, signing, reservations, explorer and
receipt-archive implementations are unchanged. The failed earlier publication
scripts are not a release artifact. This version is built from the directly
verified Codex return, not an uncommitted tree from those attempts.

## Test-only crash boundary

`scripts/serve_abci_state_sync_crash.py` supervises a disposable application child.
The child runs the ordinary BlockApplication and private ABCI server, wrapping
only its process-local StateSyncManager._install method. After the real method
returns from its durable snapshot installation, the wrapper records its height,
AppHash, PID and inactive transaction state, then pauses without returning to
ApplySnapshotChunk. The supervisor sends SIGKILL to that exact child, observes
exit -9, and reads the durable checkpoint/marker with zero executed block rows.
No final Apply response can be constructed by the paused call.

The supervisor removes only the original Unix socket's captured device/inode,
not an arbitrary replacement path. It waits for a new run-bound resume record.
The runner stops the target engine, requests resumption, then restarts the same
CometBFT home. The second application child records an observed successful
checkpoint_recovery=True installation before normal operation continues. It does
not repeat the retention option; the persisted local policy must survive.

This wrapper is NOT a production recovery process. There is no such hook in the
normal server or consensus code. A process being killed after a commit is not
hardware/power-loss testing, OS compromise resistance, or independent validation.
Control files are bounded, private, exclusive observations owned by the test
runner. They are not cryptographically signed node attestations. Missing or
partial records remain incomplete; records from another run cannot satisfy the
acceptance validator. On interruption the supervisor terminates its own child.

## Retained-history bootstrap

`run_state_sync.py --block-history-keep 2` applies the existing retention policy
to all five applications. A source's old local block-result row may disappear
before bootstrap inspection. The runner therefore retrieves the exact H+1 signed
commitment and independently verifies its committee signatures against the generated
engine genesis, comparing its AppHash to the restored marker. A bare endpoint hash
is not sufficient evidence. CometBFT's own historical block store is not pruned.

The target must process the exact nonempty post-snapshot transfer, converge with
the source at the frozen height, retain the marker, and keep the bounded local
window while preserving both native receipts. Both source and target window
snapshots are checked. The source snapshot-height local block row must actually
be pruned by the end; missing unrelated data is not called deliberate pruning.

## Six-profile supplement

From the exact clean checkout, with the genuine pinned engine already available:

```sh
python tools/release/check_release.py --output ../new-local-result
python tools/release/check_network.py --cometbft /absolute/path/to/cometbft \
  --engine-sha256 EXPECTED_BINARY_SHA256 --output ../new-original-matrix
python tools/release/check_state_sync_faults.py --cometbft /absolute/path/to/cometbft \
  --engine-sha256 EXPECTED_BINARY_SHA256 --output ../new-fault-matrix
```

The supplement covers retained-only, crash-only, and combined retained+crash
scenarios, each in P1 flat and P3 SMT modes. It does not replace the original nine
profiles or the official wire check. Parent results belong to their exact revision.
No engine download, Actions run, deployment or paid compute is performed.

Every scenario binds the exact source commit/tree, runner and manifest hashes,
protocol, commitment mode and supplied engine digest. Named checks must have
matching details. The validator rechecks the supplied genesis, signed snapshot
anchor when retention is enabled, native final state/AppHash and complete receipt
history, and exact post-snapshot signed payment. SMT runs must also supply a raw compact
proof response that is reverified against that final native state; the genesis
protocol and commitment format must match the selected profile. Crash observation IDs, child PIDs,
kill signal, committed snapshot identity and recovered marker must agree. Numeric
booleans, generic passing labels, missing receipt bodies and placeholder histories
are not enough.

Before and after scenarios, source and engine identities are rechecked. Result
files/logs are retained in new per-profile directories. A failure leaves a failed
terminal matrix report; it does not erase earlier evidence. The report distinguishes
zero started engine scenarios from an attempted scenario with unknown outcome.

## Local test scope and acceptance status

The source-side tests exercise actual SIGKILL over the real private ABCI socket,
then a second successful Apply and a NEW native transfer, in all four local
application combinations (flat/SMT and retained/default). Source and target states
must agree after further blocks; replay still fails, policy survives without a
repeated flag, and an ordinary initialized node can no longer accept a snapshot.
These are native application tests, not CometBFT consensus. Separate synthetic
report tests check that the matrix refuses changed or incomplete evidence.

The complete release profile includes these new tests through existing discovery.
Exact test results are delivered with the candidate, not preclaimed by this file.
The supplemental real-engine matrix remains unassessed until actually executed.
Even a full local engine pass leaves release_status=blocked: independent-host
operations, security review, production custody, economics/genesis and public or
real-funds readiness remain separate. PR #11 and unrelated optional branches are
not part of this continuation. No native receipt pruning is introduced.
