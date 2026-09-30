# P4 client and node-recovery integration

30 September 2026. This candidate deliberately reconciles the P4 client branch
from PR30 (`7be396101982f4ab14ede6104d5aae2db4485d9e`) with the additive recovery
tools from PR29 (`c256601bfa3e511b7d6723d074e1df2bd0ce8f0c`). Both share PR28
`b73a88ca53666972ae2c8ce35fd9edb7ac0cb41c`. Neither remote PR was merged.

## Compatibility and provenance

| Surface | Integration decision |
|---|---|
| Complete native `src` tree | Unchanged: `7eca75793b8f083216fdfa4a64102c0555713357` |
| P1/P2/P3 and static-client P4 refusal | Preserve existing implementation and regression gates |
| P4 read, wallet, delivery | Keep PR30's three supplied component trees byte-identical |
| Recovery dependencies | All 43 pinned dependency files match PR30 and original PR28 bytes |
| Recovery tools | Start from PR29's exact additive subtree; strengthen its acceptance evidence and driver |
| Production/release authority | No change; development qualification only |

This is a review of bounded observable behavior. Matching native bytes and fixture
results does not establish universal equivalence or production security. The real
engine profiles must run against the complete, clean final candidate; historical
parent receipts do not qualify this source automatically.

## Recovery evidence

`tools/protocol4-recovery/scripts/run_engine.py` runs two disposable, loopback-only
profiles against explicitly pinned CometBFT 0.38.25:

- **Bootstrap after turnover:** four initial validators transition to a roster
  containing one newcomer. The removed validator stops. A fresh sixth node installs
  a format-2 snapshot under CometBFT's state-sync trust policy. The harness pauses
  the last chunk reply, inspects the durable untouched snapshot, then releases it.
  Every earlier `/block/H` must specifically report `protocol-4 response unavailable`.
  A third original payment executes after the snapshot and source/target state agrees.
- **Lost Commit reply at emission:** the app process is killed after the validator
  update and payment state are durable, before its Commit reply. The controller
  reaps that exact PID, checks the checkpoint, stops its engine, and removes only
  the recorded dead Unix socket. It reopens the same database inode and engine
  node identity. A later payment executes, and complete local responses account for
  exactly one update-emission height.

Each profile replays the bounded native/registry history, verifies every adjacent
signed header through H+1, matches stored block hashes to those headers, and checks
the exact original monetary receipts. The crash check also compares the stored
request fingerprint and full response before/after recovery. Each local block
response is checked against deterministic replay, with complete coverage from
genesis or the separately observed snapshot height plus one.

The report retains per-height unavailable-query code/log/value, source identity,
engine digest, public genesis, checkpoint evidence and bounded sanitized process
logs. `consensus_executed` is false before any engine starts, null if started but
not yet observed, and true only after an owned engine reports a committed height.
Started processes and maximum observed heights are separately recorded. These
fields describe the controller's observations, not independent operator testimony.

The test wrapper alone contains the kill hook. Native runtime files, snapshots,
signing behavior and ordinary ABCI entrypoints are unchanged. Fresh fixture keys
and databases stay in a private temporary directory and are removed after owned
process groups stop. No existing node home is reset or reused.

## Driver corrections and retained failures

Read-only reviews identified incomplete accounting of non-tip block responses,
loose numeric RPC parsing, missing owned-engine liveness checks, and incomplete
descendant cleanup/diagnostics. Focused regressions cover those fixes, stale
snapshot release, interrupted runs, signed block identity and restored request
identity. The recovery component now registers 89 tests (20 beyond the supplied
69). The original 137-case regression selection overlaps the existing release
profile and must not be added again to the distinct total.

The first real bootstrap attempt rejected the supplied three-second discovery
interval: upstream config validation requires zero or at least five seconds.
The driver now uses five. A second attempt installed the snapshot but the new
evidence assertion expected an empty JSON string; real CometBFT RPC represents
the empty query value as null. The corrected check requires exact integer code 1,
the specific unavailable-response log, and an empty value (null or empty string).
It still rejects other query failures and nonempty values. Both failures are kept
in the return evidence. Subsequent exploratory bootstrap and Commit-loss profiles
passed before final source qualification; final receipts identify their own commit.

## Qualification commands

Run from the clean candidate with the pinned Python dependencies installed.
Every output path must be fresh and outside the checkout. No download, hosted
workflow, public listener, deployment or real funds are part of these commands.

```sh
python tools/protocol4-client/tools/verify.py --native-root . --report ../read.json
python tools/protocol4-wallet/tools/verify.py --native-root . --report ../wallet.json
python tools/protocol4-delivery/tools/verify.py --native-root . --report ../delivery.json
python tools/protocol4-recovery/tools/verify.py --native-root . --report ../recovery.json
python tools/protocol4-recovery/tools/verify.py --native-root . --regressions --report ../regressions.json
python tools/release/check_release.py --output ../existing-release
python scripts/run_protocol4_engine.py --engine PATH_TO_COMETBFT \
  --engine-sha256 INDEPENDENT_BINARY_SHA256 --output ../baseline/result.json
python scripts/run_protocol4_delivery_engine.py --engine PATH_TO_COMETBFT \
  --engine-sha256 INDEPENDENT_BINARY_SHA256 --output ../delivery-engine
python tools/protocol4-recovery/scripts/run_engine.py --cometbft PATH_TO_COMETBFT \
  --engine-sha256 INDEPENDENT_BINARY_SHA256 --profile bootstrap-after-turnover \
  --output ../bootstrap
python tools/protocol4-recovery/scripts/run_engine.py --cometbft PATH_TO_COMETBFT \
  --engine-sha256 INDEPENDENT_BINARY_SHA256 --profile commit-reply-loss-at-emission \
  --output ../commit-reply-loss
```

The existing release runner does not discover the four P4 add-on suites. Run all
four explicitly, and retain the full-response P4 vectors and official cached Go
oracle receipt supplied in the return ZIP. Engine absence is unassessed, never a
fixture pass. Complete source, invocation logs and `CODEX_RESULT.md/json` in that
ZIP bind each result to the tested revision.

## Remaining boundaries

These profiles use one host and disposable keys. They do not qualify independent
operators, host/disk power loss, production signer custody, whole-workspace rollback,
public RPC/peers, unbounded history/pruning, public governance/economics or real funds.
P4 recovery replaces one of four validators; PR30's separate eight-node payment
profile tests full four-of-four turnover and must remain part of this candidate's
qualification. P1/P2/P3 engine scenarios require their own current receipts.

The wallet still has one canonical local signing/reservation journal. A dispatch
claimed before I/O can remain unresolved indefinitely. No retry, rearm, reset,
cancellation, replacement signature or cross-device coordination was added.
Legacy static wallet/explorer/receipt clients continue to refuse P4. A successful
development run does not authorize a public network or production release.
