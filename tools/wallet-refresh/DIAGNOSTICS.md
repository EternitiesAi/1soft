# Durable read-only refresh diagnostics

## Source and scope

This is an optional-client-only follow-up to xnuonux/1soft PR #8 at
`610b443afed7e73b5938ac7b8873c6a728e7f6c4` (repository tree
`84687715dc89dfd22bd9c578cf9a40ab00fc7999`). All five required add-on files
were reconstructed and matched to that exact remote manifest before development.
The README's Git blob also matched. The fixed-H+1 RPC collector remains unchanged.
There are no changes to native rules, signatures, wallet reservations, catch-up
verification, the consensus interface, any engine runner, or the deployed site.

Codex's handoff and current PR document 61/61 flat-state and 66/66 SMT
real-validator checks after the fixed-commit repair, and 1,062 local Python tests.
Those are inherited reported results, not executions performed for this change.
The first failed optional network run did not retain the client result; its exact
status remains UNKNOWN. This recorder does not reconstruct that lost information.

The latest Windows return named `1soft-wallet-refresh-evidence-a7234f9-20260927.zip`
was not attached and was not found in the two Library searches. Its supplied digest
was not independently checked here. No claim is made to possess or reproduce that
complete final local tree. The accessible source basis is the exact PR add-on.

For local integration testing, the unchanged earlier supplied Codex catch-up core
was used: declared commit `4fbebc8461b80538a85cf14b181f282ff60583f9`, tree
`af1963fe7b16fa0be030ccee47c731795cbfad71`, 106 required files checked. This is
an explicit dependency distinct from Codex's later 110-file full-source result.
The add-on still cannot run standalone from PR #7/#8. No missing or previously
blocked core implementation is included, renamed, encoded, or uploaded here.

## New interface

Existing calls remain valid. Recording is opt-in:

```python
from refresh_trace import recorded_refresh

report = recorded_refresh(
    wallet,                         # existing CertifiedWallet; already configured
    "http://127.0.0.1:26657/",      # explicit local development node only
    "/private/workspace/run-001",  # must not already exist
    max_batches=2,
    headers_per_batch=64,
)
# The sanitized report is already flushed before this assertion can fail.
assert report["state_synced"]
```

The refresh CLI accepts `--report-dir NEW_DIRECTORY`. All its existing genesis,
policy, journal and endpoint options remain required. With no report directory,
it uses the existing unrecorded path. Exit zero still requires state_synced=true;
partial progress and unavailable or rejected evidence are not successful sync.

The separate inspector needs only the add-on and Python standard library:

```sh
python scripts/inspect_refresh.py /private/workspace/run-001
```

Inspector exit zero means a complete diagnostic result was readable. It does NOT
mean that result was a successful refresh: inspect outcome.status and
outcome.state_synced. Exit 2 means incomplete/aborted recording, and 3 means an
invalid or unavailable record. No wallet, key, native source, or RPC connection
is opened by inspection.

For direct library instrumentation, refresh_wallet also accepts a trusted
`observer(event, data)` callback. This is application code, not endpoint-supplied
code. Do not treat arbitrary callbacks as sandboxed or give them untrusted code.

## Recorded information and non-authority

The new directory is private (0700); events.jsonl is private (0600), exclusively
created, and never overwritten or reused. Each accepted event is written and
fsynced before continuing. A run permits at most 64 events of 4,096 bytes each;
reading is capped at 256 KiB. The code checks normal POSIX file ownership and
rejects symlinks and hard-linked trace files. Its assumption is a trusted local
filesystem, not resistance to a malicious same-user host.

The allowlist records phase names, counts, selected heights, a random run ID and
local start time. Completed records preserve status, state_synced, header/batch
counts, RPC count (including null when genuinely unknown), bounds and target/
verified/state heights. It deliberately omits balances, account IDs, signer keys,
signatures, policy/genesis identifiers, raw response bodies, paths, the endpoint
and exception text. No financial data is necessary to diagnose where this client
stopped. Raw public/financial proofs may be retained by a separate explicitly
reviewed test runner, but are not silently collected by this recorder.

The JSONL records use canonical encoding, sequence numbers and hash links to catch
accidental truncation, editing or reordering. They are NOT digitally signed,
independently authenticated, an audit certificate, chain evidence, or a hostile-
operator tamper guarantee. They never determine a balance or authorize a payment.

## Interruptions and write failures

A completed result is flushed BEFORE recorded_refresh returns. A subsequent
runner assertion or failed stdout write therefore need not lose that result.
If the process exits before completion, the last complete event remains visible;
a partial tail is identified and not interpreted as a terminal result.

There is intentionally no atomic transaction spanning the wallet database and
this diagnostic file. A crash may happen after a wallet commit but before its
following diagnostic event. A missing result therefore means UNKNOWN, not
rollback, nonexecution, nonpayment or a released reservation. A completed record
also does not prove that the caller received it or that hardware survived power
loss; process-interruption tests are not power-loss durability certification.

An observer/write failure stops this invocation. Previous header or full-state
wallet commits can survive. No automatic retry, undo, re-signing or wallet reset
occurs. Inspect/resume using the existing authenticated wallet path. A subsequent
recorded invocation requires a fresh diagnostic directory and never edits the
older evidence. Expiry and header-continuity enforcement are unchanged.

## Executed tests

The final optional add-on suite contains 50 distinct tests: the 10 exact Codex
add-on cases plus 40 new diagnostic/storage/integration/CLI cases. It exercises
actual loopback HTTP, fixed-H+1 retries, expired policy before reads, changed
signed evidence, partial progress, successful state reconciliation, no key access,
private record fields, invalid/truncated traces, exclusive output, failed writes,
actual subprocess termination after a header commit and after final recording,
reopen and no resend. The fixture headers are synthetic committee signatures over
real local native state, not a new CometBFT execution.

The original pre-change 10-case suite passed independently first. An initial
combined new test command hit its tool deadline; its partial log is retained and
not counted as a successful run. It also exposed duplicate discovery of an imported
fixture test class. The import was changed to a module reference so every selected
test runs once. Later completed runs and exact IDs define the reported result.
The native core manifest is checked both before and after testing.

No new full-native 1,062-case run or validator execution is claimed. No Actions,
paid compute, public deployment, real funds, production keys, DNS/site or
Resident/Luna work, force pushes, or merges are part of this checkpoint. The
next real-network exercise can wrap each refresh call with recorded_refresh and
retain its record before asserting, without weakening any acceptance condition.
