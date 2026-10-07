# Local authenticated wallet guide

The Linux/WSL terminal guide reduces manual identifier transfer across the
existing wallet journey. It authenticates inventory through one unchanged
protected wallet child, then displays note commitments and retained transaction
IDs. Select one explicitly to receive redacted continuation templates. It
performs no preparation, submission, reconciliation, export or private delivery.

Use an initialized protected wallet and its existing external credentials and
trusted full genesis SHA. These placeholders are not funded accounts or a public
network:

```sh
python -B scripts/protocol8_console.py --workspace /home/operator/wallet-config \
  --genesis-sha256 TRUSTED_FULL_SHA --credentials /home/operator/private/credentials.json guide

python -B scripts/protocol8_console.py --workspace /home/operator/wallet-config \
  --genesis-sha256 TRUSTED_FULL_SHA --credentials /home/operator/private/credentials.json \
  guide --commitment EXACT_AUTHENTICATED_NOTE_COMMITMENT

python -B scripts/protocol8_console.py --workspace /home/operator/wallet-config \
  --genesis-sha256 TRUSTED_FULL_SHA --credentials /home/operator/private/credentials.json \
  guide --txid EXACT_RETAINED_TXID
```

The console lists opaque identifiers from authenticated local custody. Notes may
already be held; their presence does not establish spendable funds or a balance.
A missing retained wire is labeled explicitly and cannot be selected as a txid.
Wallet attempts/completion flags are displayed as flags, not converted into an
execution phase, delivery capability or current-network validity.

The output contains argument arrays, not shell commands. Replace every placeholder
locally and invoke a separate existing command. Arrays keep one explicit selected
identifier and leave credential/workspace paths, recipient intent, request ID,
amount, expiry and outputs unspecified. Both wire-backed and genesis-note import
forms are shown separately; the operator must supply the correct actual source.
The guide never infers which source is valid or whether any suggested effect will
be accepted. It emits no submit template or permission to submit.

Prepare retains its exact input confirmation. Submit retains its independent
txid/wire confirmation, second protected review and durable one-attempt path.
Use actual protected status/reconciliation for journal and signed-state authority.
An uncertain result cannot be retried. Delivery requires certified exact execution
at its existing protected caller; a selected identifier cannot replace that check.
See [wallet journey](PROTOCOL8_WALLET_JOURNEY.md) and
[payment review/status](PROTOCOL8_PAYMENT_CONSOLE.md).

The existing optional global receipt is a separately requested new owner-only
metadata file. Existing files, unsafe ancestry and collisions refuse before
inventory starts. Read-only means no wallet, configuration, journal, attempt or
private output mutation; explicitly requested public metadata receipts remain
an ordinary output. No private paths or intent values enter guide templates.

## Host profiling

`scripts/profile_protocol8_inventory.py` runs only the unchanged protected
inventory operation under Python's function profiler. It records aggregate
function call counts, self/cumulative host durations and the normal public wallet
receipt. It stores no raw function statistics, argument values, private payloads,
keys, openings or private request contents.

Measured phases include configuration/input checks, native object construction,
the exact Worker constructor (valid/corrupt KAT and identity checks), binary
reopen/hash, native call orchestration, helper/prover/wallet constructors and
authenticated inventory. Functions are bound to their exact code location so
same-named constructors cannot be conflated. Native per-call audits separately
retain real PID/birth, binary pins, timeout and reaping facts.

Cumulative phases overlap and must not be summed as disjoint wall time.
Profiling overhead is unassessed. This is one trusted-host sample, not a speed
improvement or production responsiveness claim. Protected runtime files, pins,
locks, KAT/profile checks, native subprocess environment, timeouts and cleanup are
unchanged. No worker caching, lifetime extension, migration or repinning occurs.

## Acceptance and limits

Focused tests label fake inventory authority explicitly. The actual gate
`scripts/run_protocol8_guide.py` adds ten real guide calls at observed/received,
prepared, exact-observed, conflict-observed and recipient checkpoints within
the unchanged four-validator wallet journey. It checks repeat stability, missing
selection/wrong-genesis refusal, exact rendering against controlled fixture
inventory, all wallet/configuration/journal/private-output bytes unchanged, no
additional node request, exact child identity and reaping. It also measures one
real protected inventory operation without changing fixture state.

The closed checker `tools/release/check_protocol8_guide.py REPORT` binds
guide/profile calls to the captured runtime, literal sequence, canonical child
streams and inherited journey evidence. Actual fixture comparisons, coherent
receipt tamper refusals and separate native proof/certificate replay remain
distinct gates. Historical PR84 qualifies its captured source, not this change.

Finite synthetic funds on one trusted host only. Production privacy/custody,
latest freshness, independent operators/signers, marker-kill/power loss, hostile
host rollback, scale/economics/listings, specialist review and public launch remain
separate. No Actions, paid/public compute, public endpoints/deployment/DNS/site,
other-project work, real funds, production keys, forcepush or outside messages.
