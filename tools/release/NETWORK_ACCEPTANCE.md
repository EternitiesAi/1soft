# Retention-enabled product-network acceptance

28 September 2026. Direct source baseline: PR #18,
`3a6723582af8d2fe25bc306cd1ac576449f68423`, tree
`20075322cc09505b2581f39684c0a3b6064d04ac`.

This is an opt-in execution gate for the existing 1soft product components, not
another node, wallet, archive, consensus implementation or deployment. It keeps
the prior standalone network runners unchanged. The native monetary, signing,
reservation, state-sync and local-history code is unchanged. The small explorer
retry adjustment below is the only product-runtime change.

## What the new gate requires

`run_product_network.py` starts four disposable CometBFT v0.38.25 validators on
loopback only. Every application starts with an explicit small block-history
window. The engine file must match the caller's explicit SHA-256 AND the pinned
version. No download or synthetic replacement occurs. An absent engine or absent
engine digest returns unassessed with zero executed checks. A wrong digest/version
refuses execution. The source must be an exact clean Git checkout with matching
root and component manifests.

The gate creates its own no-value DEV genesis and test keys through the existing
fixture builder. It executes four setup transactions, signs two native agent
payments through one CertifiedWallet journal, and tests the shared 100-unit budget:
Raven 58+2; Atlas 39+2 refused before unlock, 38+2 accepted. Temporary signer files
are removed before delivery. This is not memory-zeroization certification.

The existing DecisionDelivery proxy drops the first downstream HTTP reply only
after observing successful upstream CheckTx admission. Admission is NOT execution.
The second response is forwarded normally. Reopened journals must return the
original signed bytes, and read-only receipt collection must verify execution
without another send. Original standalone quorum and five-node state-sync gates
remain mandatory, separate regressions; this scenario does not replace them.

The ProductObserver then invokes the actual explorer collector, indexer, receipt
capsule builder and archive before wallet reconciliation. These operations must
leave the complete logical wallet/dispatch journals unchanged. The first explorer
anchor is the exact signed checkpoint already accepted by the wallet, not merely
another signed header at the same height. Receipt pins are separately retrieved
and checked under the locally pinned test genesis; this is not evidence of an
independent RPC operator or independent validator administration.

The required (wallet pending / explorer recorded budget spend) sequence is:
100/0 -> 100/60 -> 40/60 -> 40/100 -> 0/100. Explorer and archive reopen between
payments. Every archived record must match its exact indexed execution receipt
and verified block inclusion. Duplicate archive imports must be idempotent.

All four source applications must then cross the local pruning boundary. Their
old payment block-result query must explicitly report pruned while the complete
native receipt remains identical. The observer checks the configured contiguous
window, pruned-through boundary, and explicit false flags for native receipt
pruning, engine pruning, absence proof and total storage boundedness.

One validator's engine AND application stop and restart. On restart the application
command intentionally omits the retention flag: the saved policy must survive.
The four nodes must converge again, with all six original native receipts and
100 units of recorded shared-budget spending. The resulting complete native state
and exact two payments are verified against a signed next-header commitment.

Finally all source processes stop. The index and archive reopen and reverify their
records without RPC. Revisiting the older receipt must return already_recorded
without reimporting older state or touching the network. The proxy must show only
two payment submissions, one of each original signed byte sequence.

## Execute locally when the pinned engine is available

With the existing pinned dependencies already installed, from a clean checkout:

```sh
python tools/release/check_release.py --output /private/new-local-profile

python tools/release/run_product_network.py \
  --cometbft /private/bin/cometbft --engine-sha256 YOUR_VERIFIED_BINARY_SHA256 \
  --keep-blocks 3 --output /private/new-product-flat

python tools/release/run_product_network.py \
  --cometbft /private/bin/cometbft --engine-sha256 YOUR_VERIFIED_BINARY_SHA256 \
  --keep-blocks 3 --smt --output /private/new-product-smt
```

An evidence directory must be new and outside the source checkout. No existing
node home or wallet is accepted. The gate's finite retention window is 2..16;
this is an acceptance constraint, not a change to the production node's allowable
range. The same binary digest is rechecked afterward. Source identity is rechecked
before reporting a pass. Existing log-capture code retains bounded sanitized
engine/application output, including separate logs for the restarted processes.
Truncated or failed log capture cannot produce a passing result.

Each observed product result is saved before its assertion. A failed explorer
read can occur after a receipt archive commit; neither that failure nor a missing
final report proves rollback or nonpayment. Inspect the progress and component
reports. A new attempt requires a new evidence directory. No failed run is
silently reclassified as successful by a later retry.

A successful result still says release_status=blocked, public_network=false,
real_funds=false. The engine acceptance report may say consensus_executed=true
only after real processes have produced blocks. The local fixture tests do not
set that field or fabricate a network result.

## Explorer retry correction

The previous collector tried the captured H+1 commitment four times with 100 ms
between reads. In a deterministic publication-delay regression, all four attempts
were exhausted before a commitment becoming available 500 ms after the state read.
That matches the duration of the development runner's configured block interval,
but the regression is a model of that delay, not an observed live-network failure.
The initial failing log is retained.

Spacing is now 250 ms: still four total commitment reads, still one captured state,
no newer target, and at most 750 ms of explicit retry delay. The existing total
request and worker-process bounds remain unchanged. Permanent unavailability,
invalid evidence and stale captures still refuse. The delayed-publication test and
the existing permanent-unavailable/fixed-height tests pass. This is not a guarantee
that a network will publish the next commitment within 750 ms.

## Verification scope and exclusions

The new tests drive the same ProductObserver through existing native/HTTP fixtures,
including both flat and SMT modes, actual TCP reply loss, archive/index reopen,
exact wallet-journal preservation, bad pins, missing evidence, diagnostic failure
and original receipt export after the fixture source closes. The fixtures use
synthetic committee signatures; they do not launch validators. Driver tests verify
binary refusal, startup/restart argument policy, clean-checkout unassessed output,
fixed-height capture and bounded ancestry. These tests qualify those components,
not the unexecuted whole real-engine branch.

The supplied source retains all prior release tests. The final full-suite totals,
exact candidate commit/tree, per-case logs and archive checks live in the separate
returned verification report rather than being inherited from PR #18.

Still separate: actual execution of this new gate, the exact-source standalone
Go wire and validator regressions, fresh-node state sync, final-Apply process
kill/restart, independently administered hosts, external security review, production
custody, economic/genesis choices and value-bearing deployment. This gate does not
start the fifth state-sync node or exercise its final-Apply crash window.

No Actions, paid compute, public service, real funds, production keys, DNS/site,
Resident/Luna/Psyche work, force-push or merge is performed or authorized here.
