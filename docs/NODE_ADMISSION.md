# Bounded transaction admission and private node I/O — 1soft v0.16

This is native-coin node engineering. No new monetary rule, signature domain,
genesis format, account identifier, proof format, token, issuer or Resident
feature is introduced. All changes are local admission, proposal-selection and
private transport behavior. The actual consensus engine has not run here.

## Exact transaction + committed checkpoint

`CheckTx` now has an optional process-local LRU of completed admission answers.
Its key is the full immutable transaction bytes, including the signature, under
an explicit tuple of native genesis hash, committed height and application hash.
It is not keyed only by a payment body, account, or a claimed transaction ID.
Changing the signature cannot inherit another envelope's positive answer.

Only actual native results (`code` 0 or 1, log and transaction ID) can be retained.
The result is stored immutably and returned as a new dictionary. Caller mutation
cannot change a later response. Internal execution-image faults are not cached
as ordinary rejected transactions. Each lookup first checks the existing
execution image's committed checkpoint and read-only integrity conditions, so a
cached success cannot hide a missing, closed or inconsistent execution image.

A successful durable commit clears the old entries. Binding also clears on any
checkpoint change, including an empty block that only changes height. A failed
commit leaves the previous committed state's answers in force. Finalized but
uncommitted candidates never replace them. Thus old nonce failures can become
valid after a commit, and formerly valid spends can become expired, executed,
revoked or over budget. Neither approval nor rejection survives a different
committed checkpoint. Restart discards all memoized answers.

On a miss, incoming signatures, balances, nonce, expiry, fees, recipients, grants
and shared native budgets are still evaluated by the existing ledger. Exact
repeats at the same checkpoint reuse that previously computed result. The new
syntax precheck rejects malformed/noncanonical JSON before cloning database
pages; it is the same canonical-transaction prerequisite used by `_apply`, not a
replacement authorizer. This reduces repeated work; it is not free admission of
unverified transactions.

`PrepareProposal`, `ProcessProposal`, `FinalizeBlock` and `Commit` never use cached
CheckTx answers for monetary execution. Individual transactions can each be
admissible against the same starting state while their combined spending exceeds
a budget. Blocks still execute in order against an isolated trial. Tests exercise
that exact case. A successful CheckTx is not a receipt or a balance reservation.

## Retained-data limits

Defaults are 512 entries, 4 MiB of charged retained payload and at most 24 KiB per
entry. An entry too large for its limits is not cached. Least-recently-used entries
are evicted to satisfy both the count and byte ceilings. The byte accounting
includes raw signed bytes, UTF-8 log/data strings and one code byte; Python object
overhead is not included. The separate entry-count ceiling bounds the number of
objects, but these numbers are NOT a total process-RAM limit. Distinct adversarial
inputs can churn the cache, and distinct valid-looking transactions still require
native work. The feature is not a complete network denial-of-service defense.

`AdmissionLimits` is operator/process configuration, not peer-controlled state.
`admission_cache=False` explicitly disables reuse for comparisons. Statistics are
available only through the local application accessor; no public metrics endpoint
or authentication service was added. The older execution-image benchmark explicitly
disables the newer admission cache to preserve the meaning of its comparison.

## Bounded proposer selection, unchanged peer validation

A local proposer inspects at most 1,024 candidate entries and 4 MiB of candidate
payload in a pass, returning at most the existing 64 transactions and existing
block-data budget. This bounds scanning through unhelpful candidate lists.
These selection limits do NOT become consensus rejection rules: a peer's otherwise
valid block is processed with the unchanged native/block rules, even if this local
proposer would have stopped scanning before reaching its transaction. There is no
new mempool implementation, guaranteed inclusion, fee auction or fairness policy.

## Private ABCI connections

The existing Unix-socket endpoint now admits a connection BEFORE constructing its
handler thread. Default maximum is 16 concurrent connections (operator range 1–128).
The old placement of the slot check inside the handler was after thread creation.
Tests hold two admitted sockets and show that 24 further connections create no
additional handler threads; closing a holder releases a slot for a healthy client.
This endpoint remains private to the same OS user and is NOT a public RPC/P2P gate.

Started frames have one absolute receive deadline, default 5 seconds. A byte dripped
just before a timeout does not renew the deadline. Responses have a separate absolute
send deadline, also default 5 seconds. Input uses the unchanged bounded ABCI frame
codec. Idle channels with no frame started have no timer because an engine may
legitimately leave a persistent channel idle. Therefore a same-user actor can hold
all available idle slots; OS isolation remains an assumption, not solved here.

Malformed or incomplete client frames close only that client. A stalled reply
releases its handler without claiming delivery. An oversized full-state query
returns an explicit local-size error and recommends compact records rather than
quarantining the node. An internal application exception instead sets the failure
flag and stops new service. Shutdown interrupts blocked socket reads, then allows
a bounded join for native work already executing. It cannot safely kill arbitrary
Python computation: a worker still alive after the join marks the endpoint failed.
No CPU-time, process-memory, or all-client availability guarantee is introduced.

The receive timer starts at the first received byte. It does not include earlier
idle time or native execution. The reply timer starts when reply transmission
begins. These limits may cause a real engine connection to fail if set too tightly;
actual-engine compatibility and operator settings still need the real acceptance run.

## Local interface

```sh
python scripts/serve_abci.py --db PRIVATE_DIR/app.sqlite --socket PRIVATE_DIR/app.sock \
  --genesis native-genesis.json --max-connections 16 --frame-seconds 5 --reply-seconds 5
# Explicit reference comparison, not a peer-selected fallback:
python scripts/serve_abci.py --db PRIVATE_DIR/app.sqlite --socket PRIVATE_DIR/app.sock \
  --genesis native-genesis.json --no-admission-cache
```

Use a private 0700 directory and disposable genesis/keys. This starts only the
application endpoint, not CometBFT or an operational Layer 1. The scripts do not
provision a public server, financial service or chain. `Info` now advertises software
version `0.16.0-dev`; the genesis-pinned protocol execution version remains separate.

## Executed measurement

With 256 real signed local transfers in four committed application blocks, 512
identical valid checks required 512 execution forks with reuse disabled and one
with reuse enabled. The same fork counts held for 512 identical invalid signatures.
Answers and committed state matched. Median valid-check times in this run were
1.6797765 ms versus 0.028603 ms; invalid-signature times were 1.2699315 ms versus
0.027952 ms. These are sequential local measurements, not randomized load tests,
network TPS, fees, finality or a production performance guarantee. The work-count
reduction, not the timing ratio, is the main demonstrated result.

A separate 2,048-input malformed-data exercise performed zero ledger forks. With
local limits of 16 entries and 4,096 payload bytes it retained 16 entries, below
both limits; it did not silently enlarge storage to hold the flood. Response and
state checks are enforced by the reproduction script itself.

```sh
python scripts/verify_checkout.py
PYTHONPATH=src:tests python -m unittest test_admission_cache test_node_limits -v
python scripts/measure_admission_work.py --output NEW_DIRECTORY
python scripts/check_admission_guards.py --output NEW_GUARD_DIRECTORY
```

## Primary upstream basis and remaining gate

Python socketserver documents `process_request` as the hook where threading mixins
create threads; the local quota now operates before that step. Its `serve_forever`
timeout does not limit a handler's socket read, hence explicit frame I/O deadlines.
CometBFT distinguishes CheckTx from execution and permits proposer transaction
selection; none of this replaces validator consensus.

- https://docs.python.org/3.13/library/socketserver.html
- https://docs.cosmos.network/cometbft/v0.38/api-reference/rpc/tx/check_tx
- https://docs.cosmos.network/cometbft/v0.38/spec/consensus/Creating-Proposal

Only primary public documentation was used for these API semantics. Exact runtime
results and source hashes are in `evidence/v016`. The normal local engine build
still fails at dependency-host DNS and the actual-engine gate remains unassessed.
The new server/tests are not a reimplementation of CometBFT, network simulations
are not substituted for it, and no independent security audit is claimed.
