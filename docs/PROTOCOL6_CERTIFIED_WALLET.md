# Certified Protocol 6 treasury obligations

This controller retains an exact prepared treasury proof and records completion
only from exact inclusion in validator-authenticated state. It independently
replays the complete bounded P6 history with the genesis-pinned real verifier.
P6 consensus, proof bytes, original qualification and P1-P5 remain unchanged.

## What the controller does

One canonical SQLite journal retains the original wire and reserves its input,
parent commitment, grant commitment and request locally. A delivery attempt is
committed before the one loopback RPC call. A response or a timeout is only a
delivery hint. The journal keeps its hold until a valid H+1 certificate commits
the exact original transaction, statement, positions, nullifiers and fees.

Unknown/absent, conflicting and stale-authority observations never release an
obligation. No expiry release, refreshed replacement, retry or re-signing exists.
A known conflict/stale authority or observed elapsed validity window also refuses
the first delivery without creating an attempt. An authenticated unknown before
the original window ends can still claim its single attempt. Certified exact
execution wins over later changed authority and remains exportable after reopen.

Older state, a conflicting same-height state or a higher non-prefix history is
refused. Another valid consensus round over the same state is idempotent. Every
reopen rechecks schema, genesis, private-file ownership, original wires/proofs,
resource keys, attempts, signatures, replay, continuation and exact completions.
FULL-sync WAL and BEGIN IMMEDIATE keep the observation and completion atomic.
The component has8 obligations,65 observations and1MiB observation limits.

## Use on an owned local development host

Prepare a0700 journal directory. Supply a trusted genesis file and its separately
recorded SHA256, the exact verifier binary/hash and public known-answer transaction.
Never derive the trust pin from the same RPC response being authenticated.

```sh
python scripts/treasury_wallet.py   --journal /absolute/private/journal.sqlite   --genesis /absolute/trusted-genesis.json --genesis-sha256 EXACT_BOOTSTRAP_SHA256   --worker /absolute/treasury-consensus-bridge --worker-sha256 EXACT_WORKER_SHA256   --kat /absolute/a.tx retain --transaction /absolute/prepared.tx
```

The same required pins apply to inspect, deliver-once, observe and export.
`deliver-once --txid ID --rpc-url http://127.0.0.1:PORT` accepts loopback only,
refuses credentials/paths/queries, disables proxy routing, refuses every redirect and never retries.
`observe --packet FILE` consumes a closed JSON object containing witness and
signed_header. `export --txid ID --output FRESH_FILE` returns original recovery
bytes; export is not authorization to send again. There is no proving/signing,
recipient-key lifecycle, private note scanning, merchant redemption or custody.

## Verify the actual caller

```sh
python scripts/run_protocol6_wallet.py --engine /absolute/cometbft   --worker /absolute/treasury-consensus-bridge --fixtures /absolute/public-fixtures   --output /absolute/fresh-wallet-report.json
python tools/release/check_protocol6_wallet.py /absolute/fresh-wallet-report.json   --worker /absolute/treasury-consensus-bridge
```

The runner creates a separately persisted and hash-pinned owned bootstrap before
launching peers. That is a synthetic one-host trust setup, not a human-approved
public genesis or independently operated trust anchor. It submits one real
transaction through the same operator loopback transport, deliberately
discards its acknowledgement and recovers via the actual signed state. A second
synthetic controller retains a conflicting proof and stays held. These actors
exercise conflict handling; they do not establish globally coordinated journals.

Qualification needs clean committed source, exact source/binary/fixture startup
identities, all19 checks, actual process exits, raw logs, signed inclusion and
exact exported record. Candidate/unfinished/altered reports cannot qualify. The
checker also uses the actual worker to replay the history. Unit signatures are
locally authored test signatures and are separate from real engine evidence.

## Deployment boundary

One trusted POSIX host and static validator quorum. Reports/logs are unsigned
execution artifacts, not signed publisher provenance. Full-history continuation
does not establish freshness. Cloned/deleted/rolled-back journals can lose local
attempt history; there is no hostile-host or cross-device custody protection.
Original raw export/API bypass can be misused outside deliver-once. Use one
canonical journal; do not claim reservations prevent independent external callers.

This controller adds exact certified execution recording to a finite development
protocol. Public deployment, independent operators, real funds, anonymous metadata,
production custody, specialist security/cryptographic review, owner lifecycle,
merchant discovery/redemption and scalable state remain separate release gates.

## Registered execution

The clean-source run at `c0b442868a14a9adfffd3be4215135656a39e9b4` passed all19 checks.
It committed the exact payment, discarded its acknowledgement, recorded the
H+1-authenticated state at height1, reopened the exact completion and refused
a second attempt. The competing obligation stayed held and refused its first
attempt after the conflict was known.

Receipt: [wallet-qualified-01.json](../evidence/protocol6-wallet/20261005/wallet-qualified-01.json).
Component: [COMPONENT_MANIFEST.json](../tools/protocol6-certified-wallet/COMPONENT_MANIFEST.json).
Actual20 journal cases,1 proof-backed CLI case,5 transport/operator cases and5
report-tamper cases passed. The manifest-checked default suite ran1476 tests
with55 optional real-input skips and no failures/errors; supplied P6 wallet
inputs were exercised separately. AI peer review is separate from independent
specialist cryptographic review.
