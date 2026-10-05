# Read-only AI reviews and retained failure evidence

Two separate AI reviewers inspected the new application/recovery and verifier/
report boundaries. They performed read-only review; this is not an independent
specialist cryptographic or security audit.

The application review found that a well-formed replacement block/request hash
could survive reopening. A failing regression demonstrated the defect. Recovery
now retains exact FinalizeBlock request bytes and recomputes identity from those
bytes, the block body and durable fields before accepting recovered state. The
regression passes with actual proof-backed execution.

The worker review prompted explicit timeout reaping and startup known-answer
receipts. The final evidence pins the worker, profile, parameters, verifying key
and known-answer transaction and records valid-proof acceptance and corrupt-proof
rejection for all four applications. Exact source and raw-artifact checks reject
altered or incomplete evidence. Final read-only review found no material mismatch
blocking integration within this scope.

Two initial real-engine candidates failed during cold proof verification:
candidate 01 exceeded the client timeout; candidate 02 exposed CometBFT's default
10-second global HTTP write timeout even after extending the client deadline.
Inspection of the pinned upstream source justified a bounded local-node setting
of 50 seconds (global write timeout 51 seconds), a 60-second client deadline and
the existing 45-second worker wall limit. The client never automatically resends.
Candidate 03 passed all checks but used dirty exploratory source and is not a
qualification. The final run used a clean committed source tree. All failed and
candidate reports and sanitized raw logs are retained in the delivery ZIP.

The source-qualified report authenticates state height 19 through a signed
height-20 header with 30/40 static-genesis voting power. It records two committed
payments, exact allowance exhaustion and four-validator convergence after
same-store restart. Its 18 checks and six adversarial report tests passed.

The manifest-checked default suite ran 1445 tests with no failures and 29 explicit
skips: 27 optional P6 real-input tests and two older P5 binary-dependent tests.
Separate supplied-input gates ran all 21 P6 proof/application/worker/certificate/
recovery tests, six report tests and the missing-input preflight test without
skips. The 64 checkout/older-P5 regression tests also passed. Default-suite skips
do not qualify a protocol; the real-engine receipt is the separate P6 gate.

Unsigned report/log hashes do not establish signed publisher provenance. Static
quorum signatures do not establish freshness or independent operators. One host,
synthetic funds, finite state and static grants remain explicit restrictions;
owner lifecycle, wallet integration, merchant redemption, public deployment,
hostile-host isolation and real-funds safety remain unassessed.
