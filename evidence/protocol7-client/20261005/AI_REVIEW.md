# P7 client AI review and validation scope

Two read-only AI peers reviewed the typed journal, admission, transport, actual
caller harness and strict report checker. Review found that the initial transport
only parsed payments, so owner delivery failed before HTTP. A real local HTTP
red test reproduced it; typed exact-wire dispatch repaired it. Five real HTTP
cases passed for owner/payment wires, failures, lost replies, malformed input,
redirects and no second request. Both wire kinds now keep code0 as an untrusted
acknowledgement. The CLI import failure was repaired and its two cases passed.

The AS-OF journal uses witness stateH authenticated by COMMIT H+1; fresh execution
starts no earlier thanH+2. Exact first completion records keep their original
certificate while status names the journal's latest certified state. The local
eight-height companion checks future commands without synthesizing blocks or
changing frozen proposal/finalization rules. AI reviewers found no remaining
concrete blocker in these boundaries after fixes. This is AI peer review only.

The registered clean-source actual caller report passed25 checks: future owner
admission, early proposal/process refusal, exact-height rotation, durable claims
before two actual RPC submissions, deliberately discarded acknowledgements,
two typed full-state/quorum-certified completions, cold journal reopening and
exact wire export, refused redelivery, stale unclaimed payment first-claim refusal,
forged certificate refusal and ordinary same-store validator restart.

Supplied-input unit gates passed5 admission,10 real-proof/signature journal,
5 actual HTTP and2 executable CLI cases, plus3 adversarial report cases. The
default suite passed1542 tests with0 failures/errors and120 optional real-input
skips; actual P7 inputs were supplied separately. Current source hashes, raw
artifact roster, measured binaries/processes and certificates are strictly checked.

One trusted POSIX host, finite synthetic value and static quorum remain the
qualification boundary. No signer/prover wallet, production custody/privacy,
freshness, hostile-host rollback protection, cross-device coordination, automatic
retry/migration, independent operators, public deployment or real-funds support.
