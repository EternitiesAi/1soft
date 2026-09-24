# 1soft v0.8 — observed verification

September 24, 2026. Local execution only; no GitHub Actions, paid compute,
production keys, customer funds or public deployment.

| Check | Observed result | Actual scope |
|---|---|---|
| Inherited v0.7 inventory | 261 entries matched | Original archive before edits. |
| Inherited Python baseline | 395 passed | Rerun before adding the new code. |
| Final discovered Python cases | 449 passed across five bounded processes | All distinct case IDs covered once; zero skipped. |
| New cases included above | 46 state/outbox + 8 command-line cases | Not additional to 449. |
| Separate JavaScript reference | 30 passed | Still separate from native accounting. |
| Full required-source inventory | 53 files | Not an assertion that the remote node import is complete. |
| Actual consensus engine | Not built or run | Module-host DNS lookup failed before compilation. |
| Real validator transfer / public network | Unassessed / absent | No synthetic replacement. |

The new tests exercise signature and state tampering, genesis pinning, same-height
conflicts, rollback after restart, missing/forged predecessor links, local age
bounds, signer/nonces, agent limits including fees, shared native balance holds,
competing approval connections, exact receipt reconciliation, signed-height
expiry, and recovery after abrupt process exit before export. Real terminal
sessions cover encrypted signing and verify that the fixture password is not
echoed. Failed output creation retains the original signature in the outbox.

All validator certificates supplied to these exercises are SYNTHETIC. Ed25519
operations and native ledger execution are real, but no consensus engine produced
these headers. This is not a network finality claim or an independent audit.

## Failures retained rather than hidden

The first implementation supplied 12 placeholders to an 11-column outbox insert;
14 focused tests errored. The SQL was corrected and those tests passed. Both logs
remain under `evidence/v08/`.

Three combined full-suite invocations were interrupted by tool execution limits,
without a final suite result. They are not counted as passes. The initial progress
update described a terminal-test hang; that diagnosis was not established. The
final evidence instead partitions all 449 discovered case IDs into 100, 100, 100,
100 and 49, each in its own local process. All passed. A single-process full-gate
success is not claimed for v0.8. Coverage and exact IDs are recorded in
`partition-coverage.json` and `partition-*.json`.

The explicit local engine build returned a Go module-host DNS/connection refusal
before compilation. The release metadata inspected through GitHub lists no binary
assets for the pinned v0.38.25 release. An attempted supported download path did
not produce the module file. No workflow was enabled, runner registered, paid
resource provisioned, or blocked ABCI upload retried/rerouted.

## Evidence and publication

New source: `src/wallet_state.py`, `scripts/state_wallet.py`,
`tests/wallet_state_fixture.py`, `tests/test_wallet_state.py`, and
`tests/test_state_wallet_cli.py`. The existing `src/commit_verifier.py` is unchanged
and is now included with this standalone wallet subset on GitHub; it is not the
previously blocked ABCI transport. The new fixture imports no ABCI transport or
consensus application. The complete node import remains partial.

Final remote and local source commits, publication byte comparisons, and package
checks are recorded in RELEASE.json and companion release evidence. Old reports
are preserved in `docs/archive/v0.7/`. Old standalone process/fault-injection
exercises were not rerun as standalone scripts in this checkpoint; inherited unit
cases remain in the 449-case coverage.

Fresh package checks must be reported separately from development runs, not counted
as extra distinct tests. Checksums are integrity checks, not signatures or audits.
See STATE_WALLET.md for static-validator, local-clock, backup rollback, same-device
reservation and full-state-size limitations. No launch readiness is asserted.
