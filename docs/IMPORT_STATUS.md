# Repository import status — v0.6

24 September 2026. Owner-authorized target: `xnuonux/1soft` (private).
Original head: `29d330b1d135b6cbc6d472692c13f6fdf9756915`.
The original `1soft` file remains unchanged (Git blob
`75ed9b64ff34df89a9ce69214b40a55341cd712b`). No force push or unrelated repository
modification was performed.

## What is actually published

`src/native_core.py`, `tests/test_native.py`, `scripts/verify_checkout.py`,
`scripts/run_tests.py`, `tests/test_checkout_gate.py`, `SOURCE_MANIFEST.json`,
pinned application requirements, engineering/status documents and workflows.
The native code/test imports are unchanged v0.5 files; checkout verification and
33 associated tests are the new work. Full-package integration is not complete.

The full required-source inventory has 43 entries. Checks must fail when any
listed file is missing or altered. The complete local archive and remote partial
checkout are distinct artifacts and have distinct Git histories. Later import
must preserve the owner's history rather than force-replacing main with the
local historical branch.

## Publication interruption

The platform returned, twice for the same existing ABCI transport file:

> This tool call was blocked by OpenAI because we couldn't determine the safety status of the request.

Those calls did not create `src/abci_wire.py`. Further coordinated application
publication was stopped. Other application modules, full tests, research and the
interface remain in the complete local package, not this partial remote tree.
This is not a claim that every unpublished file was separately attempted or
blocked. No encoded archive or alternate upload route was used to bypass it.

## Hosted execution interruption

Actual Actions runs include:

- Engine preflight: `36020962853`, commit
  `bb609bf79b01df89008756a2d9b95a43b8b0e5f4`.
- Dependency-free echo diagnostic: `36021635525`, commit
  `a7891df8ba14ecffb3461e010d00897711a1f83a`.

Both report `completed` / `startup_failure`, with `path: BuildFailed`; their job
lists are empty. No engine build, echo step, dependency install, or native test
ran in those jobs. The cause is not exposed by the connector. No billing,
permissions, policy or workflow-syntax diagnosis is established.

Run URLs:
https://github.com/xnuonux/1soft/actions/runs/36020962853
https://github.com/xnuonux/1soft/actions/runs/36021635525

The local environment also cannot resolve the Go module download host. A new
repository solves the durable destination problem, not either execution blocker.

## Continuation boundaries

Do not convert startup failure into a pass, reduce source inventory, represent a
core-only checkout as the complete node, or substitute scripted votes for the
engine. The next verified result requires real upstream execution. No public
network, banking/card integration, reserves or external financial action exists.
