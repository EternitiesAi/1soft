# Qualifying the current 1soft development source

Use a clean checkout and new evidence directories. The supported current local
profile is `tools/release/check_current.py`; older manifests and fixed-checkpoint
commands describe their original snapshots. Do not rewrite those byte seals to
make a newer checkout inherit historical tests.

## Local source and component checks

With pinned Python dependencies, Git and Node already installed on Linux/WSL:

```sh
python tools/local-platform/scripts/1soft.py check --output "$HOME/1soft-current-check"
```

The entry point executes `tools/release/check_current.py` with the same Python
interpreter and returns its actual exit status. You can invoke that checker
directly with the same `--output` argument. Output must be a new directory outside
the checkout, with an existing parent. `doctor --engine PATH` separately checks
installed prerequisites without executing the engine or qualifying the source.
See the [first-run guide](LOCAL_DEMO_GUIDE.md).

The command binds every tracked byte and mode to the current commit/tree before
and after execution. Native tests and all 18 component directories run in separate
interpreters, preserving component-specific imports. Empty, missing, duplicated or
uncovered Python groups refuse qualification. The optional unpublished account
catch-up test is explicitly excluded; it is not counted as passing.

The isolated privacy-proof benchmark is a separate source qualification surface.
It requires pre-cached Go modules and Cargo crates, local Go >=1.25.7 and stable
Rust >=1.88, then independently verifies two experimental profiles for one
synthetic one-input/two-output relation: gnark v0.16.3/gnark-crypto v0.21.0
Groth16/BN254/Poseidon2 with ephemeral setup, and Halo2/Pasta IPA with
deterministic public parameters. Both require the listed rejection cases. Unless
a successful exact receipt is
present, its status is source under qualification; local tests alone do not make
the benchmark a pass.

Key-free JavaScript unit suites run separately from browser scenarios. Browser
rendering, authenticated service workflows and actual merchant consensus require
their own process/toolchain and scenario receipts. A successful local profile still
reports a blocked release and no real consensus or public-funds readiness.

Keep `started.json`, `progress.json`, `result.json`, source inventories, child
reports and raw logs together. A started run without a complete final result is
incomplete. Failed or skipped cases, stale child reports, timeouts and truncated
logs do not qualify. A source digest identifies bytes, not protocol security.

## Actual validators and browser callers

Use the exact already verified CometBFT binary and record its SHA-256 and version.
Do not substitute scripted signatures or direct application calls for validator
consensus. The repository has separate P4 runners for:

- Native payments before and after full validator turnover.
- Decision-bound delivery, unresolved claims, receipts and wallet reconciliation.
- Explorer receipt consumption across the same turnover.
- Fresh-node bootstrap and recovery after a lost durable Commit reply.
- Fresh format-2 state sync and checkpoint reoffering after final Apply reply loss.
- Explicit owner key replacement with original account identity and payment history.

The relevant commands and acceptance assertions live in
[P4 delivery](P4_DELIVERY_ENGINE.md), [P4 recovery](P4_RECOVERY_INTEGRATION.md)
[format-2 state sync](PROTOCOL4_STATE_SYNC_QUALIFICATION.md)
and [key replacement](P4_KEY_ROTATION.md). Outputs for cryptographic recovery must
be private, owned POSIX directories; do not relax that boundary to write directly
to a Windows-mounted path. Export only sanitized public receipts/logs afterward,
leaving private validator homes, keys and financial journals behind.

The existing browser tests distinguish controlled API rendering, an actual guarded
local fixture service, and an actual four-validator merchant journey. Record the
browser, driver and Node versions as well as the tested source. Controlled rendering
is useful UI evidence but does not establish native settlement. Follow
[browser payment recovery](BROWSER_PAYMENT_RECOVERY.md) and
[merchant browser qualification](MERCHANT_INVOICE_BROWSER.md).

Protocol 1/2/3 flat and SMT matrices, their state-sync formats and the official
Go/wire oracle are separate compatibility gates. A P4 pass does not qualify all
legacy matrices. Run affected gates for a source change and retain earlier results
with their actual source identities rather than adding historical counts together.

## Review, integration and publication

The separately versioned [segmented recipient ledger](SEGMENTED_RECIPIENT_DESIGN.md)
has a one-host actual-engine development gate beyond P8's original caps:
10 native payments, 21 notes, a payment after height 64, same-store validator restart,
global older-segment spend refusal, and a signed height 83 checkpoint. The native
relation/profile/wire remain P8; consensus genesis, bootstrap, storage and AppHash
identities are new. Existing wallets and stores do not migrate. Its direct 50-
attempt probe, 21 fake-verifier storage tests, and separate 11-proof/header check
have distinct scopes. Retained disk growth, linear restart replay, sixteen-note
segment input sets, pruning/state sync, compact authenticated wallet witnesses,
production custody, independent operators and external review remain gates.

The separate [P9 authenticated wallet](PROTOCOL9_AUTHENTICATED_WALLET.md) passed
19 actual native journey checks on four disposable validators: two payments,
received-fund spending, discarded-reply exact recovery, one-attempt refusal,
authenticated change and fresh Python-process encrypted reopening. It authenticates
complete bounded native history under a static-quorum signed next header. This
is not a compact witness, freshness proof, browser migration or independent-host
trial. That earlier five-note receipt keeps its original scope.

A separate [native P9 wallet rollover gate](PROTOCOL9_WALLET_ROLLOVER.md) now
qualified three wallet payments plus seven setup-generator payments,21notes,
actual segment0/segment1 wallet spending after height64, valid competing older
input refusal, discarded-response recovery and fresh-process encrypted reopening.
All25 native checks passed; a separate public process replayed five signed full
histories and ten exact receipts. Public proofs hide inputs/amounts; their private
binding and conservation are checked by the native wallet runner. Maximum-capacity,
long-duration, independent-host and production-custody behavior remain unassessed.

Independent review names its exact source and executed cases. Preserve negative
results and limitations, including unmeasured maximum-capacity resource behavior.
After combining reviewed changes, rerun the current local profile and affected
actual caller/engine scenarios on that combined revision.

A merge receipt should record the exact tested head, resulting main commit/tree,
PR and preserved source/evidence archive. Matching main and tested trees confirms
integration, not independent-host safety or a production release. Do not run
Actions, deploy infrastructure or use value-bearing keys/funds to complete these
development checks.

Long-term history policy, independent operators and network faults, external
security review, hardware/cross-device custody and economic/genesis decisions stay
visible as distinct release gates. See the [roadmap](ROADMAP.md).
