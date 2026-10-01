# Browser payment recovery

The local development wallet now follows one original payment through review,
signature, submission, collected receipt and wallet reconciliation. The next
action comes from inspected retained state. A saved submission attempt with no
exact execution evidence remains **outcome unknown**; it is never an invitation
to pay again.

## Behavior

- Pending actions lock buttons, role selection and editable payment fields.
  Prepared responses are bound to the captured request, role and view generation.
  A stale response cannot restore approval after that context changes. Signing
  and submission send the original opaque canonical review, not a reconstructed
  JavaScript numeric representation or the current role selection.
- A refused action or lost return causes one read-only local state inspection.
  The interface does not repeat the mutation. If inspection also fails, current
  totals become unavailable and signing/submission remain disabled until a
  successful explicit reload. The vault password and approval boxes are cleared.
- A collected delivery receipt does not release the fee-inclusive wallet hold.
  Explicit wallet reconciliation does. An explicit ledger-to-wallet sync can
  also reconcile exact execution without creating a delivery receipt; the
  display does not pretend that a receipt was collected or a capsule retained.
- Historical execution remains distinct from current authority and current
  holds. Original payment export remains available where the backend permits;
  viewing or reloading does not renew trust. An already executed request cannot
  prepare another submission even if no local attempt is recorded.
- The five-step progress display works at desktop and narrow mobile sizes.
  Receipt capsules include full public chain history; they are not private proofs.

This browser still handles generic **unsigned payment intent**. It does not
authenticate merchant invoices or expose the separate encrypted private payment
desk through HTTP. Native invoice commitments remain the separately qualified
parent feature. No native application, wallet/delivery journal, HTTP guard,
signer, custody path or transport endpoint is changed by this interface update.

## Bounded checks

The new browser checks require an already-installed `playwright-core`, Node and
Chromium. They never download dependencies. Set `ONE_BROWSER_TEST_DRIVER` to
that module directory and `ONE_BROWSER_TEST_EXECUTABLE` to the installed browser.
Run from the source checkout:

```sh
node tools/local-platform/tests/browser_workflow.test.cjs
```

Ten real Chromium event tests use a key-free controlled HTTP fixture. They check
pending edit locks, stale review refusal, exact original mutation payloads,
complete allowed POST sequences after lost returns, recovery from an unavailable
inspection, original hold display, separate receipt/reconciliation states,
historical uncertainty and desktop/mobile overflow. Headers-loss cases deliberately
lose a partial application response **after headers**. Browsers may transparently
retry a connection that closes before headers; these checks do not establish an
arbitrary network exactly-once guarantee. Server-side original-decision and
attempt journals retain their existing authority.

An additional Windows/WSL test drives the **actual guarded HTTP service and native
P4 application** through Chromium, with the existing deterministic development
fixtures. Set `ONE_BROWSER_SERVICE_ROOT` to the Linux source path,
`ONE_BROWSER_SERVICE_PYTHON` to the pinned installed Python, and optionally
`ONE_BROWSER_SERVICE_USER` to the WSL user (default `xnuonux`). It creates only
owned temporary fixture vaults/journals, closes its servers and removes that
temporary workspace; it never opens a user wallet. Run:

```sh
node tools/local-platform/tests/browser_service.test.cjs
```

That journey creates a 58-unit Raven request, signs/reserves 60 units, submits the
original payment once, collects a receipt with the 60-unit hold unchanged,
explicitly reconciles to zero and exports the original and capsule. The real API's
origin/session, canonical review, CSP and no-store contracts remain in force.
The committee and RPC are **synthetic fixtures**. This is application integration,
not CometBFT consensus, independent operators, production custody or real funds.

Existing local platform Python tests and eight pure browser helper tests provide
additional contract checks. Results record a clean committed source inventory,
before/after identity, raw logs, runtime versions and independent agent review.
The parent invoice engine evidence remains pinned to its own commit. Historical
byte seals and feature-specific full qualifiers intentionally refuse changed
descendants; none is weakened or relabelled to qualify this browser slice.

## Remaining work

Human usability/accessibility and real devices remain unassessed. A merchant
invoice browser adapter, production custody, independent-host readiness,
on-chain privacy, demand/economics and a value-bearing release require separate
implementation and evidence. The current view remains local development using
valueless DEV units. No public deployment or monetary readiness is implied.
