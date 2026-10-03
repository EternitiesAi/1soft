# Durable payer-side invoices

The local durable alpha can pay committed invoices through the existing encrypted
invoice store and guarded browser. Native signatures bind the exact invoice terms,
resource digest and amount. The wallet keeps one shared financial journal for the
owner, Raven and Atlas; collection, reconciliation and delivery retain their
separate meanings. This is a private development feature, with public transactions.

## Fresh setup

Use the installed Linux/WSL dependencies and pinned CometBFT 0.38.25 engine. A new
invoice-capable alpha is selected explicitly, before any keys or journals exist:

```sh
python tools/local-platform/scripts/1soft.py init \
  --profile durable-private-alpha-v1 --invoice-commitments \
  --workspace "$HOME/1soft-invoices" --engine /path/to/cometbft
python tools/local-platform/scripts/1soft.py start \
  --workspace "$HOME/1soft-invoices" --engine /path/to/cometbft
```

The initializer records a distinct workspace/READY format and combines the existing
native `invoice_commitment_version=1` capability with `durable-private-alpha-v1`.
The default remains unchanged. The flag is accepted only for `new`/`init` with the
explicit durable profile. Existing workspaces cannot be upgraded, relabelled,
cleared or implicitly renewed. The native monetary/signature rules are unchanged.

The network command owns the four local validators and its generic wallet view.
In a second private terminal, initialize a separate encrypted invoice store with
its own password and the **original workspace genesis SHA256**, then import
independently checked committed v2 quotes with `1soft_private.py`. See
[PRIVATE_PAYMENTS_FOUNDATION.md](PRIVATE_PAYMENTS_FOUNDATION.md) for exact quote, expectation and private
content inputs. These operations connect to the ready workspace; they do not
start or stop the network. A legacy uncommitted quote is refused by the alpha desk
before creating invoice ciphertext or an unsigned request.

Serve the retained invoice-only browser in the second terminal:

```sh
python tools/private-payments/scripts/serve_private_wallet.py \
  --workspace "$HOME/1soft-invoices" --engine /path/to/cometbft \
  --invoices "$HOME/1soft-invoice-data"
```

Open that command's exact loopback URL. This listener owns its HTTP socket and
read connection only; closing it leaves the separately owned validators running.
It can reopen the original initialized workspace for historical inspection,
without recreating journals or renewing its original policy.

## Consent, expiry and originals

Importing a quote only retains encrypted invoice data and an unsigned request.
Review both the native financial transaction and the retained merchant terms.
Both explicit approvals must match before key access. The native signature commits
the original resource digest, recipient, units and lossless nanosecond terms.
Submitting is a further explicit approval of the original signed bytes.

The alpha applies quote-lifetime checks at new signature/claim COMMIT and again
immediately before dispatch, using the authenticated current checkpoint and fixed
original policy. A quote expiring during signature persistence rolls back that
signature. A quote expiring before claim COMMIT rolls back the new claim. Expiry
**after** a durable claim refuses dispatch while retaining that attempt and fee
hold. It never rearms the payment or invents an endpoint response. Network I/O is
not a transaction with SQLite, and a submitted valid native wire can execute after
merchant quote expiry; a quote clock is not an on-chain cancellation mechanism.

A lost application return requires inspecting the original decision/attempt and
collecting native evidence. Do not re-sign, recreate a journal or resend. Positive
receipt collection preserves the fee-inclusive wallet hold; explicit wallet
assimilation/reconciliation retires it from the exact authenticated execution.
Shared delegated budgets include fees and outstanding obligations from every role.

## Receipts, backups and supported boundaries

The private CLI now accepts alpha preparation heights through 4096 and exports the
explicit alpha capsule within its original 64 MiB history plus framing limit.
Capsules contain public original wire and authenticated historical execution;
they do not grant current spending authority or resource fulfillment. Alpha
`payment-header` is explicitly refused: legacy merchant books, merchant HTTP
fulfillment and portable merchant-proof/v1 cannot consume alpha receipts.

The browser's A1 download retains complete original authenticated **financial**
history, including hidden roles, attempts, responses, receipts and unresolved
holds. Recovery is inert. It excludes the invoice book, encrypted invoice content,
its dedicated data vault, unsigned request book and private signing vaults. Preserve
those original private files separately. A1 alone is not complete invoice/account
recovery, active restore or device fencing.

The original alpha limits remain: 4096 retained blocks, at most 64 new blocks per
collection batch, freshness/admission windows and one fixed 24-hour horizon.
Continuously admitted history can support payments beyond the original one-hour
anchor. An expired gap, stale context or exhausted capacity still refuses work.
See [DURABLE_ALPHA.md](DURABLE_ALPHA.md) for exact bounds and trust assumptions.

## Actual qualification

With a clean Git checkout, existing private POSIX evidence parent, cached engine,
Chrome and Playwright driver, `tests/alpha_invoice_browser.test.cjs` launches its
owned `alpha_invoice_browser_fixture.py` through Windows WSL. The fixture uses
unscaled wall and monotonic clocks for more than one real hour, retains one original
genesis/policy/journal, naturally crosses block 512 at four-second blocks and
restarts the same homes. It then exercises three actual owner/Raven/Atlas browser
invoice payments, dual consent, two controlled lost returns, exact original wires,
one attempt each, fee-inclusive holds before reconciliation, offline alpha
receipt verification, two real A1 downloads and inert reconstruction. Sources,
engine, rows and owned process closure are recorded. Generated DEV keys, vaults,
encrypted backups and inert archives remain outside source and the sanitized
handoff. Browser rendering, functional evidence and independent review are distinct.

Set `ONE_BROWSER_SERVICE_ROOT` to the Linux checkout, `ONE_BROWSER_SERVICE_PYTHON`
to the existing Linux Python interpreter, `ONE_MERCHANT_BROWSER_ENGINE` to the
pinned Linux engine, `ONE_MERCHANT_BROWSER_OUTPUT` to a new child under an owned 0700
Linux evidence parent, `ONE_BROWSER_TEST_DRIVER` to the installed Windows
`playwright-core` module, `ONE_BROWSER_TEST_EXECUTABLE` to Chrome and
`ONE_BROWSER_TEST_ARTIFACTS` to a new Windows evidence directory. Run the driver
with `node --test`. Missing prerequisites remain unassessed; the gate does not
install, download, shorten the hour, reset policy or deploy publicly.

A passed one-host scenario does not establish independent operators, production
custody, mainnet readiness, shielded privacy, economic viability, public
merchant fulfillment or performance at every resource ceiling.
