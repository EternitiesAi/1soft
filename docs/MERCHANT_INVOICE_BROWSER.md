# Committed merchant invoices in the local browser wallet

This development interface joins the existing encrypted invoice store and P4
payment desk to the guarded loopback wallet. It is limited to a configured,
already initialized **v3 invoice-capable development workspace**. DEV units have
no monetary value. The application, signature domain, genesis capability,
financial journal, receipt format and validator engine remain unchanged.

## Follow one invoice

An operator first creates and retains a committed merchant quote through the
[merchant commands](REPEATABLE_MERCHANT_PAYMENTS.md) and imports it into the
[encrypted invoice store](X402_NATIVE_DEVELOPMENT.md). The browser does not fetch
arbitrary offers or accept a URL, key path, policy or network configuration.
It shows the configured store's public metadata without decrypting invoice content.
Legacy uncommitted quotes are refused by this v2-quote browser boundary; their
existing CLI remains separate. A mixed/corrupt or incompletely correlated catalog
is refused, rather than silently becoming generic payment authority.

Choose an invoice and owner, Raven or Atlas. Review the exact recipient, amount,
fee and validity, then separately approve the retained merchant origin, resource,
public resource digest and native invoice commitment. Both approvals belong to
the same request, signing role and view generation. The original canonical native
review and merchant consent are returned as opaque text; nanosecond times in the
visible summary are decimal strings, so JavaScript cannot round them.

Signing unlocks only the existing fixed development payment vault and reserves
the fee-inclusive debit through the existing P4 wallet. Submission remains a
separate explicit approval of the original signed bytes. Lost returns inspect
retained state without repeating either mutation. Collection does not retire a
hold; exact verified wallet reconciliation does. Quote expiry blocks new signing
and submission, while original-wire inspection and applicable evidence recovery
remain available. See [browser payment recovery](BROWSER_PAYMENT_RECOVERY.md).

A wallet receipt does not establish merchant fulfillment. The merchant's existing
independent replay, enrollment and fulfillment rules still own resource delivery.
Encrypted local invoice content is application-data encryption; **the native
ledger and portable history capsules remain public**. There is no on-chain privacy,
production custody, real-funds service or independent-operator security claim.

## Open the view

Keep the separately owned local validator network running. On the same trusted
Linux/WSL host, using the existing pinned Python environment:

```sh
python -B tools/private-payments/scripts/serve_private_wallet.py \
  --workspace EXISTING_V3_WORKSPACE --engine PINNED_COMETBFT \
  --invoices EXISTING_INVOICE_STORE
```

Open the printed `http://127.0.0.1:PORT/` URL locally. Ctrl+C closes only this HTTP
listener; it does not launch, stop or renew the separately owned network.
Missing/altered readiness pins, policies, journals and invoice correlations are
refused. Startup validates the original canonical READY marker and its workspace
and policy hashes. An expired original trust policy can open a **historical**
view and recover original wires without vault unlock; it grants no current
balance or new spending/submission authority. Trust is never renewed.

Generic requests are not created or imported in merchant mode. Existing generic
requests remain in their original store but outside this invoice view. The UI
reports that count, and treasury/budget totals still include **all** obligations
in the shared journal. The ordinary generic wallet mode remains available through
its existing, separately configured entry point.

## Verification scope

New component cases exercise direct HTTP downgrade/consent tampering, exact time
binding, vault-access ordering, corrupt catalogs, foreign requests, expiry,
historical original-wire recovery and existing Host/Origin/CSRF/body guards.
Controlled Chromium cases exercise the two consent controls, selection invalidation,
late replies, lost returns, inspection failure and expired-quote controls. Those
key-free fixtures do not establish native execution.

`tools/private-payments/tests/browser_comet.test.cjs` drives Chromium through the
actual private-wallet launcher, guarded HTTP and three payments on four local
CometBFT 0.38.25 validators. Its owned fixture independently checks the owner,
Raven and Atlas signing lanes, exact replayed receipts, merchant fulfillment,
final balances, matching node AppHashes and process cleanup. It injects two lost
application returns after the actual server action completes. It also cold-starts
the same launcher under a test-only expired trusted clock, with vault unlock
refused, and checks historical export and unchanged policy. This test wrapper is
not a product clock override.

Provide the installed browser/runtime paths explicitly; the test installs nothing:

```text
ONE_BROWSER_TEST_DRIVER       existing playwright-core directory
ONE_BROWSER_TEST_EXECUTABLE   existing Chromium/Chrome executable
ONE_BROWSER_SERVICE_ROOT     this exact WSL checkout
ONE_BROWSER_SERVICE_PYTHON   existing pinned Python executable
ONE_MERCHANT_BROWSER_ENGINE   pinned CometBFT executable
ONE_MERCHANT_BROWSER_OUTPUT   new private POSIX evidence directory
ONE_BROWSER_TEST_ARTIFACTS    new Windows browser evidence directory
```

The Windows runner uses direct `node PATH_TO_BROWSER_COMET_TEST` because Node's
CLI test-glob path handling rejects UNC paths. Evidence, source identities and
all failures are retained outside the checkout. The final delivery's
`CODEX_RESULT.md/json` records what actually ran; this document is not a test receipt.
Historical byte seals and full-source qualifiers remain unchanged and intentionally
refuse later descendants. A focused browser/merchant gate does not establish that
all historical protocol, state-sync, official Go or fault gates were rerun.
