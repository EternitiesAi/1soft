# Browser purchase retrieval in the durable alpha

The browser wallet can retrieve an enrolled original purchase and offer its
resource and public proof as files. It connects through the existing guarded
wallet HTTP server to a separately configured merchant on the same trusted host.
Payment signing, one submission, receipt collection, merchant enrollment,
resource retrieval and wallet reconciliation remain separate actions.

## Configure the local bridge

Use one existing ready `1soft/local-alpha-invoice-workspace/v1`, original DEV
genesis, `durable-private-alpha-v1` and the original policy v2. The merchant operator
retains committed quotes/resources, imports the exact invoices and separately
enrolls each original signed wire with its verified positive alpha receipt using
the [merchant CLI](DURABLE_MERCHANT.md). A browser request cannot enroll a payment.

Start the actual merchant listener with the original quote IDs and a new protected
session file. Its bounded lifetime is at most 300 seconds; see the merchant CLI
help. Keep the separately owned validator network running. Then launch the wallet:

```sh
python -B tools/private-payments/scripts/serve_private_wallet.py \
  --workspace EXISTING_ALPHA_INVOICE_WORKSPACE --engine PINNED_COMETBFT \
  --invoices EXISTING_INVOICE_STORE \
  --merchant-session EXISTING_OWNER_PRIVATE_MERCHANT_SESSION
```

The optional flag defaults to disabled. The bridge validates the original
workspace, genesis, policy, retained quote IDs and protected session. It freezes
the exact session bytes; replacing that file refuses further use. To adopt a fresh
merchant session, close and reopen the wallet listener with its new path. Both
listeners own only their HTTP service, and the original books/invoices stay retained.

The browser receives neither session token nor paths. It cannot supply a merchant
destination, original wire, packet, payer or verification time. The merchant route
is the retained literal `http://127.0.0.1:PORT` origin/path. There is no redirect,
proxy, DNS lookup, CORS opening or arbitrary remote offer fetch. The wallet keeps
its existing Host, Origin, CSRF and small-input guards and `connect-src 'self'`.

## Receive the original purchase

After a positive receipt is collected and retained, the operator independently
enrolls it. Reload the wallet, choose the original invoice, and select **Review
purchase retrieval**. The page checks that displayed facts match the exact review
text and its SHA256 confirmation. Selection or role changes clear that consent,
including late review/resource/proof replies.

Review the pinned merchant/resource, public digest, original native transaction,
packet digest, original grant and any retained fulfillment time. Explicitly consent
to sharing the original receipt and its **full public chain history**. Retrieval
sends that original packet over the actual local merchant HTTP route. It signs,
submits and reconciles nothing. The enrolled reference ID selects the original
packet; it is distinct from the packet's byte digest.

The bridge checks exact unique response headers, declared size/encoding, resource
digest and enrolled native transaction ID, then replays and compares the original
retained merchant proof. Connection, send, raw response reads and completion use
a finite absolute work deadline. The browser additionally checks bounded complete
bytes and all invoice/payment metadata before creating an inert attachment.
Resources are at most 64 KiB. Proof transport is bounded by the original alpha
proof limit and a 90 MiB browser channel; small browser JSON inputs stay at 64 KiB.
Refused response streams are cancelled. Returned content never executes in the page.

The success message means bytes were received and digest-verified and a download
was offered. It does not mean the user saved it. Review again to download the
merchant proof, which includes public history. Verify that proof independently with
`verify_merchant_proof.py --profile alpha`, original external genesis/policy,
expectation/assignment and the original saved fulfillment time as AS-OF time.
Downloading a proof in the browser checks its transport digest and metadata;
independent offline cryptographic verification is a separate step.

## Recover an interrupted return

A lost return may leave consumption committed at the merchant. The wallet inspects
retained state without automatically repeating retrieval. Saved consumption is
displayed separately from resource receipt in this browser. Explicitly review,
consent and retrieve again. Completed historical retrieval returns the same
resource, original payment and original completion time, including after quote
expiry; it cannot authorize a new consumption. The bridge never uses the live payer
header path for that retry. New unfulfilled retrieval remains subject to the original
quote interval and fixed alpha horizon.

Retrieval and proof export preserve all wallet/delivery financial rows, revisions,
original wires and holds. A hold may still be pending while the purchase is received.
Use the distinct reconciliation control to retire it against exact verified execution.

## Verification and boundaries

`test_alpha_browser_delivery.py` uses native replay with synthetic quorum/clock
and real loopback merchant HTTP for bindings, expiry, cold historical retry,
response corruption and wallet preservation. `merchant_resource.test.cjs` checks
exact browser bytes/digests, stream cancellation and review consistency.
`merchant_resource_browser.test.cjs` drives real Chromium with controlled key-free
HTTP replies for consent, lost returns, corrupt bytes, failed inspection and late replies.

`alpha_resource_browser.test.cjs` launches the exact clean source on four cached
CometBFT 0.38.25 validators. Chromium makes three original owner/Raven/Atlas payments,
retains receipts while holds are pending, and retrieves from actual merchant HTTP
after separate operator CLI enrollment. The fixture audits actual browser resource
and proof downloads under original trust pins, a deliberately lost application
return after completed retrieval, explicit retry and cold same-home listener reopening.
It compares financial rows and original completion facts and requires owned process
and thread closure. It does not repeat the historical hour/height or native-restart
gates. Use the explicit existing runtime/evidence variables documented in
[the browser guide](MERCHANT_INVOICE_BROWSER.md); invoke Node directly with this
test path. Test output directories must be fresh and outside the checkout.

The delivery's `CODEX_RESULT.md/json` records what actually executed. Source
descriptions and unit/static reviews are not actual-consensus receipts. This remains
same-host local DEV, public ledger history, trusted intact journals and host clock.
It establishes no public service, shielded privacy, production custody/economics,
merchant identity, authenticated delivery time or global exactly-once consumption.
