# Experimental native P4 payment envelopes

`tools/private-payments/src/payment_x402.py` is an additive, original Python
implementation of a bounded **x402 v2 HTTP envelope profile**. It uses the
`PAYMENT-REQUIRED`, `PAYMENT-SIGNATURE`, and `PAYMENT-RESPONSE` base64 JSON headers.
It connects exact unsigned payment intent to the existing `RequestBook` and
rechecks an existing portable P4 capsule. It introduces no signer, submission
path, wallet reservation journal, consensus rule, account enrollment, or SDK
spending authority.

The experimental scheme is `1soft-p4`, with `assetTransferMethod: p4-capsule` and
`paymentFlow: upfront`. Its only supported asset is the valueless development
native `DEV`, identified by the operator-pinned `1soft:DEV` string. The network
is `1soft:<operator-label>`, where the label is 1–32 lowercase ASCII letters,
digits or hyphens, beginning with a letter or digit. This is grammar-valid
CAIP-2 syntax with an **unregistered experimental namespace**, not a registered
ecosystem network. The local label does not establish chain identity: exact
independently pinned native genesis bytes and digest establish it.

Envelope field compatibility does **not** establish stock x402 SDK, middleware,
facilitator or server acceptance. No EVM/Solana scheme, USDC, stablecoin, fiat,
external settlement or cross-chain routing is implemented. Stock `exact`,
`upto`, other assets, other network families, alternate transfer methods and
unknown extensions fail closed. SDK installation and automatic payment retries
are absent.

## Authority inputs and APIs

Construct `NativePaymentExpectation(merchant_origin, resource_url, network,
asset, genesis_sha256, recipient, amount_units)` only from authenticated operator
configuration or an independently authenticated merchant invoice. Never derive
these pins from the `402` response being checked. Amounts are exact positive
decimal strings bounded by the existing native `MAX_UNITS` (2^53−1), not browser
numbers. Native recipients are exact `lab_` accounts. Resource URL equality and
merchant-origin equality are literal. Remote resources require HTTPS; HTTP is
accepted only for literal `127.0.0.1`. No function fetches the resource.

| API | Result and boundary |
| --- | --- |
| `make_payment_required(expectation, created_ns=…, expires_ns=…, quote_nonce=…, description='', mime_type='application/octet-stream')` | Canonical `PaymentRequired` header; no financial action. The caller supplies the quote nonce and exact timestamps. |
| `payment_header(raw_header_pairs, 'PAYMENT-REQUIRED')` | One bounded payment header. Case-insensitive duplicates are rejected. Pass the original pairs, before conversion to a dictionary. The other two standard header names are supported. |
| `parse_payment_required(header, expectation, now_ns=…)` | Checked offer, `quote_sha256`, exact canonical unsigned `request`, and `request_id`. `spending_authority` is false. |
| `retain_payment_request(book, header, expectation, now_ns=…)` | Rechecks the header and calls the existing canonical `RequestBook.add`. It never binds a review, signs, reserves funds or submits. |
| `make_payment_signature(required_header=…, expectation=…, exact_wire=…, capsule=…, payer=…, now_ns=…)` | A `PaymentPayload` header preserving the exact original public native wire, exact quoted terms, quote/request identities and exact capsule digest. It checks shape and correlation, **not positive execution**. |
| `verify_merchant_payment(signature_header=…, required_header=…, expectation=…, assignment=…, exact_wire=…, capsule=…, genesis_bytes=…, policy=…, payer=…, now_ns=…)` | Full existing `verify_capsule` execution replay with independent pins and exact merchant assignment matching. Returns a positive native receipt report, identities and response header. Merchant consumption is still required before resource delivery. |
| `parse_payment_response(header, expectation, payer=…, quote_sha256=…, wire_sha256=…, capsule_sha256=…)` | A checked server declaration. `execution_proven`, wallet mutation, merchant replay checking and resource delivery authority are all false. |

Headers use the existing strict integer JSON decoder and deterministic canonical
ASCII JSON spelling. Duplicate JSON keys, floats, booleans used as integers,
noncanonical base64 (including pad bits), whitespace/CRLF injection, unknown
fields, excess nesting and unsupported versions are refused. This canonical
spelling is a deliberately narrower local profile than general x402 JSON.
Optional resource description/MIME fields and optional empty offer extensions
are supported; other resource metadata/extensions are refused. Only one native
offer is accepted, so the client never chooses an alternate payment route.

Header bounds are 8,192 ASCII characters for required/response headers and
32,768 for signature headers, with at most 64 raw HTTP header pairs. Header JSON
depth is at most 16. Quotes last at most 86,400 seconds and must be currently
open under the caller's exact time. `maxTimeoutSeconds` equals the ceiling of
the quoted nanosecond lifetime. URL bounds are 2,048 characters; credentials,
fragments, ambiguous authorities, default-port aliases, dot path segments and
literal/encoded controls are rejected. Original native wire and full capsule
bounds remain the inherited 16,384-byte wire and 16 MiB evidence plus 32,768-byte
capsule overhead. Existing trust deadlines and native proof limits are unchanged.

## Resource assignment and merchant consumption

The native signed transfer contains payer, chain/genesis, recipient, amount,
grant lane, nonce, expiry and fee cap. **It contains no quote or resource digest.**
The unsigned x402 wrapper correlates the payment to the quote; it does not make
the native signature authenticate the resource or the quote. A genuine public
receipt cannot safely be treated as permission for arbitrary resources merely
because somebody constructed a wrapper around it.

`verify_merchant_payment` therefore requires
`TrustedMerchantAssignment(quote_sha256, request_id, recipient, payer,
wire_sha256)` from an independently trusted merchant store. The merchant must:

1. Durably retain the original quote and assign a **never-reused native recipient
   to exactly one quote/invoice**, before accepting payment. An identical amount
   or payer does not permit sharing that recipient across quotes.
2. Immutably bind the intended payer and independently retained original wire
   digest to that assignment. Do not copy this assignment, the original quote,
   expected wire or trust inputs from the incoming payment wrapper.
3. Call the verifier with the retained original quote/wire and independently
   supplied genesis, policy and time. The full replay must prove successful native
   execution, exact signed block inclusion and authorized validator evolution;
   admission, HTTP 200, a native signature alone or a success response is insufficient.
4. **Durably consume both the positive native transaction identity and original
   wire digest globally before delivering the resource.** Both need uniqueness
   checks across merchant invoices. Retain delivery/replay state across restart;
   uncertain delivery or an interrupted durable-consumption step requires
   diagnosis, not automatic retry or a second resource release.

The envelope module verifies the assignment's exact match, not the merchant store's
durability or recipient uniqueness. It is intentionally stateless and repeatable.
It always reports `merchant_consumption_required: true`,
`merchant_replay_checked: false`, `resource_delivery_authorized: false` and
`native_signature_authenticates_resource: false`. The returned payment response
describes a verified historical native transfer; a merchant may attach it to a
resource response only after its independent durable consumption gate succeeds.
The additive `MerchantBook` below implements this local merchant persistence gate.
This merchant bookkeeping is separate from the canonical wallet funds journal.
It cannot release reservations, cancel, refund, prove nonexecution, or authorize
resubmission. Caller approval, existing one-attempt delivery and explicit wallet
reconciliation remain separate actions.

A quote that has expired is rejected even if a historical native payment exists.
Rejected or unavailable evidence means the intended outcome is unknown; it is
not evidence that money was unpaid, absent, retryable or safe to release.

## Durable local merchant results

`tools/private-payments/src/merchant_book.py` implements a separate owner-only
SQLite book for one merchant's immutable quotes, explicit original-wire
enrollments and local fulfillment results. All invoices for that merchant must
share this book. Another database or a copied database cannot coordinate its
consumption claims. This is **at most one durable local fulfillment per enrolled
quote/payment**, not globally exactly-once delivery by an external service.

| API | Behavior |
| --- | --- |
| `MerchantBook(path, genesis_bytes, policy, clock=…, create=False, read_only=False)` | Explicit caller-supplied trusted clock and independent genesis/policy. Creates only a new private database, or opens an existing exact-schema book without repair. |
| `book.add_quote(required_header, expectation, resource=public_bytes)` | Retains the original canonical offer, authenticated expectation and exact nonempty public resource bytes. The recipient is forever unique to that quote. Exact repeats retain the original; changed content or another quote with the same recipient is rejected. |
| `book.enroll_wire(quote_id, payer, wire, evidence=independent_p4_evidence)` | Explicit merchant confirmation of the independently retained original signed wire. Replays the supplied P4 evidence under the book's pinned policy, derives the native owner/grant or exact historical receipt signer, and verifies the native Ed25519 signature. Incoming wrappers cannot enroll a wire or supply a public key. The original assignment never changes. |
| `book.fulfill(quote_id, signature_header, capsule)` | Replays retained enrollment evidence and the incoming full capsule every time, including after a completed row exists. Atomically inserts unique native transaction/wire identities across this merchant book and an immutable local result before returning its exact bytes and response header. |
| `book.selected(quote_id)` / `book.entries()` | Inspect retained metadata. These reads do not consume, enroll, sign, submit, release holds or establish current execution/delivery authority. Expectations are returned as frozen `NativePaymentExpectation` objects. |

Resource bytes are fixed at quote creation, at most 65,536 bytes, and must be
public content. The book holds at most 64 quotes with no eviction or recipient
reuse. Enrollment wires and both consumption identities have SQL uniqueness
constraints. The book validates the exact schema, foreign-key relationships,
stored identities, canonical expectations/headers/evidence and immutable resource
bytes. Aggregate retained payload work is capped at 64 MiB, and each database or
sidecar is capped at 80 MiB. Original P4 evidence/capsule bounds remain unchanged.

The parent directory and files must be owned by the current POSIX user and closed
to group/other access. Symlink ancestors, symlink/hardlink database files and
sidecars are refused. Creation is exclusive and directory-synced. The journal
uses WAL and synchronous FULL transactions, checks the original independent
genesis/policy identity, and refuses clock regression. Unknown schemas and
incomplete or modified stores are retained and rejected rather than repaired.
These checks assume a trusted same-user host; they do not defend against
coordinated privileged database rewrites, copied journals or filesystem rollback.

Enrollment is not proof of payment or a grant of financial authority. For a wire
not already present in the independently verified receipt history, its nonce and
expiry must match the selected verified owner/grant view. Unknown, revoked or
wrong-epoch grants are rejected with no owner fallback. A verified exact
historical receipt may authenticate its recorded historical signer. If only the
selected current key view is available and it cannot authenticate an old wire,
the enrollment fails closed. No enrollment key comes from an invoice/wrapper,
and the selected view is not a guarantee of latest network state.

On first fulfillment, native proof verification, consumption and retention of
the exact public result occur in one SQLite transaction. A commit failure rolls
back the local claim/result. An identical repeat returns
`original_local_fulfillment_retained` with the original resource, response and
timestamp, after fresh proof verification. Changed quote/context, wire, capsule,
signature wrapper or resource cannot use a cache shortcut. A valid but different
later capsule is also refused for an already completed record; the original proof
is retained. Unresolved wire enrollment and completed consumption survive an
ordinary close/reopen.

There is no external side-effect callback. SQLite commit and HTTP response are
not atomic: response loss may leave a durable local fulfillment whose exact
result can be fetched through an identical, reverified fulfillment call. The
book neither repeats an external service effect nor proves that a customer
received the HTTP response. It always reports
`external_service_delivery_verified: false` and
`globally_exactly_once_service_delivery: false`. It changes no wallet reservation
or one-attempt P4 delivery record.

## Loopback merchant HTTP fixture

`tools/private-payments/src/merchant_http.py` carries the original native wire in
`PAYMENT-SIGNATURE` and the complete canonical capsule as an `application/json`
POST body. It uses a synchronous `HTTPServer` bound to literal `127.0.0.1`, with
one active handler, a four-connection listen queue and five-second socket timeouts.
It is an operator-owned local development fixture, not public merchant hosting.

Create it with `server(book_factory, session_token=token, port=0, quote_id=None)`.
The independently supplied per-process token must be 64 lowercase hex characters;
the trusted caller should generate it with `secrets.token_hex(32)`. The returned
server exposes `.origin`, such as `http://127.0.0.1:<chosen-port>`. For an ephemeral
port, retain the quote at that exact merchant/resource origin, then call
`.configure_quote(quote_id)` **once, before starting the server**. An already
retained quote can instead be supplied through the `quote_id` creation keyword
when its exact port/origin is known.

Configuration freezes the original quote ID, exact path/query, expectation,
required header, public resource digest, and merchant database path/genesis/policy
context. The trusted factory returns a context-managed `MerchantBook` for that
same database per request. There is no HTTP quote selector, session-discovery,
wire-enrollment, signing, native-submission, collection or wallet route.

Every request requires `X-1soft-Merchant-Session: <token>`, exact
`Host: 127.0.0.1:<port>`, and, if supplied, the exact loopback `Origin` and
`Sec-Fetch-Site: same-origin` or `none`. The token is local fixture access
authentication, not merchant identity, user spending approval or payment proof.
It is never served, attached to errors, stored in the merchant database, or
logged by the server. Request/error logging is silent. No CORS access is granted.

Authenticated GET on the exact configured path returns HTTP 402 with the
original `PAYMENT-REQUIRED` header and performs only non-authoritative merchant
inspection. POST on that path requires one bounded `PAYMENT-SIGNATURE` header,
exact `Content-Type: application/json`, and canonical full capsule bytes. It
calls `book.fulfill`; only a successfully retained/reverified local result gets
HTTP 200, exact immutable resource bytes and `PAYMENT-RESPONSE`. Response loss
does not undo that durable result; an identical valid POST retrieves the saved
bytes after rechecking evidence, without a second native submission or external
service effect.

Malformed or duplicate headers, obsolete HTTP versions, unsupported methods,
transfer/content encoding, chunking, `Expect`, GET bodies, wrong path or session,
duplicate/noncanonical JSON and excess lengths are refused before fulfillment.
Application header work is bounded to 64 fields/65,536 aggregate characters,
with at most 32,768 characters in a signature header. The standard-library parser
also supplies finite pre-application line/header-count limits. Capsule bodies
retain the existing `MAX_CAPSULE_BYTES` bound. Every response closes the connection
and disables caching; generic errors echo no request, token, key or plaintext
resource. This synchronous fixture offers bounded socket work, not production
DoS hardening, multi-host identity or availability guarantees.

`test_merchant_http.py` exercises genuine synthetic P4 capsule transport, 402
read-only offers, missing/wrong authentication, Host/Origin/Fetch enforcement,
fixed quote selection, unsupported methods/versions, header/body bounds,
duplicate JSON, invalid evidence after completion, and verified first-request
retention followed by exact result retrieval after a lost HTTP return. Synthetic
committee evidence remains separate from the root actual-validator HTTP gate.

## Full-evidence disclosure and proof scope

The signature header includes the original public wire and a capsule SHA256;
the full capsule is supplied separately, for example in an operator-owned local
fixture body. This body is not a standard stock x402 mechanism. It must be
bounded by the inherited capsule limit before parsing. No remote capsule URL,
arbitrary URL retrieval or full-evidence HTTP header is offered.

**Sending this full capsule reveals public ledger history, accounts, amounts,
grants, validator changes and complete replay evidence to the merchant.** This
transport has no privacy, unlinkability, zero-knowledge or selective-disclosure
claim. A future confidential receipt design is a separate cryptographic system,
not a rename of this evidence carrier. Never include keys or wallet database
files in a fixture body.

The existing capsule verifier checks dynamic-validator signed history and native
execution under the original independent trust policy. It proves a selected
historical positive transfer, not current network state, independent validator
hosts, actual observed ABCI responses, external settlement, or wallet headroom.

## Private payment CLI

`tools/private-payments/scripts/1soft_private.py` is an explicit local CLI over
`InvoiceBook`, `PrivatePaymentDesk` and the existing native financial authority.
Run it with the already-installed development Python. Wallet commands connect to
an initialized, ready local workspace and the independently pinned engine; they
never start engines, bootstrap trust, repeat submission or stop someone else's
runtime. The dedicated invoice-data seed persists in its own encrypted PKCS8 vault,
`invoice-data.pem`, and remains distinct from the payment vaults and financial
journals. This is trusted-host software custody, with no hostile-OS, backup
rollback, production custody or memory-erasure claim.

Each wallet command requires `--workspace DIR --engine PINNED_BINARY --invoices
DIR`. Standalone invoice commands require `--invoices DIR --genesis-sha256 HEX`
and do not need an engine. All paths refer to private owned POSIX directories and
files. Inputs reject links, extra file permissions and excess size. Outputs must
be new private files outside the source tree; existing files are never replaced
or repaired. The CLI prints JSON metadata on stdout and generic failures on
stderr. It never prints decrypted invoice content or a password.

| Command | Additional arguments and behavior |
| --- | --- |
| `init-invoices` | Standalone; initializes a new invoice directory and dedicated encrypted invoice-data vault. Prompts twice. |
| `inspect` | Standalone; optional `--request-id HEX`; reads encrypted invoice metadata, without decryption or spending authority. |
| `check-quote` | Standalone without invoice storage; `--required FILE --expectation FILE`; checks exact terms using the current explicit system clock. Retains no request and grants no spending authority. |
| `import-invoice` | Wallet; `--required FILE --expectation FILE --content FILE`; prompts for the invoice-data password, encrypts the application data and appends only the unsigned canonical native request. |
| `open-invoice` | Standalone; `--request-id HEX --output NEW_FILE`; prompts for the invoice-data password and writes plaintext only to that new private JSON file. |
| `export-invoice` | Standalone; `--request-id HEX --output NEW_FILE`; writes the exact retained encrypted envelope without unlocking either key. |
| `prepare` | Wallet; `--request-id HEX --role owner\|raven\|atlas --valid-until HEIGHT --output NEW_FILE`; writes an unsigned native-and-merchant review wrapper, with no reservation or signature. |
| `approve` | Wallet; `--request-id HEX --role ROLE --review FILE --confirmation NATIVE_HEX --terms-confirmation TERMS_HEX`; prompts for the payment-vault password only after the wrapper and both independently supplied confirmations match. Native authority rechecks the current review before signing or returning an already retained original. |
| `recover` | Wallet; `--request-id HEX --output NEW_FILE`; writes the exact original signed wire without a new signature, hold or submission. |
| `submission-review` | Wallet; `--request-id HEX --output NEW_FILE`; writes the separate explicit submission review wrapper and its confirmation. |
| `submit` | Wallet; `--request-id HEX --review FILE --confirmation HEX`; consumes the confirmed submission review through the existing durable one-attempt journal. An unresolved result remains unresolved; there is no automatic retry. |
| `collect` | Wallet; `--request-id HEX`; asks the existing evidence collector for the original payment's positive execution receipt. Collection does not retire the wallet hold. |
| `retain-receipt` | Wallet; `--request-id HEX`; creates and retains the verified public native receipt capsule, without financial reconciliation. |
| `export-receipt` | Wallet; `--request-id HEX --capsule-id HEX --output NEW_FILE`; exports that verified canonical full capsule for the local fixture transport. |
| `payment-header` | Wallet; `--request-id HEX --capsule-id HEX --output NEW_FILE`; writes the desk's JSON result containing `payment_signature_header` and exact digests. This file is structured payment material, not a naked HTTP header or authorization to deliver a resource. |
| `reconcile` | Wallet; `--request-id HEX --expected-revision HEX`; explicitly invokes the existing wallet reconciliation under the caller's selected current revision and verified exact receipt. |

The required-header file contains **only the exact ASCII base64 header value**,
without a trailing newline. The independent expectation file is canonical JSON
with exactly `merchant_origin`, `resource_url`, `network`, `asset`,
`genesis_sha256`, `recipient` and `amount_units` (the amount is a decimal string).
Its bound is 4096 bytes. The expectation must come from an independently trusted
operator or merchant configuration; a file copied from the offer is not
authentication. No URL is fetched. The private content input is JSON with
`description`, `contact` and `content`, bounded to the existing 10000-byte
plaintext limit. Duplicate JSON fields are rejected. The required header retains
the protocol's 8192-character limit; review and payment-material files are
bounded to 65536 bytes, encrypted envelopes to 14000 bytes, and exported full
capsules to the existing `MAX_CAPSULE_BYTES` bound.

`prepare` writes this canonical wrapper, rather than a naked native review:

```json
{"schema":1,"format":"1soft/private-cli-approval/v1","request_id":"<request SHA256>","role":"raven","prepared":{"review":"<original native review object>","confirmation":"<native review SHA256>","terms":"<original merchant terms object>","terms_confirmation":"<terms SHA256>","request_id":"<request SHA256>","role":"raven","reserved":false,"signed":false,"broadcast":false}}
```

The placeholders illustrate object structure; actual `review` and `terms` are
JSON objects. Read both objects before explicitly selecting the two confirmation
arguments. `approve` requires the wrapper's request, role, native review and
terms to match those arguments, and the desk rebuilds the merchant terms from
the independently retained invoice. Passing only the native review is refused.
`submission-review` uses the separate `1soft/private-cli-submission/v1` wrapper
with `schema`, `format`, `request_id` and `prepared`; its `prepared` object has
the original submission `review`, `confirmation`, `request_id`,
`submission_performed:false` and `wallet_reservations_changed:false`.

For example, after an independent quote check and invoice import, preparation
and approval are separate operations:

```text
1soft_private.py prepare --workspace PRIVATE_WALLET --engine PINNED_BINARY --invoices PRIVATE_INVOICES --request-id REQUEST_HEX --role raven --valid-until HEIGHT --output NEW_APPROVAL_FILE
1soft_private.py approve --workspace PRIVATE_WALLET --engine PINNED_BINARY --invoices PRIVATE_INVOICES --request-id REQUEST_HEX --role raven --review NEW_APPROVAL_FILE --confirmation REVIEWED_NATIVE_HEX --terms-confirmation REVIEWED_TERMS_HEX
```

Passwords are accepted only by `getpass` with both stdin and stderr attached to
a TTY; stdout may be a JSON pipe. There are no password argument or environment
options. Invoice operations prompt `Invoice-data vault password: `; initialization
then prompts `Repeat invoice-data vault password: `. Approval prompts `Payment
vault password: `. The qualification-only terminal driver supplies disposable
test passwords programmatically to an owned PTY after the actual prompt and echo
disablement. This is an actual interactive-path test, not a production password
injection API. It retains only safe result metadata and digests, never passwords
or raw terminal logs.

**The signed native wire and exported capsule disclose public ledger evidence.**
Neither invoice encryption nor this CLI hides ledger accounts, grants, balances,
validator history or transfer details. Merchant replay consumption remains in
the separate merchant book. A payment header, HTTP 200 or merchant result never
reconciles wallet funds; only the explicit existing native reconciliation can
retire the original hold. Invoice/request retention spans two stores and is not
claimed atomic; a failed unsigned append can be completed through the original
live import without replacing ciphertext or signing a payment.

`test_private_cli.py` exercises actual private storage, standalone subprocesses,
real getpass through an owned PTY, private file/JSON/header bounds, generic damaged
storage refusal, both explicit confirmations, original recovery, genuine
synthetic P4 receipt callers and unresolved one-attempt holds. Only the terminal
password boundary in the direct wallet caller tests is substituted; encrypted
vaults, journals, native signatures, local RPC and capsule verification are real.
Actual four-validator subprocess CLI qualification is a separate root gate.

## Verification and source attribution

`tools/private-payments/tests/test_payment_x402.py` exercises the real existing
P4 application and capsule verifier with **synthetic committee signatures and
public deterministic test keys**. The fixture includes actual native/admin replay
and validator replacement. It is not consensus evidence. Tests cover canonical
unsigned intent, offer/trust/numeric/header/URL bounds, original-wire and capsule
binding, independently pinned assignments, rebundling a genuine public receipt
for a second resource, tampered signatures, changed genesis/policy/time and
untrusted response declarations. `test_merchant_book.py` covers immutable public
content, same-recipient reuse, independent signer-key verification, wire
reassignment, tampered incoming evidence after completion, changed valid
capsules, duplicate exact result retrieval, restart with enrolled/consumed
records, cross-quote replay, read-only inspection, private file/schema checks,
resource mutation, no-eviction capacity and rollback under a real SQLite commit
denial. Actual validator and product/HTTP integration qualification remain
separate root gates.

The implementation was written from tests after a missing-feature red run. Fresh
logs are outside the repository at
`/home/xnuonux/1soft-payment-protocol-agent-20260930/`. The focused runner uses the
already-installed Python environment at
`/home/xnuonux/1soft-v016-execution/integrated/.venv/bin/python`, with source paths
for `src`, `scripts`, `tools/validator-transition/src`, `tools/protocol4-client/src`,
`tools/protocol4-client/tests`, `tools/protocol4-wallet/src`,
`tools/protocol4-receipts/src`, `tools/local-platform/src`, and
`tools/private-payments/src`, and runs
`-m unittest discover -s tools/private-payments/tests -p test_payment_x402.py -v`.

Primary interface references were read from the inert warehouse copy of
[x402 Foundation](https://github.com/x402-foundation/x402/tree/c8c71f244c0d45a6a4fd990a96c69aa34781cd05):
[v2 specification](https://github.com/x402-foundation/x402/blob/c8c71f244c0d45a6a4fd990a96c69aa34781cd05/specs/x402-specification-v2.md),
[HTTP transport](https://github.com/x402-foundation/x402/blob/c8c71f244c0d45a6a4fd990a96c69aa34781cd05/specs/transports-v2/http.md),
and TypeScript core `types/payments.ts` and `types/facilitator.ts`. The upstream
`LICENSE` is Apache-2.0 and `NOTICE` identifies Copyright 2026 x402 Foundation.
This package preserves that interface/source attribution and copies no upstream
SDK implementation. The current official specification was also located by
read-only web research; implementation references remain pinned to the above
revision. No acquired code, dependency install or upstream SDK execution occurred.
