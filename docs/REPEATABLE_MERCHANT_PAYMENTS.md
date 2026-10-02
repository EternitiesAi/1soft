# Repeatable local merchant payments

The private-payments package can now process several distinct invoices in one
intact merchant book. A fresh local development network preallocates 2–16 merchant
recipients. Each quote permanently assigns one recipient, including after expiry
or fulfillment. Owner, Raven and Atlas use the same original P4 wallet; Raven
and Atlas share its delegated budget. The merchant verifies independently enrolled wires and replayed native
execution before returning a public resource.

This is a finite, valueless local development fixture. Invoice content is encrypted
locally. Native transfers and full-history receipt capsules remain public. Native
signatures do not authenticate invoice or resource terms. Separate quote pins and
operator enrollment remain necessary; copied books or devices are outside the
consumption guarantee.

## Run the complete qualification

Use the existing pinned private Linux environment and CometBFT 0.38.25 binary.
No installation, download, public endpoint, GitHub Action or real funds are needed.
The output directory must be new and outside the repository.

```sh
python -B tools/private-payments/scripts/qualify_merchant.py \
  --engine /absolute/path/to/pinned/cometbft \
  --output /absolute/private/new-merchant-qualification
```

This first runs the complete inherited and private-foundation qualification,
including its original actual-validator scenarios. It then runs the new
three-invoice journey on four actual local validators: owner pays 7, Raven 11 and
Atlas 13 DEV units, each with fee 2. It abandons a real HTTP return after durable
fulfillment, cold-restarts the original workspace and recovers original wires,
ciphertexts, grants, journal entries and resources. Holds remain 37 until explicit
native reconciliation. Final balances are owner 957, recipients 7/11/13 and fees
12; supply stays 1000 and the shared delegated budget spends 28.

`run_merchant_acceptance.py` runs only the new actual journey. Its exploratory
result is explicitly source-unqualified. Use `qualify_merchant.py` for complete
qualification tied to a clean source commit, manifests and pinned engine.

## Operate a fresh fixture

The commands below run from the repository root on Linux. Use private directories
outside the source tree. Create input files with owner-only permissions, for
example after `umask 077`; even files inside a private directory must be private.
Passwords are entered only at a terminal prompt, never
through arguments, environment variables or a saved command. Each runtime and
merchant server has a finite operating window; startup and shutdown have their
own bounded waits. A synchronous HTTP handler may finish after that window.

```sh
python -B tools/private-payments/scripts/1soft_merchant_network.py init \
  --workspace /absolute/private/new-network \
  --engine /absolute/path/to/pinned/cometbft --recipient-count 3

python -B tools/private-payments/scripts/1soft_merchant_network.py run \
  --workspace /absolute/private/new-network \
  --engine /absolute/path/to/pinned/cometbft --seconds 300
```

The first run performs the original budget and two grant setup operations. Ready
restart is key-free and retains the original policy. Keep the original workspace
and every journal and vault. The initializer refuses an existing path; it does
not migrate a v1 workspace, rewrite genesis or renew trust. A partially initialized
workspace is retained and fails closed once canonical financial journals exist.

In another terminal, initialize the sole merchant book:

```sh
python -B tools/private-payments/scripts/1soft_merchant.py init-book \
  --workspace /absolute/private/new-network \
  --engine /absolute/path/to/pinned/cometbft
```

Create a quote with an unused recipient index, exact loopback origin and unique
resource path. The resource is explicitly **public**; do not put private invoice
content in it. Its size is bounded to 64 KiB. Supply its SHA-256 as
`--public-resource-confirmation` and a future
Unix timestamp in nanoseconds as `--expires-ns`:

```sh
python -B tools/private-payments/scripts/1soft_merchant.py add-quote \
  --workspace /absolute/private/new-network \
  --engine /absolute/path/to/pinned/cometbft --recipient-index 0 \
  --origin http://127.0.0.1:39080 --resource-path /premium/invoice-1 \
  --amount-units 7 --resource /absolute/private/public-resource.txt \
  --public-resource-confirmation RESOURCE_SHA256 --expires-ns FUTURE_UNIX_NS
```

Retain the returned `quote_sha256`. `export-quote --quote-id QUOTE_SHA256
--required-out NEW_PRIVATE_PATH --expectation-out NEW_PRIVATE_PATH` exports the
original header and independent merchant expectation. Both outputs are exclusive;
if the second write fails, retain the first and export to new paths. The original
quote assignment remains consumed. `inspect` shows the original assignments,
enrollments and fulfillments without unlocking a key.

Follow the existing [payer CLI guide](PRIVATE_PAYMENTS_FOUNDATION.md): initialize
an invoice-data vault, import with independently selected expectations, prepare a
review, confirm both native and merchant terms, and approve once with the selected
role. The payer CLI accepts both validated v1 and v2 workspaces. `recover` returns
the original signed wire without another signature or reservation.

Before payment submission, enroll that exact wire against the selected quote:

```sh
python -B tools/private-payments/scripts/1soft_merchant.py enroll-wire \
  --workspace /absolute/private/new-network \
  --engine /absolute/path/to/pinned/cometbft --quote-id QUOTE_SHA256 \
  --payer ORIGINAL_OWNER_ID --wire /absolute/private/original-wire.json \
  --wire-confirmation WIRE_SHA256 \
  --evidence /absolute/private/independently-retained-native-evidence.json
```

Enrollment verifies independently selected current native evidence, original
wire, payer, role authorization and quote recipient. An HTTP request cannot enroll
itself. The payer must independently review and explicitly submit through the
original delivery journal, then collect and retain the actual native receipt.
Export its capsule and payment-signature header using the payer CLI.

Serve the retained routes with repeated quote selections:

```sh
python -B tools/private-payments/scripts/1soft_merchant.py serve \
  --workspace /absolute/private/new-network \
  --engine /absolute/path/to/pinned/cometbft \
  --quote-id FIRST_QUOTE_SHA256 --quote-id SECOND_QUOTE_SHA256 \
  --session-file /absolute/private/new-session.json --seconds 120
```

Use the token from that private session file for `X-1soft-Merchant-Session`.
GET returns the route's original `PAYMENT-REQUIRED` header. POST accepts the exact
native capsule as its JSON body and the original `PAYMENT-SIGNATURE` header.
Every successful response, including a replay, re-verifies native execution.
The server returns only the selected retained public resource. It never signs,
submits, enrolls, retries or clears a wallet hold. Keep the session file private;
the token is absent from stdout.

## Boundaries that remain

The recipient pool cannot be extended or reused. Pool exhaustion requires a new
disposable development fixture; it is not unlimited billing. Concurrent operator
assignment uses a kernel file lock, and the intact merchant book consumes each
enrolled native transaction once across its quotes. This is not global exactly-once
service delivery across copied books, processes, devices or independent operators.

There is no trust renewal, retry, rearm, reset or automatic repair. Expired policy
or original quote/wire pins refuse. Preserve uncertain original obligations;
merchant fulfillment and retained receipts do not retire them. Explicit native
reconciliation alone can clear them.

Native invoice commitments, live account provisioning, private-ledger proofs,
production custody, independent hosts/operators, external security audit, human
wallet UI, commercial demand and real-money launch remain separate unassessed
work. See [private-ledger architecture](PRIVATE_PAYMENTS_ARCHITECTURE.md) before
making a stronger privacy claim.
