# 1soft private-payments foundation

Encrypted local invoices, explicit merchant/native consent, one existing P4
payment attempt, replayable native receipts and durable local merchant fulfillment.
**Application data encryption is implemented; on-chain privacy is not.** This is
a valueless local developer slice, not a public cryptocurrency release.

Start with [the foundation record](../../docs/PRIVATE_PAYMENTS_FOUNDATION.md),
[CLI and native x402 guide](../../docs/X402_NATIVE_DEVELOPMENT.md) and
[future private-ledger architecture](../../docs/PRIVATE_PAYMENTS_ARCHITECTURE.md).
The existing P4 wallet and delivery path own signatures, holds, attempts and reconciliation.
Merchant responses never retire funds or authorize another payment.

[Repeatable merchant payments](../../docs/REPEATABLE_MERCHANT_PAYMENTS.md) adds a
fresh finite recipient pool, key-free merchant operator commands and exact
multiple invoice routes. It supports separate owner, Raven and Atlas payments
without changing native signatures or ledger privacy. Original v1 workspaces are
preserved; recipient assignments are never reused.

```sh
python -B tools/private-payments/scripts/1soft_private.py --help
python -B tools/private-payments/scripts/qualify_private.py \
  --engine /absolute/path/to/pinned/cometbft --output /absolute/private/new-output
python -B tools/private-payments/scripts/qualify_merchant.py \
  --engine /absolute/path/to/pinned/cometbft --output /absolute/private/new-merchant-output
```

Run qualification in the original pinned private POSIX environment. It preserves
all 445 d14165d parent files and runs the unchanged full developer-release gate,
new private components and the actual four-validator journey. No Actions, downloads,
public deployment, paid compute or real funds are involved. Source inventories
are `DEPENDENCIES.json` (complete parent) and `SOURCE_MANIFEST.json` (this package).

The payer and merchant-operator CLIs operate an existing local development
workspace. The separate merchant-network lifecycle CLI explicitly launches
validators; payment operations never launch them or retry payments.
Invoice-data and payment passwords use terminal
input only. Decrypted content is written only to an explicitly selected new private
file. Preserve the original data vault, invoice store and sole financial journal;
there is no reset/repair command.
