# 1soft private-payments foundation

Encrypted local invoices, explicit merchant/native consent, one existing P4
payment attempt, replayable native receipts and durable local merchant fulfillment.
**Application data encryption is implemented; on-chain privacy is not.** This is
a valueless local developer slice, not a public cryptocurrency release.

Start with [the foundation record](../../docs/PRIVATE_PAYMENTS_FOUNDATION.md),
[CLI and native x402 guide](../../docs/X402_NATIVE_DEVELOPMENT.md) and
[future private-ledger architecture](../../docs/PRIVATE_PAYMENTS_ARCHITECTURE.md).
The existing wallet owns all signatures, holds, attempts and reconciliation.
Merchant responses never retire funds or authorize another payment.

```sh
python -B tools/private-payments/scripts/1soft_private.py --help
python -B tools/private-payments/scripts/qualify_private.py \
  --engine /absolute/path/to/pinned/cometbft --output /absolute/private/new-output
```

Run qualification in the original pinned private POSIX environment. It preserves
all 445 d14165d parent files and runs the unchanged full developer-release gate,
new private components and the actual four-validator journey. No Actions, downloads,
public deployment, paid compute or real funds are involved. Source inventories
are `DEPENDENCIES.json` (complete parent) and `SOURCE_MANIFEST.json` (this package).

The CLI operates an existing local development workspace; it does not launch
validators or retry payments. Invoice-data and payment passwords use terminal
input only. Decrypted content is written only to an explicitly selected new private
file. Preserve the original data vault, invoice store and sole financial journal;
there is no reset/repair command.
