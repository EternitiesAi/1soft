# Minimal delivery receipt

`1soft/minimal-delivery-receipt/v1` is a deliberately reduced metadata
projection for a browser resource download in the transparent local alpha. It
is separate from `1soft/alpha-merchant-proof/v1`, which remains the explicit
full public proof export.

The minimal receipt contains only:

- the selected public resource digest;
- the fixed literal loopback merchant origin and resource path;
- the quote commitment;
- the fact that the original enrolled execution was fulfilled; and
- an opaque 32-byte verifier anchor selected by the trusted caller.

It omits payer, grant and budget identifiers, original wire, receipt capsule,
native transaction ID, validator signer key, full history, session token,
invoice timestamps, and resource bytes. It cannot independently prove payment
or merchant identity. The verifier anchor is a binding input for a future
transparent verifier; in this alpha it is metadata, not a cryptographic
zero-knowledge proof or an anonymity set.

The producer should derive a fresh delivery- or audience-scoped verifier anchor.
Reusing a payment, quote or customer-derived anchor across receipts creates a
stable correlation handle. This alpha validates only the anchor's exact 32-byte
shape; it does not enforce freshness or prove how the caller selected it.

This projection reduces application-level disclosure. It does not hide the
same activity from a public ledger observer, local process, browser extension,
merchant operator, network observer, or anyone who already knows the public
quote/resource. The loopback origin and resource path can still be correlated,
and the resource digest may be a stable fingerprint. It also does not pad
timing, hide ciphertext length, or prevent correlation through other public
ledger records.

The full proof export must remain a separate deliberate action because it
contains full bounded public ledger history and exact payment evidence. A
minimal receipt must never be presented as shielded privacy, a payment proof,
customer anonymity, merchant authentication, or a production release.
