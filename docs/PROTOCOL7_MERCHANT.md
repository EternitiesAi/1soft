# P7 local merchant purchase boundary

This adapter connects an immutable local quote to an exact certified P7 payment
and one retained public resource result. It uses the native domain604 merchant
note commitment already constrained by the frozen P7 relation. The circuit,
profile, parameters, verifying key, P1/P2/P3 bytes and `smt-v1` are unchanged.

The initial implementation needs its own clean-source real-engine qualification;
the earlier wallet or P4 merchant receipts do not qualify this adapter.

## Agreement before payment

`MerchantBook.create_quote` retains a closed canonical quote containing exact
public resource bytes/hash, an externally configured merchant namespace and
recipient field, atomic amount, payment-note expiry, chain/full-genesis/profile
pins, asset/mission, grant ID/generation, owner epoch, validity window, book ID
and a fresh unique nonce. The request field is:

```text
SHA256("1soft/P7-merchant-quote/v1\0" || canonical_quote_core)[:31] || 0x00
```

Those 32 bytes use the existing little-endian field encoding. The upper byte
is zero, so the value is less than 2^248 and fits the native field without a
modulus operation. `quote_sha256` separately hashes the canonical core normally.
This is a versioned local adapter encoding, not a change to consensus.

The exact purchased resource is a nonempty opaque byte string of at most8192
bytes. There is no URL normalization, redirect, HTTP route or external retrieval
in this milestone. A different resource or nonce produces a different request;
an existing payment cannot be assigned a new quote after it is observed.

Quotes are purchase terms, not assertions of current spend authority. A positive
specified grant generation may become unfulfillable; only independently replayed
certified execution establishes that the payment had valid authority. Genesis
metadata is not treated as a fresh observation of a post-rotation grant. The local
adapter restricts `1 <= valid_from < valid_until <=64` and expiry at least
`valid_until`; it makes no liveness or latest-state guarantee.

## Exact execution and explicit disclosure

Enrollment requires the exact P7 execution record, including4168-byte wire,
txid/hash, full-state witness, signed next header, receipt and certificate. It
checks external genesis/bootstrap/profile/verifier/KAT pins, verifies the native
proof, independently replays the AS-OF state through `checked_observation`, and
requires `_resolve == executed-exact`. A certificate without exact inclusion
cannot fulfill a quote.

It then checks the quote-derived request against `p18`, network domain `p1`,
asset/mission, grant ID/generation, owner epoch and exact validity window. The
measured native note controller accepts exactly1256 bytes: existing pinned
request header,30 public fields and the five closed disclosure fields. It maps
recipient/payment/blind/expiry/note-secret to witness12/13/14/29/30 and calls the
existing `relation::merchant_note`:

```text
H(604, p1, p2, p3, p18, p26, p28,
  payment_expiry, payment, recipient, payment_note_secret, payment_blind)
```

The result must equal certified `p22`. Payment and expiry are canonical u64s;
recipient, blind and secret are nonzero canonical fields. Amount is positive;
expiry is at least `p16`. All five terms and all native hash domains matter.
Quote recipient/amount/expiry must match the disclosure exactly.

This is explicit disclosure to a trusted local merchant, not selective-ZK
disclosure. A native commitment match proves neither execution by itself nor
authenticated merchant identity, recipient ownership, redemption or settlement.
Helper execution failure is `Unavailable`; an available helper returning a
different commitment is a deterministic `MerchantError`.

## Durable local result and privacy boundary

The merchant book requires an owner0700 directory and regular owner0600 SQLite
files, no symlink parents/hardlinks, a fixed database identity, external256-bit
AES key, opaque book ID and configured recipient/namespace. Creation is explicit
and exclusive; opening a missing book does not initialize one accidentally.
SQLite uses WAL, FULL synchronization, foreign keys and bounded exact schema.

An AES-GCM key check catches the wrong key even before the first payment.
Disclosures are encrypted with unique12-byte nonces. Associated data binds the
complete pins, original request and exact certified-origin digest. The key,
payment blind and note secret are not stored or exported in plaintext. On cold
open, retained disclosures are decrypted and checked again against the native
commitment and retained certified payment. This does not protect against a hostile
host, stolen key, cloned/rolled-back history or key loss.

`enroll` is immutable. Re-enrolling the identical record/disclosure is idempotent;
another wire, disclosure or later certificate cannot replace it. `fulfill`
atomically retains canonical result bytes tied to quote/hash, exact wire/hash,
`p22`, certified height/AppHash/certificate and original resource bytes/hash.
Duplicate calls and cold reopen return those same bytes from one retained row.
There is no external side-effect callback or claim of globally exactly-once
delivery, and no wallet dispatch/release/retry is invoked by this adapter.

`inspect` is a read transaction, with no fulfillment or retry authority. It
re-verifies the retained certificate and encrypted opening, so it can fail if
the helper is unavailable; it is not a cheap unauthenticated metadata query.
Outputs explicitly keep freshness, retry, external delivery and redemption false.

## Developer command and qualification

`scripts/owner_treasury_merchant.py` provides one-shot `quote`, `enroll`, `fulfill`
and `inspect`. Public flags pin book/genesis/verifier/KAT/controller/recipient;
the external key and opening enter only through bounded canonical stdin. Optional
execution receipts report helper operation/PID/start ticks/binary hash and byte
counts, never private request values or their hashes. Errors emit closed static
diagnostics. After entering a mutating method, a failed return is conservatively
unknown: inspect retained state; the response does not authorize another payment.

The actual gate is `scripts/run_protocol7_merchant.py`; independent public replay
is `tools/release/check_protocol7_merchant.py`. The gate uses one fresh native
arbitrary proof on four actual pinned CometBFT0.38.25 validators, actual merchant
commands, five opening mutations, wrong quote/certificate guards, helper failure,
encrypted cold open, a deliberate application-return discard, exact duplicate
recovery, read-only store checks, corruption guards and an authenticated same-store
engine restart. Helper unavailability, ciphertext mutation and return discards
are deliberate test injections, not uncontrolled incidents or concurrency stress.

The exported ciphertext is not independently decrypted by the public checker;
its independent guarantee is public proof/certificate/source/artifact replay.
Private disclosure checks and decryption are measured behavior of this local run.
P7 domain604 redemption remains a separate relation/state/wallet gate: ordinary
and CHANGE input notes do not by themselves permit merchant-note redemption.

No public service, deployment, real funds, paid compute or production keys are
used. This milestone does not qualify production privacy, operator independence,
economics, listings, external service agreements or a value-bearing launch.
