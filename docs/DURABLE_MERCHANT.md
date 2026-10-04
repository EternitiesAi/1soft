# Durable alpha merchant fulfillment

This explicit development adapter completes a committed invoice with an immutable
public resource. Use a fresh `1soft/local-alpha-invoice-workspace/v1` with original
DEV genesis, `durable-private-alpha-v1`, invoice capability 1 and policy v2.
It never migrates an old workspace or changes native monetary/signature rules.

`merchant_alpha.AlphaMerchantBook` uses `merchant-alpha.sqlite`; the legacy v1
book remains exclusive to legacy receipts. The new signature payload and portable
proof have separate alpha format identities. `1soft_merchant.py` selects its
adapter from the independently validated workspace, never from an incoming packet.
`verify_merchant_proof.py --profile alpha` requires independent genesis, original
policy, expectation, assignment and caller-selected AS-OF time.

The operator retains exact quote/resource bytes, then explicitly enrolls the
original signed wire with a fully verified positive alpha receipt. The HTTP
endpoint cannot enroll, sign or submit. Its authenticated GET returns 402 and the
retained quote. POST accepts a small PAYMENT-SIGNATURE header binding the SHA256
of the original receipt packet and a separately bounded JSON packet body.
The reference-based alpha `capsule_id` is reported separately from that hash.

New enrollment and consumption require the current quote interval and the original
fixed 24-hour horizon. Clock monotonicity and expiry are rechecked after replay,
after insertion and immediately before committing. Committed invoice signatures
allow multiple distinct resources to use the one pinned merchant recipient;
quote/request IDs, routes, original wires and native transaction IDs stay unique.
The resource and consumption record commit together; socket failure does not
undo consumption. Identical retries fully reverify the original payment and
return the original bytes/time, including after expiry or the fixed horizon.
This historical retrieval gives no permission for a new charge or consumption.

The book stores each complete packet once, with no eviction: 64 quotes, 64 KiB
per public resource, 80 MiB logical quote/payment bytes and 240 MiB total physical
SQLite/WAL/shared-memory bytes. Each alpha packet retains the original custody
bound of 64 MiB plus 64 KiB framing. Proof transport has an explicit base64 bound.
Quota refusal preserves existing rows. Paths are owner-only on the same POSIX
host; SQLite FULL/WAL durability and an intact journal/local clock remain
assumptions. This is not tamper-proof external notarization or multi-host delivery.

A portable proof cold-replays signed block inclusion, registry authorization,
native execution and the exact invoice/resource commitment. Quote interpretation
uses external AS-OF time; the audited signed checkpoint may not exceed that time
plus the pinned clock-drift allowance. Original host admission times, actual
buyer receipt, merchant identity, global consumption uniqueness, external service
completion, settlement and current spending authority are not proved.
Transactions and receipt history are public; this is not onchain privacy.

The complete caller path is CLI invoice payment and receipt export, explicit
merchant enrollment, authenticated local HTTP resource retrieval, and cold proof
verification. The optional [browser host bridge](BROWSER_MERCHANT_DELIVERY.md)
connects the guarded wallet to the separately configured fixed loopback merchant;
direct cross-origin browser fulfillment remains unavailable. Existing browser
invoice/receipt behavior is retained. Actual short four-validator
qualification is separate from historical hour-scale source receipts; it cannot
relabel an old hour test as a new-source long-horizon qualification.
