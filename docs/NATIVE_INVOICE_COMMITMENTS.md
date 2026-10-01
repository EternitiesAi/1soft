# Native invoice commitments: development design

This continuation adds native authentication of approved public invoice terms to
the repeatable merchant flow. It uses a fresh P4 development genesis with the
exact integer capability `invoice_commitment_version: 1`. Existing P1/P2/P3/P4
genesis bytes, plain-transfer behavior, old workspaces, refs and return archives
are preserved. There is no migration, trust renewal, new signer or second funds
journal. The native implementation and selected callers necessarily change;
the historical 445-file immutability qualification is retained, not claimed for
this modified candidate.

The native transfer operation may contain one additional lowercase SHA-256 field,
`invoice_commitment`, only under that capability. Its complete operation remains
inside the original Ed25519 signed body and native transaction identity. Monetary,
nonce, grant, fee, reservation, receipt and ordered execution rules stay intact.
Consensus authenticates an opaque commitment, not an HTTP service or delivery.

The public preimage has exact schema/format, quote digest, separately pinned engine
genesis digest, merchant origin, resource URL and content digest, network, asset,
recipient, atomic amount and exact created/expiry nanoseconds. Its digest is
SHA-256 over domain `1soft/invoice-terms/v1` followed by a NUL and canonical native
JSON. Private invoice plaintext/ciphertext, passwords and private keys are absent.
The new quote profile includes the content digest before its quote digest is
computed, avoiding any circular dependence on payment or receipt identities.

The signing wallet retains the full preimage in a distinct invoice review. It
checks genesis, recipient and amount against native transfer context, and checks
the exact invoice lifetime both before and after vault unlock inside its original
writer transaction. Historical replay checks the original signing time and never
renews a quote or produces another signature. The request book additionally binds
the original quote digest and requested lifetime; the private desk reconstructs
terms from its immutable original quote rather than trusting submitted review
fields. Generic plain requests retain their old behavior.

Merchant enrollment and positive receipt replay reconstruct the same preimage,
require the native commitment for the new profile, and compare the retained public
resource bytes with its digest before delivery. A genuine receipt for another
invoice, altered resource, expiry, amount, recipient, network or genesis is refused.
The permanent finite recipient pool and independently selected payer/wire remain;
this step does not relax merchant-book consumption or add live provisioning.

Acceptance requires real ledger transitions and tampering refusals, an expired
post-unlock approval with no signature/reservation, unchanged old tests/semantics,
source and engine identity before/after, and an actual four-validator invoice
journey with original wallet/delivery journals and cold recovery. Qualification
must list every intentional native/caller/manifest change against a09afbf, retain
all unchanged parent files exactly, and preserve failures. Old immutable-source
qualifiers stay intact and are not relabeled as passing this candidate.

No Actions, paid/public compute, public deployment, DNS/site changes, other
projects, real funds, production keys, force push or remote merge. The ledger and
full receipt history remain public. A digest hides neither low-entropy invoice
terms nor their later disclosed preimage. Trusted-host custody, intact local
journals/clock, bounded histories and original trust policy remain assumptions.
Independent hosts, external audit, production privacy/custody, human acceptance,
customer demand and a value-bearing launch remain unassessed.

## Caller authority and operation

`PrivatePaymentDesk` owns immutable quote-preimage reconstruction for the invoice
CLI. `PlatformService` and the wallet remain generic signing primitives: a direct
caller supplies authoritative public terms and must independently authenticate
its quote. A wallet confirmation alone does not establish merchant authority.
The merchant independently selects original genesis, policy, payer and wire;
HTTP fields never supply those trusted values. Generic capsule verification
proves the native transfer and makes no claim about invoice/resource terms.

Create the capability only through the network CLI's `init --invoice-commitments`
option into a new private directory. It produces workspace/READY schema 3 and
the exact native genesis flag. Default initialization still produces schema 2
without the flag. Neither version accepts a schema/capability mismatch, even if
its file hashes are repinned. The permanent 2–16 recipient pool is unchanged.

Run `tools/private-payments/scripts/qualify_native_invoice.py --engine ENGINE
--output NEW_DIRECTORY` from the repository with its pinned dependencies. The
new `NATIVE_INVOICE_SOURCE.json` records all 491 parent rows, every changed path,
every addition and every current file except its own self-reference. The full
clean Git source identity covers that inventory file too. Historical validators,
manifests and dependency seals retain their original semantics; no 445-file byte
preservation claim is made for this candidate. Component tests are discovered
in isolated interpreters with complete test IDs and no permitted skips. The new
actual journey adds seven checks to the unchanged 37 merchant invariants,
including a genuine same-amount/same-recipient receipt with different terms.
Its run result and source identity, rather than this design document, establish
which gates have passed. All actual validators are local and disposable.
