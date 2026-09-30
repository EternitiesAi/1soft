# Private invoices and native merchant payments

This additive development slice connects a private invoice to the existing 1soft
P4 wallet, real native execution, a portable receipt and a durable local merchant
result. It preserves the complete d14165d parent, including its financial journal
and protocol rules. The parent README describes the earlier platform; this record
is the entry point for the new slice.

**Invoice content is encrypted at rest. The blockchain is still transparent.**
Description, contact and negotiated content use a dedicated password-protected
data vault and AES-256-GCM with genesis/request-bound associated data. Recipient,
amount, merchant URL, public quote, exact wire and receipt evidence remain public.
The current portable capsule discloses full ledger history, including unrelated
activity. This is not a shielded payment, anonymous network or production custody
system. Passwords and decryption keys transiently exist in a trusted local process;
there is no memory-erasure or hostile-OS protection claim.

## Delivered path and its authorities

1. An operator independently pins merchant origin, exact resource URL, native
   network/asset, genesis, recipient and amount. The quote cannot choose these
   trust inputs. The experimental x402-v2 scheme is `1soft-p4`, with grammar-valid
   but unregistered `1soft:<label>` identifiers and valueless `1soft:DEV` units.
2. Import checks those pins and encrypts the private content before retaining an
   unsigned canonical request. It creates no financial reservation, signature,
   dispatch or authority to spend. A failed second-store append can be completed
   by the same live import without changing the original ciphertext; the two
   stores are not an atomic transaction.
3. The private caller presents a native review and a separate merchant-terms
   review. Approval requires both explicit digests and the existing payment vault
   unlock. Signing and the fee-inclusive hold remain in the sole existing P4
   wallet. Generic parent callers retain their original behavior; this new caller
   does not rewrite their consent rules.
4. The wallet permits one existing submission attempt. Admission is not execution
   proof. Uncertainty retains the original wire and financial obligation; there is
   no resend, reset, rearm or automatic trust renewal.
5. The independently configured merchant retains a unique recipient for one quote
   and explicitly enrolls the original payer/wire using verified P4 evidence. An
   incoming wrapper cannot supply that trust or a signing key. The native transfer
   signature does **not** authenticate the quote/resource digest. Unique recipient
   assignment and the intact shared merchant book are therefore necessary here.
   The local network currently preallocates one merchant recipient. A second quote
   for that address is refused even after fulfillment. Fresh native recipient
   provisioning and a signed quote/resource commitment require separate versioned
   native work; this fixture is not a general recurring-billing service.
6. A merchant verifies the complete portable native receipt before atomically
   retaining consumption of that native identity and the exact immutable public
   resource. Each identical repeat replays the proof before returning the saved
   bytes and original fulfillment timestamp. A changed proof/result is refused.
   The fixture has no external side-effect callback. Separate/copied books do not
   coordinate claims, and database commit plus HTTP return is not atomic.
7. Merchant HTTP success, capsule retention and invoice decryption do not retire
   the wallet hold. Only explicit native reconciliation with the expected wallet
   revision does that.

The bounded merchant HTTP fixture binds literal `127.0.0.1`, requires an
independently supplied session token, and exposes only its fixed public resource.
It serves no signing, dispatch, enrollment or token-discovery endpoint. Tokens are
local fixture access control, not production customer identity or payment proof.
The CLI supplies useful wallet/invoice operations without launching or retrying
engines. See [the command guide](X402_NATIVE_DEVELOPMENT.md) and
[package entry point](../tools/private-payments/README.md).

## Reproduce the local evidence

Use the same private POSIX Python environment and locally built CometBFT 0.38.25
described in [the developer release](LOCAL_DEVELOPER_RELEASE.md). The engine's
required SHA256 is
`218628da07bed5d27e178d38d0bef9ecf46f21b214c8e9fea402fd215fccc024`.
No downloads, provider calls, GitHub Actions, paid compute or public network are
part of qualification. All output/runtime directories must be new, private and
outside the checkout. Existing workspaces are never overwritten or reset.

```sh
python -B tools/private-payments/scripts/qualify_private.py \
  --engine /absolute/path/to/pinned/cometbft \
  --output /absolute/private/new-qualification-directory
```

The wrapper checks every tracked source byte and mode, all 445 parent files, the
new package manifest, the installed dependency pins and the observed engine hash.
It calls the unchanged complete local release qualification, then the new private
component suite and genuine four-validator private-payment journey. Reports bind
the same commit/tree/source digest and run ID before and after execution. Missing,
partial, failed, dirty or mismatched results cannot qualify the candidate.

The new actual journey uses one 12-unit payment plus its 2-unit fee. It exercises
real P4 execution and signature replay; deliberate *local observation loss* after
one real RPC call; real client abandonment of a merchant HTTP return; durable
fulfillment replay; cold restart of all four validators; exact recovery of data
vault/ciphertext/original request/wire/decisions/attempt/receipts; and reconciliation.
The final fixture has owner 980, merchant 12 and fees 8 out of a conserved 1,000
native development units. No real funds are involved. Four local validators are
not four independent operators.

```sh
python -B tools/private-payments/scripts/run_private.py \
  --engine /absolute/path/to/pinned/cometbft \
  --output /absolute/private/new-actual-directory
```

`--exploratory` permits a development snapshot and labels it unqualified. Its
passing result cannot substitute for clean-source release qualification. The
result contains exact named checks, public wire/capsule/state artifacts and
sanitized raw app/engine logs. It omits passwords, session tokens, vaults, databases
and plaintext invoice content. Failed execution keeps its actual negative result.

## Next engineering gates

[The privacy successor design](PRIVATE_PAYMENTS_ARCHITECTURE.md) specifies private
notes/nullifiers/proofs, conservation, shared-capability budget fragments,
revocation, disclosure, custody and versioned migration. These ledger mechanisms
are **unimplemented**. This foundation does not qualify a privacy marketing claim,
mainnet launch, stablecoin integration, audit or investment return.

Before a value-bearing public release, remaining gates include independent security
and operator review, private-ledger implementation/proof audits, hardware-backed
custody and recoverability, coordination across devices/copied journals, durable
incremental proofs beyond the current 64-block collection window, trust renewal
and historical verification beyond the one-hour interval, interrupted initialization,
human browser/mobile acceptance, public genesis/economics and actual customer
evidence. Public deployment and economic issuance remain outside this slice.

Existing parent restrictions remain in force: no public/paid compute or deployment,
DNS/site edits, real funds/production keys, other-project work, force push, remote
merge, automated financial retries or weakened checks. Reuse provenance is recorded
in the protocol guide; no acquired SDK was installed or executed.
