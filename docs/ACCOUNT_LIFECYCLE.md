# Native account lifecycle — protocol 2

24 September 2026 · v0.5 development · original application code

## Product purpose

A payment network cannot onboard new users if all payable accounts must be written into the original genesis. A persistent-agent account also needs a way to change its controlling key without changing its history or accidentally retaining old delegated authority.

This release supplies two signed native state transitions for those needs. It does not prove that the network exists, that an agent is conscious, or that a signing key belongs to a legally identified person. The account's stable identifier is a ledger identity, not proof of a persistent mind.

## Explicit version boundary

Protocol 1 is the inherited model. Omitting `protocol_version` means 1; explicitly setting it to integer 1 is also supported but produces a different genesis digest from omission. Existing genesis documents are never rewritten.

Protocol 2 requires a **fresh genesis** containing `"protocol_version": 2`. The chain identifier is limited to 50 characters for the intended engine. Only integer versions 1 and 2 are accepted. Boolean, fractional, unknown and string versions fail.

The entire genesis is already in the transaction and application commitments. A signed protocol-1 transaction cannot execute on protocol 2. Existing state cannot be reopened under a changed genesis. There is no live migration, upgrade height, conversion of old grant rows, or governance-driven version switch in this release.

The outer signing domain intentionally remains `ETERNITIES/NATIVE-LAB/v1` followed by one zero byte. The exact transaction body contains the native execution version and genesis hash; changing either invalidates its signature. The `/v1` domain is an envelope-format identifier, not permission to bypass genesis semantics.

## Two-sided key acceptance

Both new operations require an incoming key's Ed25519 signature. It is domain-separated as `ETERNITIES/ACCOUNT-KEY-CONSENT/v2` followed by one zero byte.

The signed payload is the exact canonical body, including chain, genesis digest, payer/current owner, nonce, operation, funding where present, blank grant identifier, expiry height and maximum fee. Only the operation's `acceptance` field is removed to avoid signing a signature recursively. The current owner or sponsor then signs the complete body including that acceptance signature.

A reusable proof of key possession is not sufficient. Acceptance cannot be moved to another sponsor, funding amount, key, nonce, fee cap, expiry or network. Its signature demonstrates cryptographic consent by a key, **not proof that a human saw or understood a screen**.

`accept_account_key` is a development helper. It verifies the private key matches the proposed incoming public key, returns a copied body and does not sign for the sponsor. The independent receipt verifier reconstructs the payload separately rather than importing this helper.

## `open_account`

The exact operation fields are:

```json
{"type":"open_account","public_key":"<32-byte lowercase hex>","units":100000,"acceptance":"<64-byte lowercase hex signature>"}
```

The sponsor is the envelope sender. It must have enough funds for the positive integer allocation plus the genesis-defined fee. The incoming key signs its scoped acceptance; the sponsor signs the resulting body with its current root key and unused nonce.

The new account ID is derived from the initial public key using the existing development address function. Its initial balance is the supplied allocation; root nonce and authority epoch start at zero. The account ID must not exist, and the incoming root key must not currently control another account.

Creation, sponsor debit, fee credit, nonce advancement and receipt are atomic. It moves existing supply; it does not mint. There is no implicit airdrop, account deletion, rent, faucet endpoint or regulated dollar backing. A duplicate operation is rejected by the chain-facing wrapper; an alternate transaction cannot recreate an existing account.

A recipient can subsequently send and receive normally. During ordered block execution, opening can precede a new account's transaction in the same block. Mempool admission against the previous committed state can still reject the dependent transaction; clients should wait for commitment before relying on independent admission.

## `rotate_key`

The exact operation fields are:

```json
{"type":"rotate_key","public_key":"<new 32-byte lowercase hex>","acceptance":"<64-byte lowercase hex signature>"}
```

The present owner signs using its current root key and next root nonce. The incoming key signs the same bounded intention. It must differ from the current key and must not currently control another account.

Rotation preserves the original account ID, historical receipts, grant records and balance except for the fee. The root nonce increases normally; it is never reset. The authority epoch increases, making all of that account's previous native grants inactive. Their historical spent amounts and labels remain recorded rather than being cleared or replenished.

New direct transactions must use the new key. New agent authority requires a separate, explicitly signed grant under the new epoch. Incoming transfers still use the account's **original ID**; deriving a destination from the replacement key would identify a different prospective account.

This is **not lost-key recovery**. The old key is required. It provides no recovery from loss of that key and no safety guarantee when the old key has been compromised. There is no delayed guardian veto, trusted hardware signing, emergency recovery service or key-destruction proof. Active-root-key uniqueness is checked; there is no permanent registry forbidding every historical key from future reuse.

Rotation affects native permissions only. It cannot cancel an external card authorization, undo a settled payment or revoke a credential at an unrelated service. The separate settlement journal still needs an explicit cross-system authority/reconciliation design.

## Owner-scoped agent grants

Protocol 1 retains its global grant label for historical replay. Protocol 2 stores a label under `owner_account_id + "::" + local_label`. Owner IDs have a fixed address shape; lookups, creation and revocation consistently use the actual sender's scope.

Two owners may both use `raven`. One cannot revoke the other's grant through that label. Reusing an existing label under the same owner fails, including after revocation or rotation. This avoids resetting a spent cap by silently replacing a row. A separately named new grant is a new owner-authorized allowance.

The native owner balance is shared, and each grant has its own inclusive-fee spending cap and nonce. There is **not** yet a single parent budget across separately named grants, a hierarchy of subdelegation, or a common budget across native transfers, cards and x402. Grant labels do not establish real-world agent identity.

## Commit and interruption behavior

`CheckTx` and proposal construction use isolated copies. Pending accounts and replacement keys are not visible through committed queries. Native changes become durable with the block height, application hash and execution records in the same commit transaction.

A process killed before commit returns with the prior key and state; replay produces the same staged hash. A process killed after commit returns with the new key, preserved ID and old grants inactive. The included four-process exercise tests these cases using scripted engine requests, **not validator consensus**.

An already-executed offline envelope can still return its historical idempotent receipt after its signer is retired. That is not renewed spending authority. The chain-facing wrapper rejects already-executed transaction IDs.

## Evidence

`tests/test_account_lifecycle.py` contains 63 tests, `tests/test_lifecycle_blocks.py` 12, `tests/test_lifecycle_signatures.py` 15, and the new runner-plan class five: 95 new tests overall. `scripts/check_account_processes.py` records 65 checks over four actual application processes and 11 accepted native operations. `scripts/check_lifecycle_certificates.py` tests six CLI cases using explicitly synthetic validator signatures.

Seven deliberate code changes test whether omitted acceptance, missing epoch invalidation, nonce reset, unscoped labels, ignored genesis version, duplicate active root keys, and bypassed verifier acceptance are detected. They are fault-injection sensitivity checks, not seven newly discovered security exploits or an audit.

The real-engine runner is extended for both versions, but no actual-engine onboarding, key rotation, quorum test or live certificate has yet been observed. See `VERIFICATION.md`.

## Before production

Design the trusted wallet/signer interface, account ownership and recovery policy, address format, transaction costs and account-growth limits. Replace full-state cloning and linear key lookups with a bounded, authenticated design. Review metadata privacy: the sponsor, funding and rotation linkage are visible in this ledger. Add independent review and actual engine tests. Do not submit real money or production keys to these primitives.
