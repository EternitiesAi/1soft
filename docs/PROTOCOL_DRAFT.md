# Executable semantics / v0.5 laboratory

This package contains a signed native-asset state machine, block-processing/ABCI adapter, independent static-genesis receipt verifier and a separate payment journal. The actual consensus engine has not run; it is not yet a demonstrated working Layer 1. All demonstration keys and balances are disposable fixtures.

## Genesis-pinned native versions

Genesis may specify integer `protocol_version` 1 or 2. Omission means 1. Protocol 1 preserves the prior semantics and global grant IDs. Protocol 2 requires a fresh genesis and adds account lifecycle operations plus owner-scoped grant IDs. Genesis is hash-bound in transactions and AppHash; changing it invalidates existing state. There is no migration or live upgrade mechanism. The highest supported implementation version is 2, while `Info` reports the selected genesis version.

## Native transition envelope

A body binds version, chain ID, genesis hash, sender, nonce, optional grant ID, expiry height, maximum fee and an exact operation. Ed25519 signs the domain-separated canonical body. Accepted bodies use exact fields and integer amounts; booleans, fractions, negative quantities, duplicate wire keys and nonfinite JSON are rejected in the relevant validation paths.

The domain is `ETERNITIES/NATIVE-LAB/v1` followed by a zero byte. Addresses are development-only hashes of public keys. This encoding is not a selected public-address format or a formally standardized canonical serialization.

Both versions support `transfer`, `grant`, `revoke` and `fence`. Protocol 2 additionally supports `open_account` and `rotate_key`. Transfers reach existing accounts; those may be genesis allocations or accounts opened by protocol 2. Grant recipients must be explicit and nonempty. Spending plus fees cannot exceed a grant's cap. Grants cannot administer the account, open accounts or rotate keys. An owner epoch change invalidates older grants.

`open_account` moves a positive allocation plus fee from a sponsor and requires the incoming key to sign the exact scoped intention before the sponsor signs it. `rotate_key` requires old and new keys, preserves the original account ID and increasing nonce, increments the epoch and retains grant/receipt history. It is not lost-key recovery. `ACCOUNT_LIFECYCLE.md` defines the extra domain-separated signature, field sets, version boundary and scope restrictions.

Protocol-2 labels are stored under the owner account; protocol 1 keeps its original global IDs. A label cannot be silently reused to reset spending. Distinct grants still have separate caps. Exact accepted envelopes remain idempotent in the standalone offline ledger after signature verification, even after key retirement; this returns history rather than new authority. The chain-facing wrapper rejects such replays; a different envelope using an already-spent nonce fails.

All accepted operations charge the genesis-defined test fee. Rejected transitions roll back without charging fees. A production mempool would require an independent admission/anti-abuse design; this fixture does not model public spam resistance.

SQLite `BEGIN IMMEDIATE` serializes writers on one database. State updates, nonce changes, fees and receipts commit together. The standalone supplied height is trusted test input. The block adapter uses the height delivered over its privileged engine interface, but actual engine integration remains unassessed. A public caller must not choose execution height or access ABCI.

## Native invariants

Total native balances, including the fee collector, equal the genesis supply. No accepted balance is negative. Every grant's spent amount remains within its cap. Accepted new spending uses the correct nonce and signature. Recipient restrictions, revocation and epochs are enforced inside the transition boundary, not by interpreting a model's prose.

Receipts contain signed envelopes, ordered hash links and the post-transition state hash. Local verification checks these links, payload signatures and final state consistency. Anyone controlling the process/database and signing environment can compromise the system; a hash chain is not an external witness, consensus or proof of bank reserves. Full historical authority validation requires replay against the trusted genesis, not merely checking each signature in isolation.

Separate owner grants currently have separate caps; there is no single parent policy budget across distinct grants. The owner balance is shared. The prior JavaScript budget-tree reference and this native core have not been composed into one security boundary.

## Settlement journal

Assets have explicit identifiers and fixed integer scales. Events create balanced postings per asset. USD units cannot compensate for a BTC shortage. Available and held accounts may not become negative; designated counteraccounts represent fixture funding, settled amounts or liability exceptions.

`fixture_credit` is expressly test-only. It neither verifies a bank deposit nor creates legitimate redemption backing. Do not expose it as a mint or deposit endpoint.

A reservation binds owner, asset, units, payment route, beneficiary and provider. Reusing an ID with different details fails. Dispatch leaves the funds held. An uncertain result stays held across restart. Explicit fixture evidence may settle or release it; timeouts alone do not release it. A final aggregate settlement below the hold releases the difference. Excess or late settlement is recorded as a liability exception and freezes new reservations for that owner until an as-yet-unimplemented resolution process addresses it.

Refunds are idempotent, cannot exceed capture, and return the settlement asset. Exception debts need an explicit waterfall; the fixture deliberately does not apply a simplistic refund path to them. There is no multiple-capture, chargeback, incremental authorization, FX, bridge, bank statement or processor integration.

Journal callers are trusted test operators. Provider names are strings, not authentication. A production adapter must verify the provider's evidence and bind transaction identity, amounts, currency, status and provenance. This interface must not be handed to an untrusted agent or public HTTP caller.

## Critical integration gap

The native core and settlement journal use separate databases and have no atomic bridge between them. They are two executable specifications, not one end-to-end payment system. The web interface displays a captured local fixture and performs only in-memory UI simulations. It does not submit transactions to either model.

## Still required

Demonstrated consensus/peer networking; validator lifecycle and network economics; production onboarding around the tested account-creation primitive; secure owner-key recovery; protected signer and trusted consent; full agent identity/migration; authenticated connectors; cross-route authority accounting; reserve-backed issuance/redemption; DDoS protection; rollback/state-sync/upgrade handling; external custody; independent security review; and live operating procedures.
