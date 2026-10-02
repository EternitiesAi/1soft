# Executable semantics / v0.2 laboratory

This is a single-host native-asset state machine and a separate payment journal. It is not a network protocol implementation or a working Layer 1. All keys and balances used by demonstrations are disposable fixtures.

## Native transition envelope

A body binds version, chain ID, genesis hash, sender, nonce, optional grant ID, expiry height, maximum fee and an exact operation. Ed25519 signs the domain-separated canonical body. Accepted bodies use exact fields and integer amounts; booleans, fractions, negative quantities, duplicate wire keys and nonfinite JSON are rejected in the relevant validation paths.

The domain is `ETERNITIES/NATIVE-LAB/v1` followed by a zero byte. Addresses are development-only hashes of public keys. This encoding is not a selected public-address format or a formally standardized canonical serialization.

The model's supported operations are `transfer`, `grant`, `revoke` and `fence`. Transfers only reach known genesis accounts. Grant recipients must be explicit and nonempty; spending plus fees cannot exceed the grant's cap. Grants cannot administer the account. An owner epoch change invalidates older grants. Exact already-accepted envelopes are idempotent after verifying their signature; a different transfer reusing the nonce fails.

All accepted operations charge the genesis-defined test fee. Rejected transitions roll back without charging fees. A production mempool would require an independent admission/anti-abuse design; this fixture does not model public spam resistance.

SQLite `BEGIN IMMEDIATE` serializes writers on one database. State updates, nonce changes, fees and receipts commit together. The supplied height is trusted test input. It must eventually come from the selected consensus/application integration; it is not presently a trusted distributed clock.

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

Consensus and peer networking; validator lifecycle and network economics; post-genesis account creation; secure owner-key recovery; protected signer and trusted consent; full agent identity/migration; authenticated connectors; cross-route authority accounting; reserve-backed issuance/redemption; DDoS protection; rollback/state-sync/upgrade handling; external custody; independent security review; and live operating procedures.
