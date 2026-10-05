# Atomic private treasury payment component

The separate [treasury payment component](../tools/private-treasury-payment-lab/README.md)
now implements one conserved value-note payment and exact hidden parent/grant
debits in one Halo2 circuit. It is a checker-qualified trusted local execution component, not a validator-integrated protocol or deployed coin.

The relation binds the same amount, recipient, fee and agent across the allowance,
input, merchant output and restricted change. Two independently prepared grants
compete for one current parent fragment. Exact current authority is selected
inside serialized execution; historical note anchors do not provide old authority.
Revocation preserves prior spending and rejects prepared stale proofs. The local
ledger commits all effects and its exact-byte receipt in one FULL-sync SQLite WAL
transaction. A persistent outbox retains unresolved bytes and one-attempt holds.

The gate exercises both race orders, refreshed exact remaining allowance, real
proofs, duplicate request identity, concurrent connections/claims, SQL rollback,
process exit before commit and loss of the caller return after commit. It freezes
proof/profile/source/log/binary identities and refuses altered receipts.

The outbox is deliberately unavailable for retry after an ambiguous claim until
an exact local execution receipt exists. Local absence, expiry, conflict or
revocation cannot clear it. It does not sign, approve, certify state or integrate
the P5 wallet, and the receipt establishes only trusted local execution.

Promotion requires a new fresh-genesis validator protocol enforcing this exact
combined relation/current authority, followed by certified wallet continuity and
merchant disclosure/redemption. Owner enrollment/revocation signatures, private
discovery, scaling, independent review/operation, custody, hostile-host/cross-device
recovery, metadata/relationship privacy, public readiness, real-funds safety and
economic value remain unassessed. Existing P1-P5 and the old authority lab are
preserved byte-for-byte; their historical evidence does not qualify this component.

## Retained exact-source qualification

The implementation source `69f64594d4611e468e17bdbdce2ee1f4499697f5`, tree `18620c8ff56827827ebccb1f7f7dadbd62c19685`, passed ten Rust tests,
fourteen actual-binary ledger/recovery tests and seven real proof generations.
Six additional adversarial receipt-parser tests and the thirty-three existing
checkout-gate tests passed. The combined losing-race/outbox case preserves the
original obligation and refuses a refreshed-proof replacement against its hold.

The [receipt](../evidence/atomic-private-treasury/20261004/treasury-qualified-04.json)
and adjacent sanitized logs pin the actual source, profile and verifier binary.
Verifier SHA256: `7d8fd12f054a87640fa462a5d46ce6df3064c1f2073ec91c9991d398e3786e4b`.
Earlier failed candidates remain external and are summarized in the delivery's
CODEX_RESULT. This receipt supports finite local behavior, not signed publisher
provenance, independent cryptographic review or real consensus.
