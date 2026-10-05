# Hidden shared allowance proof milestone

The [private authority proof lab](../tools/private-authority-proof-lab/README.md)
now proves a fee-inclusive allowance transition with actual Halo2 proofs. Five
proofs exercise two orderings of overlapping grants, refresh to the exact remaining
parent allowance, and ordered revocation with a surviving grant. Eight Rust tests
and four adversarial receipt-parser tests qualify this narrow local experiment.

Caps, counters, selected recipient and payment amount are private witnesses. Both
old and exact successor commitments bind the same immutable policy. Counter/range,
forged successor, expired window, stale context, replay, duplicate identity,
malformed proof and public-binding changes are refused. Profile fingerprints and
exact source/report/log identities are frozen in the component receipt.

Current authority is selected by one trusted local coordinator outside the circuit.
The experiment has no value-note, wallet, merchant, monetary or consensus caller.
Its context update does not execute a payment. Enrollment and revocation do not
yet have owner signatures, current-state certificates or durable recovery. Stable
IDs, fees and time windows remain public; no anonymity, relationship-graph privacy,
metadata resistance, production security/custody, real funds or economic value is
established. The AI review is not an independent cryptographic/security audit.

The next milestone must atomically compose this relation with a conserved value-note
spend and validator-authenticated current authority, then retain its exact unresolved
transaction through the existing wallet/delivery journals. That is the integration
required for a usable private mission treasury; it has not been implemented by this lab.
