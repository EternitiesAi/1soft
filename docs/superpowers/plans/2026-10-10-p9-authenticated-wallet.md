# P9 wallet implementation plan

Spec: ../specs/2026-10-10-p9-authenticated-wallet.md

- [ ] Add failing certificate tests for omitted/changed history, checkpoint,
  genesis, wrong header and bounded input. Implement protocol9_certificate.py
  using real P9 Store replay and the existing static-quorum header verifier.
- [ ] Add wallet envelope and one-attempt caller regression tests. Implement
  protocol9_wallet.py with explicit P9 identity, segment selection, verified
  derived indexes, retained original obligations and authenticated reconciliation.
- [ ] Add a protected bounded history exporter and loopback single-send caller.
  Never treat admission or an unsigned transaction query as settlement.
- [ ] Implement scripts/run_protocol9_wallet_engine.py: four actual CometBFT
  validators, native Alice/Bob payment, recipient spend, deliberately lost
  reply, exact reconciliation, authenticated change import, cold reopening,
  tampered history/header refusal, single-send refusal and process cleanup.
- [ ] Commit clean executable source before the native gate. Preserve sanitized
  negative runs, actual runtime identities, source SHA and public receipts.
- [ ] Run focused tests and proportionate repository checks, repair failures,
  freeze source inventory and private delivery. Open and merge the authorized
  private PR via existing supported access; verify exact merged source.

Acceptance: all four journey actions actually run with native proofs and signed
validator headers; adversarial inputs are refused; original send is not retried;
old profiles/stores/evidence remain preserved; claims state the replay limits.
