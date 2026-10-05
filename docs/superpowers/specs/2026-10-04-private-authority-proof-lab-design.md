# Private authority proof laboratory v1

Approved direction: private mission treasuries. This first cryptographic slice is
an offline Halo2 relation experiment, separate from every existing protocol.

The relation proves knowledge of the selected current parent and grant openings,
the agent secret bound by the grant, and one hidden payment amount/recipient. It
binds genesis, asset, mission, fixed policy, current context, request, fee, validity,
exact old/new fragment commitments and nullifiers. Parent and grant successors
retain caps, policy, identity, recipient, expiry and epoch; spending increases by
payment plus fee and versions increase exactly once. All integer counters and
differences are constrained to 64 bits, with positive payment and nonzero secrets
and blindings. Distinct blindings permit successor hiding; randomness quality is
outside this seeded synthetic qualifier.

The twenty ordered public fields are version, genesis, asset, mission, current
context root, parent identity, grant identity, old parent commitment, old grant
commitment, new parent commitment, new grant commitment, parent nullifier, grant
nullifier, payment commitment, authority epoch, valid-from, valid-until, fee,
merchant request commitment, and authorization digest. Stable identities, fees,
epochs and time windows are public. This profile does not claim relationship-graph
privacy, recipient discovery, metadata resistance or production privacy.

Current authority is enforced outside the circuit by one explicitly trusted local
Context. Its exact parent/grant commitments, domain, fee, epoch and current root
must match the public statement at execution. Two proofs against the same old
parent are individually valid; committing either advances the parent and prevents
the other from committing. A stale historical context must never be caller-selected
as current. Root authenticity, distributed consensus, membership proofs and
current-state certificates are not implemented here. The authorization digest is
a binding hash, not an owner signature; agent authority follows knowledge of the
secret committed in the enrolled grant. Enrollment and revocation are trusted
operator seams, and no production owner-key lifecycle is claimed.

Ordered revocation removes the selected enrolled grant commitment and changes the
current root, preserving the parent commitment/counters. This fences all already
prepared statements against the old root; surviving agents must explicitly build
against refreshed context. It does not refill budgets, release local holds or
provide a private revocation proof. No wallet, transport or monetary application
calls this lab. It provides no value-note conservation, executed payment, durable
obligation journal, crash recovery, exactly-once service delivery, independent
review, cross-device coordination, mainnet, real funds or economic value.

Completion: real Halo2 proofs for two overlapping 6-unit fee-inclusive debits of
one parent capped at 10, each grant capped at 8; both ordered races admit at most
one; a revocation between proof generation and commit rejects the stale proof;
public/witness/overflow/cap/successor mutation gates fail; P1-5 protected bytes are
unchanged. Proving and verifying must actually run; MockProver alone is insufficient.

The next consensus successor must atomically compose these authority rules with
the value-note transition, durable wallet obligations and authenticated current
state. Passing this lab cannot be relabeled as that integration.
