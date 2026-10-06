# P8 recipient-controlled transfer component

P8 adds a separate native proof relation for a recipient to spend a received
typed note. It does not reinterpret P7 merchant notes, issuer credentials or
recipient disclosure as spending authority. P1–P7 runtime source and historical
profiles remain unchanged. This increment is a native proof and bounded public
state kernel; it has no ABCI, CometBFT, certificate, wallet or custody caller.

## What the proof establishes

The spender supplies the secret for `H(810, secret)`. The input is a typed
domain-811 commitment to network, asset, mission, provenance, expiry, unsigned
64-bit value, recipient key, note secret and blinding. A four-level authenticated
path links that input to a public root. The same circuit derives a domain-814
nullifier from the input and recipient secret, independent of the request or
tree position, and proves `input = payment + change + fee` with unsigned integer
ranges. Payment, change and fee are positive in this finite version.

The payment is addressed to a new recipient key; change retains the spender's
key. Both outputs preserve network, asset and mission and chain an opaque
successor provenance commitment. A positive validity interval ends no later
than payment expiry, and payment expiry cannot exceed the input expiry. Change
inherits input expiry. Nonzero constraints and distinct output commitments are
part of the circuit. Provenance is not an issuer signature or an identity claim.

The isolated profile uses Halo2 0.4.0, Pasta IPA and Poseidon P128Pow5T3, K=13,
13 public fields, 19 witness fields and a 16-note append-only tree. Exact measured
parameter/VK identities and domain assignments are in
[`PROFILE_V1.json`](../tools/recipient-transfer/PROFILE_V1.json). Actual generated
proofs are 3136 bytes; public wires are 3560 bytes. P8 has distinct request and
wire magic and does not parse P7 wires. The profile is developmental and needs
specialist cryptographic review before production selection.

## The state authority boundary

The native verifier takes an externally supplied expected network followed by
one exact wire. Direct library callers must perform the same context gate.
Verification proves the relation, not that a note root is authoritative or that
the nullifier remains unused. The public kernel admits only known typed-note
roots and unused nullifiers/requests, exact asset/mission/fee, a valid caller-
supplied height, distinct fresh outputs and bounded capacity. It replays every
prior receipt from a caller-supplied trusted genesis before admitting a new
transfer. A copied state shape or local state digest cannot authorize a payment.

Genesis admission and height authentication are external assumptions in this
component. Synthetic fixture admission provides them only for its local test.
Neither a standalone proof nor a report can authenticate an issuer, a live
network, finality, a recipient's human identity, or a wallet's possession of its
private opening. The replay checker requires externally supplied genesis and
verifier digest pins; accepting pins copied from an untrusted report creates no
independent trust. Its replay validates public proofs/state, not private custody.

The verifier release must be built with `--no-default-features`; its private
request parser, synthetic fixtures and proving modules are then excluded. The
prover accepts a closed 1160-byte private request on stdin, uses fresh OS entropy
and returns a fixed public wire or a static refusal. Raw requests are not recorded
by the gate. Input buffers are overwritten after use; this is not a promise of
whole-process memory erasure or protection from a hostile host.

## Reproduction and next integration

Build the Rust crate offline/locked with a separate verifier target. Run the
seven relation/request tests and the Python kernel/report boundary tests. Then
run `scripts/run_protocol8_recipient.py --help` with exact prover, synthetic
fixture and verifier binaries plus their measured SHA-256 digests. It requires
a clean checkout and refuses to overwrite an output. The real local flow is
20 -> 12 payment + 7 change + 1 fee, followed by the recipient spending 12 ->
5 payment + 6 change + 1 fee. Public state retains five typed commitments,
two consumed nullifiers and two collected fees. The values and keys in this
example are documented synthetic fixtures, not private funds or provisioning.

`scripts/check_protocol8_recipient_report.py` independently recomputes four
public proof verifications and the two-receipt state history. A separately valid
competing intent for the first input has the same nullifier and a different
request/output pair; both the run and public replay refuse it after that input
is consumed. This tests an actual valid double-spend attempt, rather than
inferring uniqueness from rejection of a tampered proof. Report-schema
tests use explicitly fake proofs; they establish rejection behavior, never
cryptographic verification. Actual execution receipts are registered separately
after the clean-source run.

Next build a separately versioned P8 admission/ABCI bridge and authenticated
full-state evidence, then encrypted recipient note import/preparation/recovery.
Qualify fresh four-validator receive/re-spend, lost returns, double-spends,
restart and state sync before describing P8 as consensus-qualified. P7 owner
allowance and merchant-redemption composition require an explicit relation and
fresh evidence; this circuit does not already provide that composition. Larger
trees, pruning, zero-change spends, note discovery, independent operators,
custody/recovery, economics, external review and public deployment remain gates.

## Registered execution

The [selected clean-source run](../evidence/protocol8-recipient/20261006/recipient-qualified-02.json)
passed24 checks. Its [separate public replay](../evidence/protocol8-recipient/20261006/public-replay-02.log)
recomputed four actual proofs, two accepted receipts and refusal of the valid
competing spend. [Review and reproduction](../evidence/protocol8-recipient/20261006/AI_REVIEW.md)
record the exact scope and remaining gates. These are one-host synthetic native
receipts and do not qualify P8 validator consensus or custody.
