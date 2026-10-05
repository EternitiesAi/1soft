# Encrypted restricted-change custody review and scope

Executed source: 829c2bc80219a9f1191061775ade3e9362a3e9a4.

The fresh CometBFT0.38.25 four-validator run passes all24 checks. It certifies a
synthetic supplied-opening payment, imports its actual restricted CHANGE,
reopens encrypted custody, certifies an unrelated grant revoke, and re-spends
the imported note with the new owner sequence through the real protected-stdin
custody command. Cold command recovery returns the same exact retained wire.
Both payment acknowledgements are deliberately discarded after actual accepted
RPC returns. Exact next-header quorum certificates resolve the obligations.
The next CHANGE is imported; a spent-nullifier refusal and own-grant revocation
refusal use exact causal guard messages. Revocation causes zero prover calls
and unchanged vault bytes. Forged certificates preserve custody; all four
validators agree and a same-store validator restart converges. Owned workers
are stopped.

The strict checker independently replays source and binary identities, raw
artifacts, process lifecycles, actual caller responses, public origin/nullifier
bindings, proofs, all four certificates and final state transitions. It checks
the canonical encrypted envelope/pins without a key; it does not independently
decrypt ciphertext or attest private input use. All12 early receipt tamper
subcases pass before cryptographic replay. Actual-origin vault10 tests,
caller/touched-storage6 tests, native note2 tests and existing prover2 tests
pass with zero skips. Explicit journal/state/OS fault doubles are labeled;
actual process interruption and child exit are exercised. Raw logs are here.

Two read-only AI peers reviewed the controller process boundary, vault/journal
authority, immutable staged requests, unknown-outcome cleanup and strict gate.
Their final review found no concrete blocker in this bounded implementation.
This is AI peer review, not an external cryptographic or custody audit.

An initial Rust test borrow error was repaired. The first actual24-check receipt
is retained privately but withheld as final qualification: generic exception
assertions could conflate conservation failure with grant refusal and duplicate
staging with spent-input refusal. Exact guards and actual caller/process bindings
were added, then the fresh clean unchanged run02 and strict replay passed.

Boundary: one trusted POSIX host, external caller-held key, finite synthetic
development funds, frozen P7 profile and verifier-only consensus bridge.
No private opening/key/request or standalone private-witness hash is exported.
No production privacy, hostile-host sandbox, secure erasure, key recovery,
rollback/latestness detector, cross-device fencing, merchant redemption,
recipient discovery, automatic retry, public deployment or real-funds claim.
Public inventory is immutable history, not spendable balance. P7's16-note tree
with3 initial notes permits at most6 payments. Old encrypted copies can lose
history; restore safety remains unqualified.

Raw evidence has scoped -text attributes to preserve hashed emitted bytes.
Source/documentation whitespace checks are separate from raw engine output.
