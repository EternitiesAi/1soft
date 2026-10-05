# Retained private authority progression

prepare_retained_change composes the encrypted CHANGE vault with its canonical
certified journal. The source_txid must identify the exact certified payment
whose public request and full private witness are still retained in encrypted
pending. Its restricted CHANGE must already be imported from that same exact
origin. A supplied-origin first payment without that encrypted preparation is
refused; custody of a note alone cannot invent parent/grant authority.

The method authenticates the source certificate/wire, imported origin, retained
request and current journal. Current parent and selected grant commitments must
equal that source's post-payment commitments. It advances spent by amount plus
fee and version by one, retaining the correct private post-payment blinds and
grant expiry/recipient. Integer bounds are checked. Current generation/key,
epochs, note/root/nullifier, expiry and holds are checked by the ordinary path.
An unrelated owner-sequence change is provenance and does not relabel the note.

Private authority remains in encrypted storage and process memory. The caller
provides source_txid, explicit amount, validity window, request ID and external
key through protected stdin to prepare-retained. It supplies no authority
opening. The CLI uses the same measured prover and conservative unknown-return
diagnostics as prepare. There is no automatic submission, delivery or retry.

Both locks are released before the ordinary preparation path reacquires them.
The derived authority is a one-shot snapshot. An intervening payment or authority
change must fail current live-note/native commitment checks or the final journal
CAS. It is never refreshed to silently accept newer authority. Future openings
are encrypted before proving/retention; cold recovery returns the original wire.

The additive run_protocol7_retained.py gate targets a fresh four-validator trace
with three real payments and CHANGE7 -> CHANGE4 -> CHANGE1. The third prepare and
recovery use the actual retained-authority CLI without caller-supplied private
authority. It must refuse a missing stage, stale source commitments and an
authenticated handoff race before proof/staging with unchanged ciphertext.
Own-grant revocation remains a distinct exact guard. The earlier24-check custody
receipt and recipe remain separate. This new gate is unqualified until its clean
unchanged execution and strict replay are registered.

Same finite one-host/external-key custody limits apply: no independent ciphertext
decryption or private-input attestation, rollback/latestness detection,
cross-device fencing, key recovery, merchant redemption, recipient discovery,
hostile-host protection, production privacy or real funds.
