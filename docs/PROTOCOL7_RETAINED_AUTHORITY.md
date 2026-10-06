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
receipt and recipe remain separate. Retained progression is covered by the
[actual combined 36-check v2 receipt](../evidence/protocol7-reconciliation/20261006/reconciliation-qualified-04.json) at clean unchanged source
`c0e0e7b15921a2d6f0723575f33771eaae724ecf`, followed by strict replay.
The standalone 30-check recipe has not separately qualified.

The original cap 8 synthetic grant correctly refuses a ninth allowance unit.
The retained and combined reconciliation recipes use an explicit separate cap 10
fixture for three positive payments plus fees. The old fixture and cap checks
are unchanged; an exact native budget regression is required. The combined
[reconciliation gate](PROTOCOL7_RECONCILIATION.md) covers all30 retained checks
and adds6 snapshot/command checks. A combined receipt does not certify an
unexecuted standalone recipe.

Same finite one-host/external-key custody limits apply: no independent ciphertext
decryption or private-input attestation, rollback/latestness detection,
cross-device fencing, key recovery, merchant redemption, recipient discovery,
hostile-host protection, production privacy or real funds.

## Failed combined attempt and restart repair

The clean combined attempt at `74027d260c7d56e3de2093dc6460b72f288894a4`
is failed, not qualified:33 functional checks plus cleanup/source identity
completed (35 recorded). Replacement app3 startup timed out before the final
engine restart/convergence assertion. [Original evidence](../evidence/protocol7-reconciliation-attempts/20261005/reconciliation-failed-01.json)
is preserved; no strict completed-receipt replay or 16-subcase qualification follows.

The constructor still fully replays the checkpoint and validates its AppHash.
The repaired durable-block audit advances its own valid prefix with _execute
instead of replaying every growing prefix at each height. Every transition/proof,
row/result/request/vote/response check remains, with final reconstructed state
compared to the checkpoint. Readiness limits remain unchanged. The focused
native test passes using actual failed-run public history and explicitly
synthetic SQLite rows, including exact corrupted-response refusal. This is
not a same-store engine restart. Repeated prefix auditing is a likely timeout
cause. The fresh combined 36-check v2 run and strict replay now qualify the
repaired path within the same bounds; the original failed report remains failed.
