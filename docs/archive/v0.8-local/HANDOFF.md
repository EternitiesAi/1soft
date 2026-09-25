# 1soft continuation handoff — v0.8

Owner direction remains local-first: no GitHub Actions, self-hosted Actions runner, paid infrastructure, real funds or public launch in this lane. GitHub is the source store. Branding, public monetary policy, dollar issuance and partner integrations remain unbuilt/open.

Read CERTIFIED_WALLET.md and VERIFICATION.md. The full archive now contains src/certified_wallet.py, scripts/certified_wallet.py, scripts/check_certified_regressions.py and tests/test_certified_wallet.py. It reuses the existing fixed-validator commit verifier, snapshot restore, native ledger and encrypted vault. Existing native monetary rules were not changed.

47 new tests passed; full suite 442, separate JS 30. Five targeted weakened-code variants were detected. The new path is: pinned genesis and expiring policy -> authenticate signed snapshot -> check signer/nonce/balance/grant -> exact review -> encrypted signing -> atomic local decision -> recoverable export. These fixtures are synthetic, not output from actual consensus.

The snapshot height/hash/time is persisted, rejecting older/conflicting observed certificates. Review and sign enforce local time/expiry, rechecking after decryption. Approval locks an authority-nonce slot in one SQLite journal; recovery exports committed public signatures after an output error or abrupt process exit. No global funding reservation, policy-renewal ceremony, peer retrieval, latest-state guarantee, compact proof, changing-validator light client or production custody is delivered.

Do not claim that fresh-looking signatures imply live network provenance. Trust relies on independently chosen genesis/policy, the static validator assumption, a trusted local clock and local filesystem. Do not supply owner's keys to agents. Tests deliberately show a competing later transaction can still make a certified intention stale. Export is not broadcast or settlement verification.

Current remote: xnuonux/1soft main at 1259377651b0fe4fd4077b600640f4ec58d9ab14, unchanged. This turn's GitHub tools expose read operations only; no write endpoint was available after targeted and full discovery. Plugin search found the existing hybrid GitHub connector; local gh was absent. Local development is preserved in the complete archive/history and incremental patch, not claimed pushed. That patch contains only v0.8 changes, not the previously blocked ABCI transport. The remote node import remains partial. Never force-replace the user's remote history with the local bundle.

Engine gate: normal Go-module hostname cannot resolve in the container; pinned CometBFT absent; actual network runner unassessed with zero steps. No synthetic fallback. Prior ABCI publication restriction remains untouched. The next network acceptance result still requires a real supported engine runtime, official upstream codec and both protocol-1/protocol-2 four-validator runs. This checkpoint does not satisfy that gate.

Immediate follow-on engineering: review the new trust/journal threat boundaries; arrange supported publication when write capability is present; execute the actual engine acceptance tests in a network-enabled local environment. Keep unresolved dependencies explicit rather than adding autonomous financial behavior on top of unauthenticated state. No UI or website changes were made in v0.8.
