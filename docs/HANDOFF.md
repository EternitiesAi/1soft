# 1soft continuation — v0.8

Owner target: private `xnuonux/1soft`. No GitHub Actions or self-hosted Actions;
no paid/public compute without authorization. Preserve owner history, original
placeholder, privacy and unrelated repositories. Branding/monetary policy remain
open. Public dollar issuance, cash/cards and real-asset conversion are unbuilt.

Read STATE_WALLET.md and VERIFICATION.md. The original standalone offline signer
remains available; the new state_wallet command integrates signed historical
account evidence with a durable native-payment outbox. This is local development
software, not a running Layer 1 or audited custody product.

53 source files in the complete package; all 449 distinct Python tests passed
across five bounded processes, plus the separate 30-test JS reference. The one-
process full suite was interrupted by tool limits and is not reported passed.
46 state/outbox and 8 terminal/CLI tests are new. The initial SQL placeholder bug
and interrupted logs are retained. No real validator certificate was obtained.

The new native outbox shares local holds across agent grants, prevents competing
same-nonce approvals, binds review to a pinned signed checkpoint and current local
holds, persists signatures before export, and resolves against exact native
receipts or an authenticated height beyond expiry. It does not reserve money on-
chain, coordinate other devices or stop direct key use through another signer.
Its AS-OF authority check does not prove the current latest state. Genesis and
its exact digest are trusted separately. Catch-up requires signed predecessor
links. Restoring an old entire database is outside rollback protection.

Remote publication now includes the independent verifier required by this wallet
subset, not the previously blocked ABCI transport. New code/tests have no ABCI
transport dependency. The full node remains incomplete remotely. Do not use an
alternate channel, renamed copy or encoded archive to evade the earlier transport
upload restriction. Complete local source remains in the conversation package.

The pinned Go engine build still fails at dependency-host DNS before compilation.
No GitHub Actions were used. Do not replace engine consensus with fixture signing.
The next network gate is still real pinned upstream codec + actual validators and
independent receipt validation. For further wallet development, prioritize bounded
authenticated account queries and a safe transport/export boundary; do not deploy
full-state synthetic fixtures or expose an owner's vault password to agents.

Local and remote histories remain distinct. RELEASE.json identifies the exact
commits. Never force-replace main with the complete local bundle. Preserve failed,
unassessed and passed evidence distinctly. Test seeds are public and disposable.
