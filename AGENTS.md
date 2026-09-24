# 1soft engineering contract

Dom selected the private `xnuonux/1soft` repository for the independent native Layer 1 and persistent-agent financial-account project. Preserve the original `1soft` placeholder, private visibility, owner history and unrelated repositories. Check current refs and parallel work before writing. Branding and public monetary policy are not finalized.

Read `docs/HANDOFF.md`, `docs/LOCAL_FIRST.md`, `docs/OFFLINE_WALLET.md` and `docs/VERIFICATION.md` first. `docs/IMPORT_STATUS.md` records the historical v0.6 import interruption.

## Owner's local-first instruction

No GitHub Actions. All active workflows are archived. Do not re-enable them, register self-hosted Actions, or provision paid compute without explicit authorization. Use `scripts/local_dev.py` and keep ordinary timestamped evidence files. Dependencies are installed only by explicit commands; network verification defaults to cached Go dependencies.

## Scope and evidence

- No customer funds, production keys, public issuance, bank/card deployment or real-asset trading in this development lane.
- Keep protocol 1 and explicit fresh-genesis protocol 2 distinct. Never silently rewrite existing genesis, account history, counters or permissions.
- Verify required source. The complete local package has 48 required source files and 395 Python tests. The GitHub node import remains partial; never call it complete.
- Core mode deliberately exercises only the 90 native/wallet tests. It must remain labelled as a subset and must not weaken the full manifest gate.
- Preserve passing, failed and unassessed results separately. Scripted ABCI requests, local database replay and synthetic certificates are not validator consensus.
- No workaround may encode, split or reroute the previously platform-blocked ABCI upload. New offline wallet/local-runner files are distinct work, not a replacement for that transport.
- No mock-consensus fallback. The real upstream codec and four-validator protocol-1/protocol-2 runners must actually execute before the consensus milestone passes.
- Preserve historical evidence and attribution. No new open-source license has been selected.
- Offline wallet review does not prove current authority, nonce, balances or settlement. The confirmation digest is not human authentication. The development vault is not an audited custody product or hostile-OS protection.

The complete local Git history and smaller remote history are distinct. Never force-replace remote main with the local bundle. After real consensus passes, prioritize authenticated state, bounded resource use, protected signing and operator security. Native grants, the settlement journal and the JS budget reference do not yet share one cross-route budget. Native key rotation cannot cancel external card authorizations.
