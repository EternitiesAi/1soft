# 1soft handoff — v0.7

Owner direction: no GitHub Actions. GitHub is the source store; run installed local tooling. Do not substitute self-hosted Actions, provision paid compute or create public infrastructure without approval. Native independent Layer 1 and agent finance remain the objective; branding/monetary policy remain open.

Read `LOCAL_FIRST.md`, `OFFLINE_WALLET.md` and `VERIFICATION.md`. All three workflows on remote main were archived out of `.github/workflows`. The full package's inherited fourth workflow was also archived. No Actions run was requested in this turn.

New files: `src/offline_signer.py`, `scripts/wallet.py`, `scripts/local_dev.py`, `tests/test_offline_signer.py`, `tests/test_local_dev.py`. The existing `scripts/verify_network.sh` now invokes local gates without automatic package installation. The full required-source inventory now has 48 entries.

395 local Python tests, 30 separate JS tests and the 39/65-check scripted application exercises passed. The terminal signing tests create only disposable keys and sign real native envelopes accepted by the local ledger. These are not validator-network or production-custody results.

The explicit local Go build failed at DNS before compiling; the offline official-codec gate has no cached dependencies. The network command correctly reports unassessed with no mock engine. The installed Go toolchain is 1.23.2. No claim is made that a real CometBFT process ran.

New wallet/library review requires a trusted local genesis and exact public signer, shows all transaction fields, and binds them/role in a confirmation digest. It does not know current authority or nonce. Vaults are encrypted PKCS8 with private POSIX file/dir requirements. No password arguments, environment shortcut, network service or public-key-to-balance magic exists. External cards/payment journals remain separate.

The earlier ABCI upload safety-status block remains unresolved and was not rerouted. New wallet/local-runner source is separate work; remote import remains partial. Keep exact publication/source heads in RELEASE.json and the publication inventory. Do not force-push the full local history over the owner's remote history.

Next substantial result: use a supported network-enabled local runtime or trusted prebuilt pinned engine, execute the official upstream codec and both actual four-validator tests. Do not fabricate that result, rewrite the consensus algorithm, or expand unit counts as a replacement. After consensus passes, integrate authenticated account-state retrieval and protected signing with the interface, and address full-state-snapshot/resource limits before any public testnet.
