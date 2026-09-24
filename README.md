# 1soft — native money and persistent-agent accounts

An independent native-coin development project for people and persistent agents.
**Development only: no launched network, dollar backing, bank account, issued card or audited wallet.**

## Current checkpoint: v0.7

GitHub Actions have been retired at the owner's request. GitHub stores the source;
installed local tools execute tests and preserve ordinary evidence files.

New: an encrypted local Ed25519 vault, exact-intention review and offline signing,
plus a local build/test runner with explicit scope and no automatic downloads.
Account opening and key rotation still require separate incoming-key and current
owner/sponsor consent. Nothing is broadcast by the wallet.

```sh
python scripts/local_dev.py doctor
python scripts/local_dev.py test --scope core
```

These commands work with the published native/wallet subset when its declared
files and pinned dependencies are present. Core tests are **90 tests**, not the
complete application. The complete downloadable package has **395 Python tests**
and 48 required source files; it also retains the separate 30-test JS reference.

```sh
python scripts/local_dev.py test --scope full
python scripts/local_dev.py network --engine /absolute/path/to/cometbft
```

Full checks must fail on an incomplete import. Native consensus remains
**unassessed**: the local build still cannot resolve the dependency host. There
is no synthetic-consensus fallback. The prior blocked ABCI upload was not
rerouted, so the remote node import remains partial; the full source package is
in the project conversation. GitHub and complete local source histories differ.

Read [local execution](docs/LOCAL_FIRST.md), [wallet boundaries](docs/OFFLINE_WALLET.md),
[verification](docs/VERIFICATION.md), and [handoff](docs/HANDOFF.md).

The original native code enforces signed transfers, fees, supply conservation,
recipient-constrained grants, revocation and authority epochs. Protocol 2 adds
sponsored account creation and key rotation while preserving account identity.
Public branding, issuance/economics, bank/card/cash integrations and licensing
remain open or unbuilt. Private prompts and agent memories do not belong on a
public ledger. No upstream provider endorsement or proprietary consensus
invention is claimed. Read NOTICE.md before reuse.
