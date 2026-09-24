# 1soft — native money and persistent-agent accounts

An independent native-coin development project for people and persistent agents.
**Development only: no launched network, dollar backing, bank account, issued card
or audited wallet.** Branding and public monetary policy remain open.

## v0.8: account evidence, signing and continuity

The new offline workflow verifies a signed account-state witness under separately
pinned static validators, prepares a native transfer, obtains encrypted-key
approval and durably records the signed intention before export. It checks
permissions and balances AS OF the certificate height; it does not claim the
latest network balance. It never broadcasts a payment.

A local outbox prevents competing same-nonce signatures and accounts for other
native agent grants' pending debits. A crash or failed file export preserves the
original signature. Exact attested receipts, or verified height beyond expiry,
resolve pending intentions. This is one-workspace accounting, not on-chain locks,
multi-device coordination, or a shared native/card/cash budget.

Read [state-wallet usage and limitations](docs/STATE_WALLET.md),
[verification](docs/VERIFICATION.md), and [handoff](docs/HANDOFF.md).

With the pinned dependencies installed, these new 54 wallet tests are runnable
from the published subset without the missing node transport:

```sh
PYTHONPATH=src python -m unittest discover -s tests -p 'test_*wallet*.py' -v
python scripts/state_wallet.py --help
```

The complete package contains 53 required source files. All 449 discovered Python
cases passed across five bounded local processes, plus 30 separate JavaScript
reference cases. The single-process combined run was interrupted by tool limits;
it is not reported as passed. Synthetic certificates are NOT validator votes.

## Local-first and incomplete-node boundary

No GitHub Actions. Existing workflows remain archived; no paid runner is used.
The prior 90-test core gate and local build/test tools remain available. Full
checkout verification correctly fails on the still-partial remote node import.
The complete development archive and full history are in the project conversation.

The independent receipt verifier is now published for the wallet; the previously
blocked ABCI transport has not been rerouted or replaced. Actual CometBFT consensus
remains unassessed because its local dependency retrieval still fails before
compilation. No mainnet/testnet, issuer agreement, exchange/card integration,
production key custody or independent security review is implied.

Publicly known fixture seeds must never hold real funds. Read NOTICE.md before
reuse; no project-wide open-source license has been selected.
