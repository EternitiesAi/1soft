# 1soft — native cryptocurrency development

1soft is a native-coin development project for people and persistent agents. This
branch combines the v0.16 node source with the private repository's earlier
attested-state wallet. **There is no public or production network, real-fund service, dollar
backing, bank account, issued card, or audited wallet.** Public economics and
licensing remain open.

## What the code does

The application implements native transfers, agent grants, account opening and key
rotation, protocol-3 shared budgets, receipt records, and optional compact state
proofs. CometBFT v0.38.25 is the pinned consensus engine; the Python application
speaks its ABCI protocol. The v0.16 admission cache is bound to exact transaction
bytes and a committed checkpoint. Proposal and finalization still execute the
transactions against ordered native state.

The remote repository's earlier attested-state wallet and outbox are retained. That
outbox supports protocol 1/2 only: protocol-3 shared budget reservations are not
coordinated by it, so it refuses a protocol-3 genesis. The source package's
`certified_wallet` remains a separate development path. **Do not run both signing
journals against the same funds.** Choosing one canonical signing and reservation
path is an unresolved integration task. See [source reconciliation](docs/SOURCE_RECONCILIATION.md).

## Verification boundary

The integrated checkout verifies 102 required files. On Ubuntu 26.04 under WSL2,
CometBFT v0.38.25 built from its pinned Go module, the upstream Go/Python wire
probe passed all nine checks, the integrated suite passed 919/919 Python tests
with zero skips and 30/30 JavaScript tests, and the four actual local
four-validator scenarios passed 22, 39, 32, and 37 checks respectively. The
saved signed commitments and native transaction receipts were reverified against
the public genesis for each scenario. These are one-host development validators,
not independent operators or a production security audit. See [source
reconciliation](docs/SOURCE_RECONCILIATION.md) for the exact integration boundary.
The current raw logs and results are in the accompanying Codex handoff ZIP.

On a trusted local Linux/WSL host with the pinned Python dependencies installed:

```sh
python scripts/verify_checkout.py
python scripts/run_tests.py
python scripts/check_upstream_wire.py --output NEW_OUTPUT.json
python scripts/local_dev.py network --engine PATH_TO_COMETBFT --output NEW_DIRECTORY
```

The network gate must run the real engine and all four scenarios; fixture
certificates and scripted application calls are not substitutes. The local runner
uses disposable validator keys and loopback listeners only. Do not use its public
test seeds for funds.

No GitHub Actions, public RPC, hosted compute, or production keys are used here.
The static website is separate. Read [node admission](docs/NODE_ADMISSION.md),
[wallet scope](docs/STATE_WALLET.md), [verification](docs/VERIFICATION.md), and
[reuse notice](NOTICE.md) before extending or reusing this code.
