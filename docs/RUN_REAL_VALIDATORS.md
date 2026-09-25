# Real validator acceptance — ordinary local execution

Codex is not a technical dependency. Any authorized Linux/WSL environment with
the pinned dependencies and engine can run this suite.

Use the **complete 1soft v0.15 archive**, not the currently partial GitHub node
checkout. This is the same engine gate that remains unexecuted in the chat runtime.
A domain or working website is not a blockchain network. No GitHub Actions are
needed. Use only a trusted Linux/WSL development environment and disposable state.

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python scripts/verify_checkout.py
.venv/bin/python scripts/check_index.py --application
.venv/bin/python scripts/local_dev.py build-engine --allow-downloads
.venv/bin/python scripts/local_dev.py network --engine "$PWD/bin/cometbft" --allow-downloads
```

These are commands to execute, not evidence that they have already passed. The
build targets pinned CometBFT 0.38.25 and preserves upstream provenance rather
than inventing a replacement engine. Inspect the result JSON and all individual
checks. Build success alone is not consensus. The network gate must exercise the
upstream codec, real four-validator native transfers, quorum interruption/recovery,
account opening/rotation, shared budgets and opt-in SMT queries. No mainnet,
public endpoint, customer keys, funded account or paid host is needed for the
local acceptance suite. Do not bind public DNS or deploy a validator to the website.

Keep raw failed results. If dependencies or engine startup fail, report their
actual error; do not reduce the tests or substitute a Python fixture. New evidence
must identify the exact source commit, environment and pinned engine binary hash.
The owner has already directed this lane to work locally, without Actions.
