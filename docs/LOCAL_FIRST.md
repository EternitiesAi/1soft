# Local-first development — v0.8

No GitHub Actions. The workflows remain archived outside .github/workflows.
Do not register self-hosted Actions, provision paid compute, or publish a network
without explicit approval. GitHub stores source; installed Linux/WSL tools run
local tests and preserve ordinary evidence files. No automatic package installs.

```sh
python scripts/local_dev.py doctor
python scripts/local_dev.py test --scope core
python scripts/local_dev.py test --scope full
python scripts/local_dev.py network --engine /absolute/path/to/cometbft
```

The existing core scope is 90 native/offline-signer tests. Full verification
requires all 53 source files and therefore rejects the incomplete remote node
checkout. The complete archive contains 449 discovered Python cases; they passed
in five bounded processes. A single-process full-gate pass is not claimed here.
The separate JavaScript reference contains 30 cases and remains unintegrated.

The newly published attested-wallet subset has no ABCI transport dependency:

```sh
PYTHONPATH=src python -m unittest discover -s tests -p 'test_*wallet*.py' -v
python scripts/state_wallet.py --help
```

That subset has 54 cases, included within 449, not additional. See STATE_WALLET.md
for separately pinned genesis, signed-state import, prepare/sign/pending/export,
local age/continuity policy, and limitations. Its commands make no network calls.

Engine installation requires an explicit local command and permitted downloads:

```sh
python scripts/local_dev.py build-engine --allow-downloads
```

This only builds the pinned CometBFT 0.38.25; it never marks consensus verified.
Network verification uses the official codec probe and both actual-validator
runners, not a fixture replacement. In this runtime the build still fails at
module-host DNS before compilation. No paid runner or alternate blocked-upload
path was used. Keep failed and unassessed results distinct from passing tests.
