# Eternities Native Finance — v0.3 development

**An original native-coin application with an ABCI adapter targeting CometBFT v0.38.25. Not a public cryptocurrency, bank, or production wallet.**

The coin remains the primary project. Branding, public supply, security economics and dollar issuance are not decided by the 100 DEV test fixture.

## This release's actual boundary

- The native ledger, block staging, atomic persistence, ABCI message handling and local process recovery were executed and tested.
- **The real CometBFT engine was NOT built or run.** Its dependencies could not be downloaded in the supplied runtime. The independent upstream-Go codec check is also unassessed.
- Four application processes received scripted ABCI messages and converged. They did not vote, gossip blocks, elect proposers or demonstrate consensus.
- No remote GitHub repository was created. No website or network was deployed. No funds or card/bank integrations were used.

See [verification](docs/VERIFICATION.md), [architecture](docs/ABCI_INTEGRATION.md), and [continuation handoff](docs/HANDOFF.md).

## Executed evidence

| Gate | Result | Meaning |
|---|---|---|
| Python tests | 122 passed | Includes the previous 58 tests plus 64 new application/wire/runner tests. |
| Prior JavaScript model | 30 passed | Separate, unchanged budget-tree reference. Not integrated into the native ledger. |
| Four application processes | 39 checks passed | Real Unix sockets/processes, scripted block delivery, crashes, replay and identical roots. NOT validator consensus. |
| Regression sensitivity | 3 deliberate defects detected | Missing receipt state in AppHash, exposing staged state, and non-atomic commit. |
| Official upstream Go codec | Unassessed | Dependency download failed. |
| Four CometBFT validators | Unassessed | Required executable unavailable. Runner fails closed rather than simulating success. |

## Reproduce the local application tests

Python 3.11+ is required for the runner's TOML support; the recorded runtime used Python 3.13.5. The socket server is Linux/WSL-only. The pure ledger/journal tests are not themselves Unix-specific.

```sh
python -m pip install -r requirements.txt
python scripts/run_tests.py
python scripts/check_abci_processes.py
python scripts/check_regressions.py
node --test reference/kernel.test.mjs
```

No real money or credentials are needed. Test keys and units are disposable. The application server's socket directory must be mode 0700; its socket is mode 0600.

## Run the real-network gate on a network-enabled Linux/WSL machine

With Go >= 1.22.11 and Python 3.11+ already installed:

```sh
bash scripts/verify_network.sh
```

This creates a local virtual environment, fetches version-pinned dependencies, checks the actual upstream protobuf codec, builds the pinned engine, and attempts the four-validator gate. It needs outbound package access. It does not provision paid cloud services or publish anything.

The gate generates fresh disposable validator/account keys, binds all listeners to loopback, checks native and delegated transfers, removes validators to exercise quorum loss/restoration, compares applications at a common height, and cleans up its test runtime. These engine checks are **authored but not yet executed successfully**. Dependency versions are pinned, but full offline dependency vendoring, complete dependency hash locking and a reproducible-toolchain audit are not completed.

## Main files

- `src/native_core.py` — previous signed monetary rules, preserved unchanged.
- `src/block_application.py` — isolated proposal checks, pending block state, atomic durable commits, consensus-state hashing.
- `src/abci_wire.py` — a protobuf-runtime-backed subset of the observed upstream ABCI schema.
- `src/abci_server.py` — local private Unix-socket application endpoint.
- `scripts/check_abci_processes.py` — explicitly scripted application-process test.
- `scripts/run_devnet.py` — actual-engine integration gate, with no simulated fallback.
- `tools/upstream-wireprobe/` — source for checking the real upstream codec.
- `.github/workflows/verify.yml` — authored CI gates; not run remotely.
- `web/index.html` — unchanged v0.2 account concept; embedded fixture data, not a connected wallet.
- `evidence/v03/` — current raw test output and explicit unassessed gates.

## Hard limits

The implementation clones and hashes full application snapshots. It is not a throughput-optimized state store and does not provide authenticated query proofs, state-sync snapshots, staking, validator changes, general smart contracts, production signing/recovery, public issuance, cash conversion or dollar redemption. A working local network would still not establish public-network security, decentralization or mainnet readiness.

Earlier product research remains in `docs/`; superseded verification/handoff/roadmap files are archived under `docs/archive/v0.2/`. Do not merge historical evidence with current evidence into one inflated test count.
