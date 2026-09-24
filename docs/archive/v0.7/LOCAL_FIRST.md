# Local-first development — 1soft v0.7

The owner requested that this project stop relying on GitHub Actions on September 24, 2026. All three workflows on remote main were moved to `docs/archive/github-actions/*.disabled`; the fourth, local-only inherited workflow was also archived in this package. Do not re-enable Actions, register a self-hosted Actions runner, or provision paid compute without explicit authorization.

GitHub stores source. Installed local tools run the builds and tests. No credit card, hosted minutes, background agent, or Actions account is involved. Linux/WSL is the tested environment. Native Windows key-file permissions and Unix-socket operation are not claimed supported.

## Installed-environment commands

Run from the checkout root, using the Python interpreter containing the pinned dependencies:

```sh
python scripts/local_dev.py doctor
python scripts/local_dev.py test --scope core
python scripts/local_dev.py test --scope full
python scripts/local_dev.py network --engine /absolute/path/to/cometbft
```

`doctor` is inspection, not a passing test. `core` runs the native ledger and offline wallet tests only (90 tests at this checkpoint). It checks the six relevant declared source files and explicitly reports whether the complete checkout is incomplete. It does not weaken the separate full inventory. `full` requires all 48 source files and runs the 395-test Python suite. It does not include the separate 30-test JavaScript reference model.

Every execution creates a new timestamped evidence directory under `evidence/local/`, or a new directory given with `--output`. Existing output directories and command logs are refused rather than overwritten. Exit 0 means the selected gate passed, exit 1 means failure, and exit 2 means unassessed prerequisites. The selection is recorded in `result.json`. Test scopes and consensus status remain explicit.

No install happens automatically. When dependencies are absent, an explicitly networked preparation on a machine with ordinary network access is:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python scripts/local_dev.py build-engine --allow-downloads
```

This builds the existing pinned CometBFT 0.38.25, not a new or rebranded consensus implementation. It reuses Go's dependency/build cache and stores the binary under `bin/`. The build command alone never marks native consensus verified. The exact executable hash is recorded; a hash is not publisher authentication. Use a trusted toolchain and review upstream provenance/dependencies before deployment.

`network` never silently substitutes a mock engine or installs one. It requires complete source, the official upstream codec probe, then both protocol-1 and protocol-2 real-network runners. Go lookups default to offline cached operation (`GOPROXY=off`, checksum lookup disabled, direct VCS disabled, local toolchain). `--allow-downloads` explicitly permits missing Go dependencies to be fetched; it does not allow paid resources or public deployment. The network gate accepts only consistent nonempty passing check reports and zero-return-code steps. Child process groups are terminated on timeout.

## This environment's actual result

The 395 Python tests and 30 separate JavaScript tests ran locally. The 39-check and 65-check scripted application-process exercises also passed. Those processes were not validators voting on blocks.

The explicit local engine-build attempt failed before compilation at Go module-host DNS lookup. The cache-only official-codec probe was unassessed because its dependencies are not cached. The network command returned unassessed, with no mock fallback and no live engine checks. Removing Actions does not manufacture a consensus result.

The earlier platform-blocked ABCI upload remains unresolved. The remote repository's new wallet and local-development tools do not encode, reroute, or replace that blocked file. The full application remains in the conversation archive; remote publication is still partial. No customer funds, bank/card program, public node, or live cryptocurrency conversion was created.
