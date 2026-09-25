# Local-first development — v0.12

No GitHub Actions or hosted-runner minutes. No self-hosted Actions, paid compute,
public endpoints or DNS changes without explicit authorization. GitHub stores
source; installed local tools run tests. Linux/POSIX is the tested environment;
Windows requires its own validation or an appropriate Linux environment.

```sh
python scripts/local_dev.py doctor
python scripts/local_dev.py test --scope core
python scripts/local_dev.py test --scope full
```

`doctor` only inspects the environment. `core` checks seven declared files and
runs the legacy 90 native/offline-wallet tests, not the new budget tests. `full`
requires all 69 declared source files and discovers the complete 623-case Python
suite. Tests needing the rest of the application must fail on an incomplete
checkout rather than claim success. This release ran all cases in sixteen bounded
processes, reconciled by exact unique test IDs; the standalone full runner is not
claimed to have completed in one process here. The JS reference is separate.

For the new native rules and integration specifically:

```sh
PYTHONPATH=src:tests python -m unittest discover -s tests -p test_native_budgets.py -v
PYTHONPATH=src:tests python -m unittest discover -s tests -p test_budget_integration.py -v
node --test reference/kernel.test.mjs
```

Do not mistake these 54 budget cases or the separate 30 JS cases for the full
623-case suite. All are development tests, not independent security review.

Existing commands for explicit preparation and network execution remain:

```sh
python scripts/local_dev.py build-engine --allow-downloads
python scripts/local_dev.py network --engine /absolute/path/to/cometbft
```

The build requires an installed Go toolchain and explicit download permission.
It uses the pinned CometBFT 0.38.25 and the local cache, not Actions. Network mode
requires complete source, official upstream codec compatibility, then genuine
four-validator scenarios for protocol 1, 2 and 3. Each is a fresh disposable chain
on one host, not evidence of independent operators. Missing prerequisites must
remain unassessed; a synthetic fallback is forbidden. Downloads are off by default.

Execution creates a new evidence folder and never overwrites an old one. Review
`result.json`'s scope and detailed checks, not just the exit status. Timeouts stop
child process groups. Private wallet keys, passwords, tokens and customer records
must not be placed in the repository or release evidence.

This environment still has no pinned engine and cannot resolve the normal module
host. The actual network attempt executed zero engine steps. No Cloudflare/domain
change is needed to perform the other local engineering. Domain ownership does
not establish chain execution or access to a production deployment account.

The full local archive and remote main's wallet are different lineages. Publication
is incomplete, with the v0.12 native-core write blocked. Preserve existing refs,
user files and tests; do not reroute blocked content or force-push local history.
See HANDOFF.md and VERIFICATION.md for exact observed refs and evidence.
