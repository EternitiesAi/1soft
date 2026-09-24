# Local-first development

The owner requested that this project stop relying on GitHub Actions on September 24, 2026. All three workflow files present on main were moved out of `.github/workflows` into `docs/archive/github-actions` with `.disabled` extensions. They cannot trigger from this checkout. Do not re-enable Actions, register a self-hosted Actions runner, or provision paid compute without explicit authorization.

GitHub remains the source repository. Build and test execution belongs on a local Linux/WSL machine or an explicitly authorized development environment. Save command results and source hashes as ordinary evidence files, not hosted Actions jobs. Preserve failing and unassessed results separately from passes.

The current remote source import remains partial; the complete v0.6 archive is in the conversation. The prior platform-blocked ABCI upload is not bypassed by this change. The new local development additions will be documented separately. Actual CometBFT network verification is still required before describing this as a running Layer 1.
