# Execute the P4 recovery acceptance extension

> Original 29 September handoff record. For the reviewed combined candidate and
> subsequent engine execution, see [P4 recovery integration](../../docs/P4_RECOVERY_INTEGRATION.md).

Use exact PR #28 parent b73a88ca53666972ae2c8ce35fd9edb7ac0cb41c, tree
123e5bfc57d42ee31736969f61aa5a6d32482832, plus this additive component. Do not combine
parallel proposals or replace existing runtime files with the package's dependency
slice. The slice is only an offline test convenience, not a release checkout.

First run the component verifier, its selected inherited regressions, and the
existing full `tools/release/check_release.py` profile from one clean full source.
Run the original P4 full-response oracle with its supplied vectors as required by
the original b73a88c handoff. Do not interpret the earlier 1,622/30/27 counts as
qualification of this new source tree.

The original P4 engine runner still uses:

```sh
python scripts/run_protocol4_engine.py --engine /trusted/cometbft \
  --engine-sha256 EXPECTED_SHA256 --output ../new-existing-p4/result.json
```

Then execute both new profiles documented in README.md. Require the supplied
CometBFT v0.38.25 binary hash to match before execution. The earlier reported hash
was 218628da07bed5d27e178d38d0bef9ecf46f21b214c8e9fea402fd215fccc024; rehash the
actual local binary. Missing engine is unassessed, never a substitute executable.

The new bootstrap gate must really use a fresh sixth engine/application, validate
format-2 state sync after turnover, retain no invented historical blocks, and
execute a post-snapshot payment. The commit-reply gate must observe the exact
application SIGKILL after a durable emission, then restart the same database and
engine home. Do not require CometBFT to reexecute a successfully committed native
block: its pinned handshaker can recover engine state using the saved finalization
response. Require exact state, receipt, response, epoch and subsequent-progress
agreement instead.

Both result reports retain the re-executable history and dynamically signed H+1
anchor. Reject absent or altered wires, insufficient signatures, missing ancestry,
changed administrative authorization, boolean numeric stand-ins, altered saved
responses, duplicate emission, reset databases and reused observations. Keep actual
failed reports/logs before making the smallest repair. New source repairs require
new identity, refreshed source inventory and another complete relevant run.

Do not weaken or remove P1-P3/legacy rejection tests. Do not turn this acceptance
witness into a wallet path, renew trust automatically, or authorize a deployment.
Return exact source/parent/tree, all commands and result counts, original raw
failure history, sanitized final logs, both profile reports, and CODEX_RESULT.
No production keys, private fixture keys, node homes or live databases belong in
the return. No Actions, paid compute, DNS/site changes, real funds, merges or
force-pushes. Use an ordinary new draft branch for publication.
