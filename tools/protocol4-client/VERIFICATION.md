# P4 read client — verification scope

29 September 2026. Base is draft PR #28 at
`b73a88ca53666972ae2c8ce35fd9edb7ac0cb41c`, tree
`123e5bfc57d42ee31736969f61aa5a6d32482832`.

## Exact source used

The working environment contained the previously supplied PR #26 source package,
not the new Windows-only P4 return ZIP. PR #28 metadata, source, changed paths and
its complete native runtime tree were read through the GitHub connector. The
runtime was reconstructed to all 29 exact published blobs and reproduced its
whole `src` Git tree `7eca75793b8f083216fdfa4a64102c0555713357`. The existing
requirements file, unchanged low-level validator_witness.py and its PR28 wrapper
also match their published blobs. DEPENDENCIES.json records these 32 dependencies.

The rest of that working checkout is NOT represented as a complete PR28 clone.
The current P4 runner, latest added P4 tests, full root inventory and other PR27/28
non-runtime changes were not all installed or run. This is therefore an ADD-ON
package for the actual published PR28, not a complete cryptocurrency source ZIP.
No old or missing test file was removed to manufacture a full-release pass.

Existing regression files were unchanged between the exact PR26 base and PR28,
as established by the complete commit comparison. Their bytes were checked against
that original baseline. The read client changes no parent source; its patch only
adds the previously absent tools/protocol4-client directory. PR24/25 and earlier
parallel drafts are not merged or treated as dependencies.

## Completed tests

- New client suite: 97 distinct tests, zero skips, failures, errors, expected
  failures or unexpected successes. There are 45 evidence tests, 33 read-store
  tests, 11 RPC-worker tests and eight command-line tests.
- Existing certified-wallet, obligation and budget regressions: 114 passed.
- Existing static certificate, compact-state and local-history regressions:
  154 passed.
- Total: 365 distinct Python cases in these completed, separately scoped runs.
- Separate JavaScript reference: 30 passed; no skipped, cancelled or todo cases.

All 11 executable/test files and the 32 pinned runtime dependencies match before
and after the complete client run. The full 1,622-case PR28 local release profile
was NOT rerun. The selected inherited cases do not replace it. No new official-Go
oracle or CometBFT validator run occurred.

The suite tests signed handovers including complete roster replacement, exact
transaction inclusion, composite-state replay, administrative authorization,
original receipt identity, false balances, forged and insufficient signatures,
wrong external pins, missing history, unknown formats, integer/boolean boundaries,
fixed trust expiry, stale-tip conflicts, private storage, corrupted persisted
records and failures before commit. Public account/receipt functions require
original evidence; an arbitrary display dictionary cannot bypass verification.

Local process tests actually exit before and after SQLite commit, reopen the
store, and verify respectively the old or new complete tip. Two actual concurrent
writers cannot both advance the same reviewed tip. A caller mutating its source
object after verification cannot change the frozen bytes that get stored. Expiry
is checked again after old evidence revalidation, including a no-op import.

The RPC tests launch actual loopback HTTP fixture servers and a separate Python
worker with its PYTHONPATH cleared. They exercise fixed-H+1 retries, one captured
state, failed reads, wrong/stale tips, endpoint rejection, stale snapshots and
reopening across handovers. Fixture servers return synthetic signed headers over
actual P4 native application execution. They do not establish a new live P4
validator-network result.

## Demonstration

The source application executes P4 budget/grant/payment and signed administrative
transactions. The client imports state3 (queued), state5 (emitted), state8 (epoch1)
and state16 (epoch2), reopening the store each time. The second change replaces
the entire validator roster. The final recorded owner balance is874 DEV atomic
units; shared-budget spending remains100; six native receipts and conserved
supply1000 are verified. Four selected payment wires at heights1,2,7,15 retain exact
receipts. A later payment queried at state3 is unavailable, not proof of absence.

Headers use deterministic public fixture validator keys. The example is not a
claim that AI agents executed jobs, independent hosts voted, or value was sent.
The original native application is closed before subsequent read verification.
No private-key files or node/wallet databases are shipped in the demonstration.

## Weakened controls and initial failures

Four disposable weakened source copies were each detected by assertion failures:
ignored external anchor hash, ignored fixed expiry, ignored complete parent block
identity, and ignored reviewed-tip comparison. These are author-controlled checks,
not an independent adversarial/security audit. Their logs and selected tests are
retained separately and are not included in the passing-case count.

The initial 44-case client run exposed an implementation mistake in an added
height-one check: the existing block-ID decoder was called without allow_empty,
so valid genesis headers were refused. It was corrected to use the decoder's
explicit empty-parent mode; the empty-parent condition remains enforced.
A later newly added negative fixture attempted to sign a header that the existing
header-hash helper already refuses. The test was corrected to submit the malformed
header directly and require rejection. Both initial logs are retained and excluded
from the final passing totals; no verification condition was weakened.

## What is inherited, not independently rerun

PR28's published description corroborates the reported 1,622 Python/30JS checks,
four official-Go vectors and 27 actual one-host engine checks on b73a88c. The new
handoff ZIP with expected SHA256
`dd61d65ff01a2f036ccadd65b4bd2507ac6f4ebebc8b501257c28341dd98426c`
was not attached or located in Library. Its raw reports, negative gates in
CODEX_RESULT and archive hash were NOT independently reviewed here. Earlier attached
ZIPs are not substitutes for that exact return. No test result from PR28 is
relabeled as execution of this new client.

## Publication and remaining qualification

The client is completed and tested locally. This turn's GitHub discovery exposed
read actions but no source-write action; no new remote branch/PR or merge was made.
The portable patch has only additive paths for PR28. Its full source-file digest
inventory and a fresh-extraction check are provided with the package.

Actual P4 engine collection/restart needs its own acceptance run. P4 state-sync
bootstrap and final-Commit reply-crash still need actual-engine qualification.
No signing wallet, reservation migration, public explorer, new receipt-archive
adapter, policy renewal, independent operator/security/custody/economic or
value-bearing readiness is implied. No Actions, paid compute, deployment, DNS/site,
Resident/Luna/Psyche work, production keys, real funds, force-push or merge occurred.
