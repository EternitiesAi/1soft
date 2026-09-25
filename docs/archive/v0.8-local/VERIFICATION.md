# v0.8 verification — certificate-backed review and signing journal

September 24, 2026. All executed work was local. No GitHub Actions, public network, paid infrastructure, or real funds were used.

| Gate | Observed result | Scope |
|---|---|---|
| Inherited v0.7 archive inventory | 261 entries matched | Before edits. |
| Inherited Python suite | 395 passed | Rerun before new code. |
| New certified-wallet tests | 47 passed | Synthetic signed snapshots, actual cryptographic operations and local execution. |
| Complete Python suite | 442 passed; zero skips/errors/failures | 395 inherited + 47 new, not separate additive runs. |
| Required source inventory | 52/52 matched | Complete local source, not remote completeness. |
| JavaScript budget reference | 30 passed | Still separate from native accounting. |
| Targeted mutation checks | 5/5 detected by assertion failures | Deliberately weakened temporary copies, not production faults or audit. |
| Real terminal signing/export | Passed in the 47-test suite | Password not echoed; signature accepted on unchanged local snapshot. |
| Abrupt process termination after signing commit | Passed in the 47-test suite | Recorded signature reopened and exported; local journal only. |
| Official engine/network execution | Unassessed; zero steps | Engine absent; module-host DNS unavailable. |
| GitHub publication | Not performed | Current connector exposes reads, no create/update actions; local CLI absent. |

`evidence/v08/full-python.txt`, `javascript.tap`, `certified-expanded-tests.txt` and `regressions/result.json` capture current results. The first certified-wallet run had 38 tests, then nine additional adversarial/terminal cases were added before the 47-test run. No failing initial development test result is claimed for that sequence. Five mutation logs deliberately contain expected test failures.

`network-access.txt` captures failed DNS resolution of the normal Go module endpoint. `network-attempt/result.json` records a complete source check followed by an unassessed engine gate with no executed engine steps. The upstream release lookup for v0.38.25 listed no binary assets. No unsupported binary URL, Actions job or substitute consensus engine was used.

The inherited standalone scripted 39/65-process exercises and older certificate mutation sweeps were not rerun as standalone commands in this checkpoint. Their unit-test coverage is part of the complete suite. Prior files preserve their original evidence scope.

Remote `xnuonux/1soft` was read at `1259377651b0fe4fd4077b600640f4ec58d9ab14`. Its original content and archived Actions were not changed. Discovery of `create_tree` and `create` returned no actions; full discovery showed read-only operations. The plugin-directory search surfaced the already installed GitHub hybrid connector but no usable write action. `gh` was not installed locally. This is a current-tool limitation, not a diagnosis of the user's GitHub account permissions. The older ABCI upload restriction was not retried or bypassed.

## Important interpretation

The result is authenticated authority at a specified snapshot, NOT guaranteed current authority. The new review explicitly reports `latest_state_guaranteed: false`. The journal only coordinates signers sharing the same local journal and trust policy; it is not a global spending lock or bank ledger. Test certificates are synthetic and fixed-validator-only. No validator consensus, production key custody, public dollar backing, deposit account, card or multi-asset settlement has been established.

The complete archive and local Git history include the code. No new local commit is represented as remote main. Packaging checks, archive digest and final local head are recorded in RELEASE.json and the companion release-check file once packaging finishes. Re-extraction/retesting verifies delivery, not additional unique tests or a security audit.
