# v0.6 verification record

24 September 2026. Repository integration and test-gate checkpoint; no new native
monetary rules, public network, or independent security certification.

## Observed in the full local package

| Gate | Result | Scope |
|---|---|---|
| Inherited v0.5 release inventory | 183 entries matched | Original archive unchanged. |
| Inherited baseline Python tests | 287 passed | Before changing test infrastructure. |
| Final local Python suite | 320 passed; 0 skipped, failures or errors | 287 inherited plus 33 new tests. |
| Required source inventory | 43/43 matched | SHA-256 and byte length checks. |
| Separate JavaScript budget reference | 30 passed | Unchanged; not integrated with native ledger. |
| GitHub core publication | Partial, actual commits | Not the complete full-package checkout. |
| Hosted engine preflight | Startup failure, 0 jobs | No engine build performed. |
| Hosted echo-only diagnostic | Startup failure, 0 jobs | Even its echo step did not run. |
| Official Go codec and real validators | Unassessed | No new engine execution or consensus evidence. |

The 33 new cases are 24 source-inventory cases and nine test-runner cases.
They cover missing/changed files, duplicate/unsafe manifest paths, symbolic links,
nonregular files, empty inventories, missing tests, all-skipped suites, import
errors, child-process source lookup and the correct test working directory.

The first new runner version failed three tests and errored in one because it
failed to propagate the source directory to child processes and did not set the
checkout working directory. The captured failing log is retained. The wiring was
fixed and two explicit regression tests were added before the final 320-test run.
This was an introduced runner defect, not a preexisting consensus vulnerability.

## Evidence location in the complete archive

`evidence/v06/inherited-manifest.txt`, `inherited-python.txt`,
`python-v06.txt` (initial failing runner), `python-v06-fixed.txt` (320 passing),
`js-v06.tap`, and the publication inventory/partial-checkout records.
Old v0.5 documents are preserved under `docs/archive/v0.5/`.
Old evidence retains its original scope and is not counted as newly rerun here.

The independent certificate fixtures, 39/65-check scripted process exercises and
fault-injection sweeps from v0.5 were not rerun as standalone exercises in this
checkpoint. Relevant unit tests are included in the 320-test suite. No live
certificate or network partition/quorum result was obtained.

## Limitations

The source manifest is not signed and does not authenticate its own author. It
checks declared required files, not every extra file or a hostile concurrent
filesystem. It cannot establish code safety, correct economics or consensus.
The full gate deliberately fails on the incomplete remote checkout. The separate
35-test native-only command is useful but must never be presented as 320 tests.

Public issuance, custody, reserves, bank/card integration, conversions, audit,
production signing, dynamic-validator light clients and scalable authenticated
storage remain unimplemented or unassessed. Existing full-state snapshots and
static validator assumptions are development limits. No throughput/cost claim
is made. Source/manifest changes alone cannot turn the real-network gate green.

Packaging verification is recorded in the companion release-check JSON when the
archive is finalized; it does not add another network result or audit claim.
