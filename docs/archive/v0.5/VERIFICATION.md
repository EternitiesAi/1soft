# v0.5 verification record

24 September 2026. Development evidence, not a security certification.

## Executed in this runtime

| Gate | Observed result | Evidence and scope |
|---|---|---|
| Inherited archive verification | 119 entries matched | `evidence/v05/inherited-manifest-check.txt`; original v0.4 unchanged. |
| Inherited Python baseline | 192 passed | `inherited-python-tests.txt`. |
| Final Python suite | **287 passed, zero failures** | `python-tests.txt`; 192 inherited plus 95 new tests. |
| Separate JavaScript reference | **30 passed** | `js-tests.tap`; unchanged, not connected to native accounts. |
| Four legacy application processes | **39 checks passed** | `abci-processes.json`; scripted ABCI, not consensus. |
| Four lifecycle application processes | **65 checks passed** | `account-processes.json` and node logs; 11 accepted native operations, real process crashes, scripted requests. |
| Legacy certificate CLI | **6 cases passed** | `certificates/checks.json`; synthetic fixture. |
| Lifecycle certificate CLI | **6 cases passed** | `lifecycle-certificates/checks.json`; synthetic onboarding/rotation proofs and rejection cases. |
| Legacy certificate mutation sweep | **1,307 rejected; zero accepted/unexpected errors** | `certificate-mutations.json`; unchanged legacy packet, not comprehensive protocol-2 fuzzing. |
| New code-fault sensitivity | **7 detected** | `v05-regression-sensitivity.json`; altered disposable source copies, exact failures required. |
| Inherited code-fault sensitivity | **10 detected** | `regression-sensitivity.json` (3), `v04-regression-sensitivity.json` (7); not newly discovered flaws. |
| Python syntax, Bash syntax, workflow YAML structure | Passed | `environment.json`; does not establish CI execution or a complete workflow semantic audit. |

The new 95 tests comprise 63 account-lifecycle tests, 12 block-lifecycle tests, 15 independent signature/packet tests and five development-runner-plan tests. Enumerated test subcases are not inflated into additional test counts.

The captured environment used Python 3.13.5, cryptography 46.0.4, protobuf 6.33.6, Node 22.16.0 and Go 1.23.2 on Linux. Versions are recorded in `environment.json`; this is not a multi-platform support certification.

## Baseline and implementation history

The original 192-test suite passed before changes. Three opening/rotation/scope tests initially could not run against protocol 2 because v0.4 correctly rejected that unknown genesis format. `lifecycle-before.txt` preserves those errors. This was a feature gap and an intentional old-version boundary, **not an existing-chain consensus vulnerability**.

After implementation, the first 63 lifecycle tests passed. Expanded suites then recorded 267, 282 and finally 287 passing tests as block, verifier and runner cases were added. Intermediate files preserve those stages; their totals must not be added together.

The new code-fault tests deliberately remove incoming-key verification, epoch advancement, nonce preservation, owner scoping, version binding, active-root-key uniqueness or independent verifier consent checks. All seven altered copies produce test failures and leave original source intact. Passing them establishes sensitivity to those specific changes only.

## What the process exercise establishes

Four local application processes received the same scripted block requests over private Unix sockets. They executed onboarding, identically labelled grants under different owners, bounded agent transfers, root-key rotation, explicit new agent authority and post-rotation transfers. Their committed snapshots and hashes matched.

One process was terminated before committing rotation, restarted with the prior durable key, replayed the staged block and committed the matching state. Another was terminated after commit and recovered the new key and inactive older grants. The exercise also checks supply conservation, nonce/epoch preservation, retained spent caps, receipt verification and rejection of stale authority.

These are actual process crashes but **not CometBFT crashes, validator votes, Byzantine consensus, a network partition, or independently operated nodes**. Four processes controlled by one test runner are not decentralized security participants. Evidence explicitly sets `consensus_engine_running` to false. Disposable private keys are not included in evidence.

## What the certificate exercise establishes

The independent verifier checks signatures and requested transaction IDs for onboarding and rotation recorded by the local application. It independently reconstructs the incoming-key acceptance payload; it does not import the signing helper to perform that check.

The packet uses constructed headers signed by disposable, known fixture validator keys. It is labeled `SYNTHETIC`; no live network produced it. The verifier authenticates a state claim under the pinned static validator assumptions. It does not replay all history, establish human consent, prove key custody or establish engine provenance. Header h+1 remains required for post-state at h.

## Unassessed and not implemented

| Gate | Status | Current reason |
|---|---|---|
| CometBFT v0.38.25 build | Failed dependency retrieval | `comet-build-attempt.txt`; DNS resolution refused. |
| Official Go codec probe | Unassessed; zero comparisons | `upstream-wire.json`; dependency resolution failed. |
| Actual protocol-1 four-validator network | Unassessed; zero checks | `network-v1/devnet.json`; no engine binary. |
| Actual protocol-2 four-validator network | Unassessed; zero checks | `network-v2/devnet.json`; no engine binary. |
| Live onboarding/rotation receipt integration | Unassessed | Runner authored, no actual-engine packet produced. |
| Remote GitHub CI | Not run | Dedicated target read returned 404; no repository created or modified. |
| Public deployment, custody, cash/crypto conversion, cards, reserve backing, independent audit | Not performed | No production keys, customer funds or external financial integration. |

The alternate Firecrawl execution route reported insufficient credits. No purchase or cloud deployment was made. These failures did not weaken the real-network criteria. A successful local fixture cannot turn either engine gate green.

## Compatibility and release boundaries

Protocol 1 remains supported with its original grant-label behavior. Protocol 2 is explicit, fresh-genesis-only and hash-bound. The tests do not establish live chain upgrades, historical migrations, dynamic validators or a changed state-storage format.

The native ledger, settlement journal and JavaScript budget reference remain separate models. The website is unchanged and disconnected. Key rotation is not lost-key recovery; it requires both keys and invalidates native grants only. Full-state cloning, hashing and public metadata are development limits. No throughput or cost target has been measured.

## Reproduction and packaging

Commands are in the README. `bash scripts/verify_network.sh` retains the official-codec gate and runs both actual network versions without a mock fallback when dependencies are available.

The release includes tracked source/evidence, local Git history, `RELEASE.json` and a SHA-256 manifest. The companion `eternities-v0.5-release-check.json` records fresh extraction, file verification, a fresh Python-suite run and history restoration when delivered. Packaging checks do not add another blockchain success or audit claim.
