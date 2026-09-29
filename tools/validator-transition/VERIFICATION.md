# Validator-transition foundation — verification scope

28 September 2026. Parent: PR #23 at
289a78056b86ebdd5878d285027f5c78562e0767, tree
bf08af8edd487750ea3476181e96d119febd239c.

## Exact incoming source/evidence

The uploaded state-sync recovery return matches SHA-256
67d00bc558eb5c6503ee45ebff73a01e3085d5aed3375f1ee894b025ba1c6c53.
All 882 listed payload entries matched; all 278 source files and their executable
modes reproduced the published tree. The parent commit object also matches its
published SHA. Earlier ancestry is explicitly shallow, not invented.

The saved nine-network and six-fault reports passed their exact parent report
validators again: 410 and 111 observed checks respectively. Saved local reports
reconcile to 1,423 distinct successful IDs within their isolated groups; all four
archived receipt capsules reverified. These are OFFLINE checks, not another engine
execution, a rehash of an unprovided binary, or independent security review.

## New tests

The new component suite contains 82 distinct cases: canonical sets, integer and
size bounds, deterministic deltas, 200 seeded randomized delta applications,
addition/removal/reweighting/full replacement, two sequential handovers, external
anchor pins, unchanged legacy rejection, all signature slots including nil/absent
votes, strict supermajority, full block IDs, next-set authority, version/time
bounds, fixed expiry, unchanged earlier proofs, capacity limits, timeline audit,
and actual file/CLI reopen. The full local release checker includes this separate
suite; consult the delivered exact-commit result for the completed integrated run,
not totals accumulated from previous revisions.

Four disposable weakened versions produced assertion failures: accepting exactly
two-thirds, omitting the prior-header next-set requirement, allowing expiry, and
activating one block early. The unannounced-roster test preserves every other
signature and block-ID link, specifically isolating the handover requirement.
The optional verifier checks 13 component source/test/probe files and 26 unchanged
parent dependencies before and after execution. Complete Git checks cover docs too.

## Demonstration and limits

A non-authorizing draft emitted at H=3 is followed through next-set announcement
at H=4, proof-file reopening, activation H=5 and the H+3 timeline. Another test
follows a second change at H=9. New header signatures are synthetic fixtures from
public deterministic keys; AppHashes are unexecuted fixture commitments. No new
native transfer, governance action or changing-validator engine runs are claimed.
The existing node, wallet, archive and explorer implementations are unchanged.

The witness grants no native-state, balance, wallet or governance authorization.
Trust is evaluated at the explicitly supplied clock, which remains an operator
assumption. A later financial action would need separately reviewed versioned
wallet integration and action-time freshness checks. The foundation is not imported
by any existing production node or wallet path.

## Initial failures and upstream compatibility

The first development run attempted to deepcopy a cryptography key in a test-only
fixture. The test was corrected; no production check was weakened. A later real-
clock CLI regression showed that the demo's synthetic evaluation clock was one
minute ahead, so the saved witness was correctly refused on immediate reopen. The
fixture now uses the current truncated second. Both red logs remain in evidence.

The official-Go probe is pinned to CometBFT v0.38.25 and compares multi-validator
hashes, delta application and FinalizeBlock update bytes. It was attempted with
GOPROXY=off: the module was absent from the local cache, so execution is UNASSESSED.
gofmt is not a compile or compatibility pass. Older wire tests do not substitute
for this probe. No new real-engine result is attributed to the candidate.

Native authorization/registry/activation/migration, changing-validator state sync,
wallet adapters, skipping light verification, independent operators, malicious
quorum/host/clock and power loss, external review, production custody, economics,
public deployment and real funds remain unassessed. No Actions, paid compute,
DNS/site, Resident/Luna work, force-push or merge occurred.
