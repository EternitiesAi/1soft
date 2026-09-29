# P4 recovery: source and executed evidence

29 September 2026. The source basis is PR #28 b73a88ca53666972ae2c8ce35fd9edb7ac0cb41c.
No prior PR's reported engine run is counted as execution of this extension.

## Reconstructed source, not an unseen ZIP

The newest Windows-only P4 return was not attached. Two Library searches did not
find it. Its supplied dd61d65f... checksum and raw reports therefore have NOT been
independently checked here. PR28's source and metadata were directly read instead.

The prior registry package was restored at cfa762ef51a0f6ba3806166549b7b1cc91610cc8.
All changed native files were reconciled to the published P4 blobs. The complete
29-file native `src` tree reproduces 7eca75793b8f083216fdfa4a64102c0555713357 exactly.
The newly published P4 core fixture and negative tests match Git blobs
0ba01c1721a96b4dd9f50de4fda2540b4b8ead54 and
f5c0b8d25c974b98b81eef139a5c98892cdb3942. The shared validator-set compatibility
import matches 99a269911bf421170363a6c0cd3698789039f1a1.

The complete PR28 repository was NOT reconstructed. The dependency slice includes
exact runtime bytes and selected unchanged helpers, not all P4 runners, manifests
or documentation. Testing that slice cannot establish a full-source release pass.
Published parent files remain unchanged by this add-on.

## Final completed runs

- New component: 69/69 distinct tests, zero skips/errors/failures.
- Selected existing native, budgets, account lifecycle and P4 core/refusal:
  137/137 distinct tests, zero skips/errors/failures.
- Separate JavaScript reference: 30/30, no skipped/cancelled/todo cases.
- Unique Python total across the two completed profiles: 206.
- Nine new code/test files and 43 exact dependencies rechecked before/after.

The original 1,622-case P4 release profile was not run. The original P4 Go oracle
was not rerun. No new CometBFT process, changing-validator network or engine
bootstrap was executed; the pinned executable is absent from this runtime.
The first completed 39-case run and intermediate 62-case run are earlier subsets,
not additional cases. Expanded tests passed at 69 and are repeated by the final
manifest-checking command. No failing completed new suite is hidden in that count.

## Actual local process demonstrations

Seven demonstrations execute ordinary P4 component paths with synthetic committee
headers. Four kill actual application processes before Commit reply: heights1
(scheduling/payment),4(emission),6(activation),7(post-turnover payment). All reopen
the same database, recover the exact response, and reach height10 with the same
state as uninterrupted execution, two monetary receipts and registry epoch1.

Three more restore format2 at heights2(queued),4(emitted),6(active), through actual
private ABCI sockets. The paused installed checkpoint has no local blocks. Later
execution reaches height10 and preserves both receipts while earlier `/block/H`
queries remain unavailable. Marker removal after ordinary P4 execution is expected,
not relabelled as a loss of the earlier snapshot observation. All outputs identify
synthetic signatures and consensus_executed=false.

The report checker also has a complete synthetic bootstrap example with a third
payment that occurs after the installed snapshot. Those signatures and process
metadata are expressly unit fixtures, not evidence of a real six-node run.

## Controlled weaker-code tests

Four disposable mutations produced assertion failures in their named negative
controls: ignoring the external initial-header pin, omitting exact signed payment
binding, allowing Python boolean/integer equivalence in the checkpoint observation,
and accepting duplicate update-emission heights. They are not an independent
security audit or reproduction of an exploit against any third party. Production
and pinned dependency files were not changed for these checks.

## Upstream basis and explicit scope

CometBFT v0.38.25 consensus/replay.go, lines360–470, contains the handshaker branch
where application Commit succeeded but engine state was not saved. It reconstructs
engine state using the saved FinalizeBlock response rather than requiring native
payment execution again. That is why this new gate checks preserved results and
subsequent state, not an invented second native execution:
https://github.com/cometbft/cometbft/blob/v0.38.25/consensus/replay.go

PR28 docs/PROTOCOL4_DEVELOPMENT.md supplies the composite snapshot and old-client
boundaries. The new runner uses full sequential signed headers and native replay
only as bounded local acceptance evidence, not as a released dynamic wallet client.
No public network, production service, custody, price/reserve/bank claim, Actions,
paid compute, deployment, DNS/site work, Resident/Luna/Psyche work, merge, force-push
or real-funds qualification was performed.
