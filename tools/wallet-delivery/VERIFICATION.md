# Decision-delivery verification — 2026-09-27

## Source

Work continues the supplied complete local transfer package, archive SHA-256
`a91f238422e89d6fc1d8df10bcf5b4390488d3c0b265882a7fbe621cfabf5148`,
commit `1299b1d6d3a0ceaa2d6365f0f4987a59bfc3a2e4`, tree
`c5e6afbccf2db7f3775f3c4840a7323e9cbed309`. All 240 archive entries and the
restored 214-file source matched before edits. The live GitHub read confirmed
PR #10 remains at `631dcc309c01ea5d183c90d5983e45063695e12a` and other observed
branches were unchanged. The older transfer upload is not retried or republished.

Every new source change is under `tools/wallet-delivery`. It depends only on the
published PR #10 account/native core, not the unpublished transfer or catch-up
modules. The complete delivery ZIP also preserves the local transfer workflow;
that full tree is deliberately distinct from a delivery-only publication on PR10.
Native/signing/reservation, existing account/transfer, RPC and validator code is
unchanged. No dependency was upgraded and no active Actions workflow was added.

## Executed development checks

The final new adapter suite passes 49 distinct cases with zero skips, errors or
failures. Completed bounded-process reports reconcile the exact IDs once. Earlier
46-case passes precede three additional safeguards/cases and are not extra tests.
The 93 inherited account/transfer cases pass separately. The 114 inherited
certificate-wallet/pending-obligation/budget cases also pass separately. The
separate JavaScript budget reference passes 30 cases. These totals are different
scopes; no new full 971/1062-case core-suite run or real-validator run is claimed.

New tests exercise original decision selection, exact bytes, explicit payer and
grant, no owner fallback, changed inventory/checkpoint, a different dispatch path,
new confirmation per replay/attempt, expired policy, stale state at submission,
revoked grants, original signature corruption, dispatch schema/configuration,
concurrent senders, a real process exit after attempt commit, and output privacy.

The HTTP fixture runs the real local native application, with internally linked
SYNTHETIC committee headers. One test executes the signed payment and actually
closes the socket before replying. Subsequent reads verify its exact receipt with
one broadcast total. This is a TCP loss in a local fixture, not a claimed repeat
of Codex's real-validator client-boundary-loss test. Both kinds of prior evidence
retain their own scope. No production key, customer payment or actual value is used.

Receipt collection leaves the wallet's pending hold unchanged. The explicit
reconciliation path delegates to the unchanged wallet. Missing ancestry preserves
both proof and hold. Known optional header progress defers to catch-up rather than
letting older wallet code ignore it. Successful two-agent reconciliation consumes
100 native units including fees, with pending 100 -> 40 -> 0 and budget spending
0 -> 60 -> 100. The original signatures remain unchanged throughout.

The CLI is exercised as actual subprocesses with freshly timestamped fixture
headers, not by disabling production freshness. Endpoint admission returns a
non-final status. A repeated first-send command is refused; receipt refresh never
resends. Proof export is private and refuses overwrite. The new code has no
vault/password options or signing primitive.

## Incomplete runs and limits

The initial single-call inherited account/transfer suite reached the tool deadline
without a completed report. That log is retained and excluded; all 93 cases were
then run in four completed groups. Two larger delivery command groups also reached
tool deadlines. Their partial logs are retained; smaller completed selections and
exact ID coverage provide the final result. A completed report from a group whose
outer combined invocation timed out was rerun and is counted only once.

No blocked source request has been encoded, renamed or sent through an alternate
write route. Publication outcome and exact final trees are recorded in the package
identity after the ordinary new-add-on write attempt. Source/ZIP hashes establish
byte identity, not an independent audit or software-authorship authentication.

This is a trusted local POSIX workspace with pinned static validators and complete
unpruned receipts. It does not coordinate devices or separate dispatcher databases,
provide transactional atomicity across wallet and network, prove latest state,
prevent direct use of already-exported signatures, or establish production custody.
The existing actual-validator findings are inherited for their exact older source,
not new consensus evidence for this adapter. No paid compute, public deployment,
Actions, DNS/site change, Resident/Luna work, force push or merge is part of this lane.
