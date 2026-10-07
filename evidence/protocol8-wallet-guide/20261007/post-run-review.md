# Actual guide evidence review

Read-only authority and native-evidence peers inspected guide-01.json at clean
executed source 29d8fbf3b571bdbbd60b4de86f02e0adc994b57a and current closed,
tamper, replay, execution inventory and phase measurement logs. Neither found a
concrete authority, linkage or preservation discrepancy in the checked outputs.

Each of ten guide calls has exactly one protected inventory child, unchanged
wallet/configuration/journal/private-output bytes and unchanged payment request
counts. Authenticated inventory internally executes native verification; the
guide is read-only with no payment/protocol effect, not free of native work.
Guide display omits recipient key; retained child inventory evidence includes
public recipient key and opaque note/transaction metadata. Checked receipts keep
private openings/intent/path contents absent. This is not general privacy proof.

All 56 guide, 75 journey, 54 console and 30 payment altered-receipt cases were
refused. Separate replay verified five proofs and three signed AS-OF states with
40 native calls reaped. Execution counted 5701 unique native records reaped and
2471 mirrored records deduplicated; replay counted separately.

The profiled protected inventory took18.594 seconds on this host. The Worker
constructor/KAT/identity phase took17.848 seconds; binary open/hash aggregated
0.036 seconds over48 calls. Cumulative phases overlap, profiler overhead is
unassessed, and no cache/lifetime optimization or speed improvement is claimed.
One trusted host and synthetic funds remain the qualification scope. These
reviews are not external certification of custody/privacy, operators or launch.
