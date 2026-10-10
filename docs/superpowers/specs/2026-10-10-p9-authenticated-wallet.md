# P9 authenticated wallet and uncertain-payment recovery

Dom approved the actual P9 journey: Alice pays Bob, Bob spends the received
funds, a lost response is recovered, and both encrypted wallets reopen correctly.
Standing private integration and merge authorization applies. No Actions, paid
compute, public service, deployment, DNS changes, real funds, production keys,
other-project work, force-push, or migration of previous wallets/stores.

P9 consensus remains unchanged. Its running history digest cannot authenticate
an isolated receipt or segment query. A new bounded history packet contains the
external full genesis, complete sequential transactions, checkpoint and AppHash.
A client validates the static quorum's next header and natively replays every
attempt, including refused attempts, to derive all notes, segment anchors,
nullifiers, intents and exact receipts. No server-provided index is trusted.

The wallet uses a separate P9 envelope and bootstrap. Private openings, original
proof requests, exact public wires, attempt markers and signed AS-OF observations
remain in one AES256-GCM blob in an owner-only POSIX directory. It selects the
input's actual segment, including an older segment. Native proof construction
remains the frozen recipient relation. No P8 height, note or receipt limit is
presented as a P9 consensus limit; explicit client capacities remain finite.

Observations must extend the wallet's authenticated history prefix. A process
may memoize verification of exact packet/header bytes; a reopened process
replays its retained observations with the pinned native worker. Receipt
reconciliation binds exact bytes, transaction ID, full genesis and signed state.
An uncertain send retains its input and intent forever unless exact execution
is authenticated; there is no retry, release, automatic re-proving or discovery.

Limits: full-history replay is linear and bounded, not a compact witness or
pruning mechanism. Signed state is AS-OF, not freshness. One owner/host, external
keys, local rollback and hostile host outside qualification. Synthetic native
four-validator qualification is not independent operation, production custody,
an external security audit, economic policy, or public launch readiness.
