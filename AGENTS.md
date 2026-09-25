# 1soft engineering contract — local v0.16 integration

1soft is the native cryptocurrency lane. Preserve the private owner's Git history,
the original placeholder, parallel payment and Resident branches, and the remote
wallet lineage. No Actions, paid/public compute, public deployment, DNS/site,
Resident/Luna/Psyche, real funds, issuer/bank/card, production keys or force-pushes.

Read docs/SOURCE_RECONCILIATION.md, docs/HANDOFF.md, docs/NODE_ADMISSION.md,
docs/STATE_WALLET.md and docs/VERIFICATION.md. The integrated local checkout has
102 manifest-required files. A source inventory pass is not consensus validation.
Keep historical, local-current, synthetic, and actual-engine claims distinct.

The node's CheckTx cache binds exact signed bytes to committed genesis/height/hash;
proposal and finalization still execute ordered native transactions. Preserve
protocol-1/2/3 and smt-v1 bytes. Private Unix channels must be capped before
thread creation; never weaken transport limits to make the validator run green.

The retained state-wallet outbox supports protocol 1/2 only. It must reject
protocol-3 shared budgets until a single shared-reservation signing path is built
and tested. Do not use independent wallet journals against the same funds.

Earlier native/ABCI source uploads were blocked by platform review; the exact
source was later accepted through the same GitHub connector and published in
draft PR #5. A future platform denial still stops that action: do not encode,
rename, split, use another channel, or otherwise reroute blocked source to
GitHub. Local build and review remain permitted. Distinguish a local branch,
bundle, or ZIP from a published PR, and report any remaining restriction.

CometBFT v0.38.25 and the upstream codec are mandatory for the network gate. Four
actual four-validator scenarios are required; fixtures, synthetic votes and
scripted ABCI processes cannot substitute. Windows has no required POSIX controls;
use a trusted local Linux/WSL environment for the real network and complete suite.
