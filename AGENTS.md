# 1soft engineering contract — cryptocurrency lane

1soft is the native cryptocurrency lane. Preserve repository history and explicit
source/evidence lineage. PR #12 at
`dd096271f24e704d27f39d551d5f16986934481d` is the validator-tested decision-
delivery baseline for this continuation. Draft PR #11 is a separate divergent
implementation: never transfer its claims or tests to the PR #12 line without an
explicit code/evidence reconciliation.

No GitHub Actions, paid/public compute, public deployment, DNS/site changes,
Resident/Luna/Psyche work, real funds, issuer/bank/card claims, production keys or
force pushes. Do not weaken a gate to obtain a pass. Missing pinned engines or
modules are UNASSESSED, never replaced with fixtures and described as consensus.

Read `docs/STATE_SYNC.md`, `docs/ABCI_INTEGRATION.md`, `docs/ROADMAP.md`,
`docs/NODE_ADMISSION.md`, `docs/STATE_WALLET.md` and the feature-specific
verification notes. Source inventory checks establish byte identity only; they are
not security or consensus validation.

Protocol 1/2/3 and `smt-v1` bytes are compatibility surfaces. Proposal/finalization
still execute ordered native transactions; admission caches never authorize block
execution. The private ABCI Unix socket is trusted engine control, not a wallet API.

The supported protocol-3 signing path is the shared-journal `CertifiedWallet`.
Legacy state-wallet/stateless signing paths remain restricted. Do not operate
independent journals or raw signing paths against the same funds and then describe
local reservations as globally coordinated.

ABCI state sync now has a bounded format-1 implementation. A restore may target
an uninitialized application pinned to the expected native genesis, or recover an
untouched installed checkpoint when its local marker matches the committed
height/AppHash and no block rows exist. That recovery can replace only the same or
a newer trusted snapshot; ordinary initialized apps with block history remain
ineligible. Every restored native state must recompute to CometBFT's
light-client-verified AppHash. Peer metadata/chunks are not authority. A local
state-sync marker is provenance, not consensus state. The new
scripts/run_state_sync.py gate must run against the real pinned CometBFT v0.38.25
binary after these recovery changes before this modified source is described as
engine-qualified for state sync.

Independent operators, public peer/RPC hardening, pruning/history policy,
validator-set evolution, production custody/recovery, external review, economics
and a bounded public testnet remain separate gates. Keep them visible rather than
turning a successful one-host development run into a launch claim.
