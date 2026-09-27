# Protocol-3 wallet acceptance on a local CometBFT network

The wallet reservation path has now been exercised against a real local
CometBFT v0.38.25 network. The runner started four validator processes on one
host, used their signed state and transaction receipts, and completed the
upstream wire-codec probe. This is development acceptance evidence for the
protocol-3 wallet path; it is not evidence of a public network or production
custody.

The pinned CometBFT executable SHA-256 was
`218628da07bed5d27e178d38d0bef9ecf46f21b214c8e9fea402fd215fccc024`. The
local executable reports the `github.com/cometbft/cometbft` v0.38.25 Go module.
The runner checks the executable's reported version and records its digest;
it relies on the earlier trusted local build receipt rather than proving
binary provenance on its own. The upstream codec probe passed 9/9 checks.
All four actual local validator
scenarios passed:

| Scenario | Result |
|---|---:|
| Protocol 1, legacy state commitment | 22/22 checks |
| Protocol 2, legacy state commitment | 39/39 checks |
| Protocol 3, legacy state commitment | 46/46 checks |
| Protocol 3, `smt-v1` state commitment | 51/51 checks |

The exact final source tree passed 971/971 local Python tests with zero skips,
and all 104 required source files matched the manifest (SHA-256
`80cc6bbc3ff0cb21f23cb84d79dbd3ac0fd73226dfe69f7d4bcb983ac8f413b7`).
The separate JavaScript reference passed 30/30 tests. The Python suite is
local logic coverage; the four validator runs above provide the network
evidence.

## Wallet path exercised

In both protocol-3 scenarios, the runner waited until the live validators had
committed the owner transfer, shared-budget creation and both worker grants. It
then obtained the state through the application RPC and its signed next header,
and gave that full-state witness to `CertifiedWallet`. The wallet pinned the
actual CometBFT genesis and used one local signing journal. Disposable Raven and
Atlas keys and encrypted vault files were confined to the run's temporary
directory; they were not written to the result report.

Raven signed a 58-unit transfer with a 2-unit fee. While that signature was
pending, Atlas's 39-unit transfer plus fee was refused by the local reservation
check; the 38-unit transfer plus fee fit the remaining shared budget exactly.
The resulting wallet signatures matched the exact planned transaction bytes.
With both signatures held, the local journal reported 100 units reserved while
the chain still showed zero budget spend.

For Raven's submission, the real loopback RPC worker contacted CometBFT and
received endpoint admission. A test shim then discarded that returned result
and reported the attempt as unresolved to the dispatcher. This injects reply
loss at the client boundary after the actual RPC response was received by the
worker; it does not simulate or claim a TCP disconnect or a dropped socket
response from CometBFT. The dispatcher recorded one unresolved attempt. The
runner did not resend or re-sign. After reopening the same wallet journal,
`CertifiedWallet.export` recovered the original signed envelope byte-for-byte.

The read-only collector then found and verified Raven's exact receipt from the
live RPC state. `CertifiedWallet.sync` reconciled the wallet against a newer
quorum-signed full-state witness: Raven's hold cleared, Atlas's 40-unit hold
remained, and the on-chain budget showed 60 spent. After Atlas was submitted,
the collector verified its exact receipt and another signed-state sync cleared
the remaining hold; the on-chain shared budget showed 100 spent. These are DEV
atomic units, not dollars or claims about reserve backing.

The `smt-v1` scenario exercised this same wallet path using the signed full
state witness. It did not connect `CertifiedWallet` to a compact account-proof
wallet interface.

## Signing boundary and limits

For protocol 3, the supported signing route is `scripts/certified_wallet.py`
with one shared local `CertifiedWallet` journal for all participating signers.
The legacy `scripts/wallet.py` CLI and direct
`offline_signer.approve_intent()` signing call refuse protocol-3 signing. The
older `scripts/state_wallet.py` outbox also refuses protocol 3. Its database is
not migrated or shared with the certified wallet.

The test's `DispatchJournal` is a separate transport journal. It records
submission attempts and receipt evidence; it is not the signing reservation
store, and these two journals are not one atomic database. Envelopes signed
through another device, a raw key, an older workspace, or an already-signed
dispatch route do not acquire a reservation in the `CertifiedWallet` journal.
The test does not unify those routes or establish cross-device coordination.

The validators ran on one host with a static genesis validator set. This does
not establish independent-operator security, public-network behavior, a dynamic
light client, guaranteed-latest state, resistance to a hostile host or
filesystem, production key custody, or readiness for real funds. The wallet
uses bounded full-state witnesses and depends on the local trust policy, pinned
genesis, clock and shared journal. No public endpoint, production key, real
funds or paid host was used.
