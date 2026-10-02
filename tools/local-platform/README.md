# 1soft local developer release

An integrated development wallet on the native Protocol 4 Layer 1. One command
creates a private four-validator CometBFT network, encrypted development vaults,
an operator-created genesis and first-header trust anchor, and a loopback wallet.
The wallet supports unsigned payment requests, owner/agent reviews, signing,
one submission attempt, exact receipt collection, explicit reconciliation,
portable receipt export and cold recovery.

This release uses valueless **DEV atomic units**. It is a bounded developer
workflow; public operation, production custody and real-money payments are not
qualified. The native engine, P1/P2/P3 interfaces and existing P4 components are
unchanged. The older static web client continues to refuse P4 spending.

## Run in Linux or Ubuntu WSL

Use the installed Python environment matching `requirements.txt` and the existing
CometBFT **0.38.25** binary. Its required SHA256 is
`218628da07bed5d27e178d38d0bef9ecf46f21b214c8e9fea402fd215fccc024`.
There are no automatic downloads, installs, Actions or cloud services.

From the source checkout:

```sh
python tools/local-platform/scripts/1soft.py new \
  --workspace "$HOME/1soft-dev" --engine /path/to/cometbft
```

The workspace must be new, outside the checkout, on a trusted owned POSIX
filesystem, and short enough for a private Unix socket (about 85 path bytes).
Choose a development vault password of at least 16 UTF-8 bytes at the terminal;
it is never supplied in arguments, environment variables or logs. Open the
printed `http://127.0.0.1:PORT/` in a browser. Host/origin guards require the exact
literal address. A browser connector may block local addresses independently of
whether the application is running; the automated API checks do not substitute
for a rendered browser or human acceptance check.

The machine used for the captured build has Python at
`/home/xnuonux/1soft-v016-execution/integrated/.venv/bin/python` and the binary at
`/home/xnuonux/1soft-v016-execution/integrated/bin/cometbft`. Substitute that Python
path for `python` and that binary for `/path/to/cometbft` on that installation.

`Ctrl+C` stops only the started validators, their applications and the wallet
server. Databases, encrypted vaults, original signed decisions, attempts, trust
policy and receipts remain. Resume the same workspace:

```sh
python tools/local-platform/scripts/1soft.py start \
  --workspace "$HOME/1soft-dev" --engine /path/to/cometbft
```

An initialized workspace never gets a new genesis, anchor, endpoint or journal
automatically. `init` separates creation from first startup; `status --workspace
PATH` inspects retained configuration without probing processes or changing data.
`new` and `init` refuse an existing directory. Unknown configuration, unsafe files,
an existing socket, a concurrent owner, or partial first journal initialization
is refused and retained for diagnosis. There is no reset or repair switch.

## Follow a payment

1. Create a 10-minute unsigned request or import canonical request JSON. A request
   binds this genesis, a recipient and exact atomic units. Its note stays off
   chain; it does not authenticate the merchant or prove execution.
2. Choose the owner, Raven or Atlas role and review the exact recipient, amount,
   fee, total debit, validity and decision digest. Approve that review and unlock
   only its fixed encrypted development vault. The existing shared P4 wallet
   records the signature and reservation before returning. It does not submit.
3. Review submission independently, then approve **one attempt** of those original
   signed bytes to the fixed local endpoint. An admitted response is not payment
   proof. If the return is lost, the desk performs one read-only inspection of the original decision;
   there is no re-sign, resend, cancel or hold-release shortcut.
4. Collect receipt evidence. An immediate collection can observe the preceding
   block, so `unavailable` means unknown and keeps the obligation. A later explicit
   collection can prove the exact original transfer after it is committed.
5. Reconcile the verified receipt in the wallet. Only this authenticated wallet
   operation retires its hold. Retaining a capsule or viewing the ledger does not.
6. Keep/export the portable capsule. It contains full proof history, including
   unrelated accounts and transactions, and retains the original trust deadline.
   Verification still requires external genesis, policy and current time.

The default treasury starts with 1,000 DEV atomic units. Setup creates one shared
100-unit budget and two agent grants before the wallet journal exists, spending
three 2-unit setup fees. A 58-unit Raven payment reserves 60 units; Atlas can then
reserve at most a further 40-unit debit from that budget. Owner transfers still
share the same account journal. There is no speculative nonce ladder or fallback
from an agent to owner authority.

The display distinguishes recorded treasury balance, pending fee-inclusive
obligations, uncommitted units and deficits. **Collect ledger** updates the read
store only. **Use ledger in wallet** explicitly reconciles that verified
observation in the wallet. GET/view reloads perform neither network collection
nor financial changes.

## Preserve the development bounds

RPC proof collection is limited to **64 blocks**, offline replay to 512, the
wallet to 32 observations/256 decisions, and the request book to 64 records. The
capsule archive has its existing 32-record/64-MiB payload bounds. No records are
evicted. The configured four-second commit interval gives only a few minutes of
active collection in this developer network. Stop it when finished rather than
leaving it mining overnight. A stopped network can resume its retained chain;
the original one-hour trust interval continues to elapse while it is stopped.

Fixed-policy expiry clears current qualified balance/ledger views and refuses
new approval or submission. Historical original-wire recovery remains available;
it does not renew trust or create current spending authority. Compact P4 proofs,
long-running collection, post-expiry archival verification, independent hosts,
public economics/governance and production custody remain separate work.

All wallets for these funds must use this one local journal. Copies, other signing
paths, hostile-host rollback and cross-device coordination are outside its
guarantee. Local vault unlock assumes a trusted host; physical memory erasure and
production browser custody are unassessed. The browser cannot choose file paths,
genesis, policy, administrative keys or transport endpoints.

## Browser recovery checks

The progress display separates saved attempts, collected receipts, ledger-derived
wallet reconciliation and historical execution. If a failed action cannot be
inspected, current totals stay unavailable and spending actions remain disabled
until reload succeeds. Pending reviews lock all payment fields and retain their
captured request/role. Commands, fixture boundaries and remaining human acceptance
checks are in [browser payment recovery](../../docs/BROWSER_PAYMENT_RECOVERY.md).

The whole-source qualification command below belongs to the older local release
revision and its unchanged 421-file inventory. It intentionally refuses later
native invoice and browser descendants. Use the feature-specific scope and
committed-source receipts; do not replace historical seals to obtain a pass.

## Qualify the exact committed source

With a clean checkout, pinned installed packages, Node and cached official Go
dependencies:

```sh
python tools/local-platform/scripts/1soft.py qualify \
  --engine /path/to/cometbft --output /private/new-qualification-directory
```

The parent directory must exist. Output must be new and outside the source. The
command verifies every tracked Git byte/mode, ancestry and all 421 inherited
files; runs inherited and new Python/JavaScript component checks; compares four
P4 response vectors with official CometBFT Go types offline; runs the existing
actual P4 baseline, delivery, explorer/receipts, bootstrap-after-turnover and
Commit-reply-loss gates; then runs the new actual product and CLI cold-recovery
journeys. Missing dependencies, skip/zero/partial results, source changes and
engine changes do not pass. Logs and machine-readable results remain outside the
checkout. Browser rendering, human acceptance and production/security gates stay
explicitly unassessed until separately performed.

The architecture and ownership boundaries are in
[`docs/LOCAL_DEVELOPER_RELEASE.md`](../../docs/LOCAL_DEVELOPER_RELEASE.md).

## Encrypted history download

The guarded wallet and merchant screens can export complete retained shared wallet/delivery history as an encrypted format-3 attachment. Scope includes other roles and unresolved obligations, excludes keys and separate book files, and restores only to a historical archive. The browser caps original captured BLOBs at 8 MiB and final ciphertext at 16 MiB, refusing the whole export rather than trimming. See [browser history recovery](../../docs/BROWSER_HISTORY_BACKUP.md) for passphrase, scope, expiry, CLI fallback and qualification boundaries.
