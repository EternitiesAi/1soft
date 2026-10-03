# Durable private alpha

This is an explicit, fresh-genesis development profile for extended local payment
work. It preserves the original financial journal while authenticated history
advances. Existing workspaces keep their original policy and limits; they are not
migrated, cleared or silently renewed.

## Start a new alpha

Use Linux/WSL, the installed dependencies in `requirements.txt`, and the pinned
CometBFT 0.38.25 binary. From the repository root:

```sh
python tools/local-platform/scripts/1soft.py doctor --engine /path/to/cometbft
python tools/local-platform/scripts/1soft.py new \
  --profile durable-private-alpha-v1 \
  --workspace "$HOME/1soft-alpha" --engine /path/to/cometbft
```

The workspace must be new, private, outside source and short enough for Unix
sockets. Enter the vault password at the terminal. Four validators and their ABCI
applications run locally; open the exact printed loopback wallet URL. Stop with
Ctrl+C. Resume with `start --workspace` and the same engine, without a new profile:

```sh
python tools/local-platform/scripts/1soft.py start \
  --workspace "$HOME/1soft-alpha" --engine /path/to/cometbft
```

`init` also accepts the explicit new profile. The default remains `legacy`.
`start` cannot change an existing profile. Original genesis, policy, signing
journal, attempts, receipts and encrypted vaults remain in their original homes.

## Limits and authority

| Bound | Legacy local wallet | Explicit durable alpha |
|---|---:|---:|
| RPC history | 64 total blocks | 4,096 total; at most 64 new blocks per batch |
| Application/offline history | 512 blocks | 4,096 blocks |
| Wallet observations | 32 | 4,096 small original-history references |
| Signed decisions / dispatch attempts | 256 / 256 | 256 / 256 |
| Unsigned requests | 64 | 64 |
| Retained portable receipts | 32 full packets | 256 small original receipt references |
| Browser encrypted-history file | 16 MiB, B3 | 180 MiB, A1 |
| Complete authenticated history in custody | Legacy format bounds | 64 MiB |

Other typed byte/cache/SQL limits apply before writes. Capacity exhaustion refuses
new work without evicting original history or financial obligations. The store's
256 MiB logical capacity exceeds custody's 64 MiB complete-history capacity: an
oversized backup is refused, not partially exported. Resource behavior at all
maximum ceilings is not established by a short qualification.

The alpha policy pins the original first header and genesis, permits sequential
checkpoint advancement, and fixes an absolute horizon at **24 hours after the
original anchor**. Each new admission must occur before the prior authenticated
checkpoint's one-hour deadline; each signing operation also needs the exact latest
retained tip and the existing five-minute freshness bound. Clock regression,
expired admission gaps, changed tips and horizon expiry refuse authority.

This is a deliberate new development trust policy. It does not extend an existing
legacy deadline. Stopping the program does not stop its clock. An expired gap
cannot be recovered by changing policy, replaying old evidence or recreating a
journal. Historical original wires and receipts remain inspectable.

## Use the local wallet

Create a request, review its recipient/units/fee/role, approve the fixed vault, then
separately review and approve one submission attempt. A transport response is an
observation; only authenticated native execution proves the original payment.
The collector fixes its target once per batch and verifies the entire ordered
native execution, header/commit chain and validator roster from pinned genesis.

**Collect ledger** advances retained read history. **Use ledger in wallet**
explicitly assimilates that tip into the same financial journal. GET/view does
neither. The network owner retains a warm authenticated cursor across sequential
browser requests; cold reopen authenticates original retained history again.

The displayed wallet and read ledger can have different checkpoints. Saved wallet
balances, original decisions and fee-inclusive holds remain visible while newer
read history is available. Signing and dispatch controls require the wallet's
context to match the authenticated current tip. A stale wallet context can sync
from continuously admitted history; it cannot independently renew expired trust.

All prior reviews, signatures, lane nonces, shared budgets and hold amounts stay
bound to their original checkpoints. Receipt collection retains a small reference.
Wallet assimilation/reconciliation is the operation that retires a hold from exact
successful execution. An expired signed transaction or an unknown delivery outcome
does not release funds and does not become safe to resend. Copies and independent
signing paths do not coordinate reservations.

## Recovery and portable receipts

The alpha browser explicitly exports A1 encrypted history. It contains one complete
authenticated retained prefix plus original shared wallet/delivery records,
including hidden decisions and other roles. It excludes private keys, vaults,
private invoice content and unsigned/separate request or merchant books. Keep the
passphrase and external original genesis/policy pins privately.

`p4_alpha_custody.backup` uses fixed scrypt and AES-256-GCM under a separate versioned
domain. `restore_backup` and `RecoveryArchive` reconstruct **inert historical
records**: original wires, holds, attempts, responses and receipts can be audited;
there is no signer, dispatch method or active journal restoration. Expired historical
export does not renew trust or fence an old device. Encryption establishes file
integrity under the supplied passphrase, not external provenance of private host
approval/admission timestamps or protection from a hostile host rollback.

Alpha receipt capsules contain the exact original wire and one authenticated
prefix ending at the selected original positive receipt checkpoint. Their
`capsule_id` is the content ID of an explicit small reference; `packet_sha256`
identifies the downloaded bytes. They remain stable when later history advances.
The offline verifier requires external genesis/policy, payer and wire SHA256 and
proves exact included native execution. It does not prove the private approval
journal, current spending authority, latestness, absence, external settlement or
independent validator operation. Legacy capsule formats remain separate.

## Run exact-source qualification

First run the existing current-source unit check:

```sh
python tools/local-platform/scripts/1soft.py check \
  --output "$HOME/1soft-alpha-unit-evidence"
```

Then, with a clean Git checkout and the cached pinned engine, run the actual alpha
gate into a different new external evidence directory:

```sh
python tools/local-platform/scripts/1soft.py qualify \
  --profile durable-private-alpha-v1 --engine /path/to/cometbft \
  --output "$HOME/1soft-alpha-real-evidence"
```

The gate takes more than **one real hour**. It uses unscaled wall and monotonic
clocks, four actual local validators and one original genesis/home/DB/policy. It
crosses blocks 64 and 512, stops and restarts the owned processes in the same homes,
keeps an original payment and an unsubmitted signature/fee hold, and proves a new
payment after the original anchor's one-hour boundary. It checks exact original
receipt bytes, budget/role nonces, more than 32 retained wallet observations,
complete encrypted inert recovery, source/engine identity and owned process closure.

Reports bind to all current Git bytes/modes. A failed or missing result stays failed
or incomplete, with original fixtures retained. The qualifier does not shorten the
hour, weaken checks, install dependencies, start Actions or deploy publicly.
Generated keys, encrypted backups and inert financial fixtures remain private
outside the source and handoff; report/source/phase history contains only sanitized
execution evidence. Browser rendering and independent correctness review are separate
gates. Old dated evidence does not certify a new source revision.

This profile makes local development last long enough to test durability. Public
launch still needs independent operators, reviewed production custody and protocol,
economic/genesis/governance decisions, and sustained operational qualification.
Transactions remain public; there is no shielded ledger privacy in this profile.
