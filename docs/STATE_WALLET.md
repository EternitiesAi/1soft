# Attested account-state wallet and persistent native outbox — v0.8

This is a development integration of the existing native ledger, static-validator
certificate verifier and encrypted offline signer. No consensus implementation,
network service, bank account, stablecoin backing or public asset is added.

## Working flow

A separately pinned engine-genesis file identifies the validators the wallet
trusts. `sync` checks a full account-state witness against their signed header.
The wallet never accepts a substitute validator list from the response. It
checks every signature slot and requires the verifier's voting-power threshold.
It then validates snapshot shape, monetary invariants and the stored receipts.

The persisted checkpoint prevents accepting a lower height or a conflicting
same-height header while that local workspace remains intact. Advancing requires
exact predecessor block-ID links; gaps need intermediate signed headers, bounded
to 64 per import. The state at height h is attested by header h+1, not header h.

`prepare` constructs a native transfer using the account/grant key and nonce
from that attested state. It checks recipient permissions, grant revocation,
authority epoch, expiry, fees and available balance. The review digest binds the
exact transaction AND its checkpoint AND the other locally outstanding debits.
A different checkpoint or changed local reservations requires a new review.

`sign` rechecks this context before releasing a signature. The existing encrypted
vault is unlocked through a terminal password prompt, not a command-line secret.
A temporary ledger copy validates the actual envelope. The signature and debit
reservation are committed to the local outbox before the caller receives them.
If file export fails, or the process exits after commit, `export` retrieves the
same signature. The wallet does not produce a second payment to compensate.

Different native agent grants using this workspace share its available-balance
check. Two different transactions cannot occupy the same pending account/grant
nonce. Existing per-grant caps also apply, including transaction fees. This is
wallet-local reservation accounting: it does not lock funds on-chain or constrain
other workspaces, older backups, other signers, or the legacy signing interface.

## Resolution

Outbox states are `signed`, `recorded`, and `expired`. `signed` does not mean sent
or paid. A matching receipt in newly verified state changes it to `recorded`.
This asserts a receipt in the attested native state, not an external settlement.

Without that receipt, the debit remains outstanding until the verified state
height is strictly greater than the intention's inclusive validity height. A
wall-clock timeout, missing response or key revocation alone does not release it.
Receipt discovery takes precedence over expiry. Reconciliation and checkpoint
replacement share one SQLite transaction.

## Commands

Use a private Linux/WSL directory and the installed pinned Python dependencies.
The genesis file and its expected digest must come from a separately trusted
source; a digest learned from the same untrusted reply adds no trust. Placeholders
below are not real accounts, public keys or a published network.

```sh
mkdir -m 700 .wallet-state-dev
python scripts/state_wallet.py --genesis genesis.json --genesis-sha256 TRUSTED_SHA256 --workspace .wallet-state-dev/state.sqlite sync --packet state-evidence.json
python scripts/state_wallet.py --genesis genesis.json --genesis-sha256 TRUSTED_SHA256 --workspace .wallet-state-dev/state.sqlite prepare --account ACCOUNT --recipient RECIPIENT --units 20 --valid-until 100 --output review.json
python scripts/state_wallet.py --genesis genesis.json --genesis-sha256 TRUSTED_SHA256 --workspace .wallet-state-dev/state.sqlite sign --review review.json --vault .wallet-dev/owner.pem --output signed.json
python scripts/state_wallet.py --genesis genesis.json --genesis-sha256 TRUSTED_SHA256 --workspace .wallet-state-dev/state.sqlite pending
```

For a grant, add `--grant-id LABEL` to prepare and use the grant's separate vault
for signing. `sync --continuation headers.json` supplies intermediate signed
headers. `export --txid TXID --output recovered.json` retrieves a saved envelope.
Outputs are never overwritten. The new attested-outbox mode supports transfers;
account opening and rotation remain available through the earlier offline signer.
No command fetches RPC data, transmits a transaction, or trusts test validators
as a public network. There is no hidden simulated-network fallback.

## Trust and security limits

Certificates establish an AS-OF state under the pinned static-validator trust
assumption. They do not prove the latest network state or live-engine provenance.
The default local age policy accepts header timestamps up to 300 seconds old and
30 seconds ahead of the local clock. This is a plausibility bound, not a solution
to stale-but-recent replies, eclipsing, validator compromise, or clock compromise.
All signing reviews keep `latest_network_state_established: false`.

The header-chain checks apply after bootstrap. Bootstrap itself trusts a static
validator quorum under the separately pinned genesis; it does not verify the
entire historical chain. Dynamic validators and production light-client trust
periods are unsupported. These tests use synthetic validator certificates over
real local ledger execution, not output from a running consensus engine.

The workspace assumes a trusted, stable, same-user POSIX filesystem. Private
permissions and signature revalidation are not hostile-OS protection. Replacing
or rolling back the entire workspace, losing it, using another device, or using
the key elsewhere can invalidate local reservation/rollback guarantees. The
workspace is not a hardware monotonic counter or a synchronized multi-device
account service. It contains public signed envelopes, not private vault keys or
passwords. It is not encrypted against privileged local readers.

Full-state witnesses are bounded to 16 MiB and 10,000 rows per table in this
wallet. They are a development technique, not scalable authenticated account
queries. The external settlement journal and card/cash routes remain separate.
No production custody, recovery ceremony, hardware signing, audit, legal issuer
arrangement or public economic policy is established by this release.
