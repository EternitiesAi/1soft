# Protected P8 wallet commands

The local Linux/WSL command wraps the unchanged encrypted recipient wallet. It
does not dispatch, retry, generate keys, choose remote trust, repair a wallet,
migrate a schema, or start an engine. A signed state establishes an AS-OF
observation under the separately pinned genesis, not the latest network state.

## Explicit custody inputs

Create an external owner-only `0600` credential file in a private `0700` directory,
with exactly `key`, `wallet_id`, and `recipient_secret`: each a 64-character
lowercase hexadecimal string. The AES256 key and opaque wallet ID must be nonzero;
the recipient secret must be a canonical nonzero P8 field. Obtain and preserve
them through a separately authorized custody process. No CLI flag accepts their
contents, and no command generates or prints them. This file is plaintext private
custody material; the CLI does not qualify its creation, backups or key management.

Supply complete trusted genesis bytes and their external SHA256, the exact public
KAT, the verifier-only worker, private note helper and private prover. Helper and
prover SHA256 pins are explicit trusted caller inputs. All files require a single
link, owned safe modes and non-symlink ancestry. Copy hard-linked Cargo binaries
to new single-link inputs without altering their originals. Runtime source and
native input hashes are frozen in a closed configuration manifest.

The configuration workspace must be new. The encrypted wallet file must be new
in a separate existing private directory. Interrupted setup is retained and
refused; no command overwrites or completes a partial creation.

```sh
python -B scripts/protocol8_wallet.py --workspace /home/operator/wallet-config \
  --genesis-sha256 TRUSTED_FULL_GENESIS_SHA --credentials /home/operator/private/credentials.json init \
  --genesis /home/operator/inputs/genesis.json --kat /home/operator/inputs/first.tx \
  --worker /home/operator/bin/recipient-consensus-bridge \
  --helper /home/operator/bin/recipient-wallet-helper --helper-sha256 TRUSTED_HELPER_SHA \
  --prover /home/operator/bin/recipient-prover --prover-sha256 TRUSTED_PROVER_SHA \
  --wallet /home/operator/private/wallet
```

Every subsequent invocation repeats `--workspace`, `--genesis-sha256`, and
`--credentials` before its subcommand. Existing credentials and binary/runtime
pins must match. Source changes require a separate reviewed release procedure;
editing a manifest does not create a new trust anchor.

## Commands and effects

| Command | Input and result |
| --- | --- |
| `doctor` | Inspects configuration, permissions, pins and envelope header. No native execution or encrypted-state authentication. |
| `inventory` | Authenticates and replays the encrypted wallet; prints public note IDs, intent IDs, attempts and completion metadata. It prints no private balances/openings. |
| `observe --packet FILE` | Verifies a closed `{witness, signed_header}` packet, monotonically extends the retained signed observation, and persists it encrypted. |
| `import-note --opening FILE --wire FILE --output-index 10` | Reproduces a private opening against the exact certified output receipt. Output 11 selects change. Explicit `--genesis-note` is a separate pinned issuance path. |
| `prepare --commitment ID --request ID --destination PUBLIC_KEY --payment UNITS --valid-until HEIGHT --payment-expiry HEIGHT` | Holds the original input and private request durably before proving; retains the independently verified exact wire before returning its txid. |
| `export --txid ID --output FILE` | Writes the exact retained public wire to a new private file. Does not mark an attempt or dispatch. |
| `mark-attempt --txid ID` | Persists one local caller attempt marker; a second marker refuses. The caller must mark before an external submission and never resubmit after an unknown reply. |
| `reconcile --txid ID` | Uses already authenticated retained observations to resolve the exact original wire: executed-exact, unresolved-held or conflict-held. No implicit state fetch or retry. |
| `deliver --txid ID --output-index 10 --output FILE` | After exact certified execution, explicitly writes the private recipient opening into a new private file. Stdout contains only its size/hash and txid. |

Packet, opening and wire inputs require owner-only files. Output parents must be
private `0700`; new outputs use atomic staged publication with `0600` permissions.
Existing files and symlink/hard-link paths refuse. Export failure does not replace
the original wire or release an obligation. Private delivery files contain note
secrets and must remain in the explicit custody boundary; the command sends them
to nobody. Standard command output contains statuses, opaque IDs, public receipts,
hashes and measured native process metadata. Refusal output suppresses private
exception strings, malformed JSON and native diagnostics.

An exclusive configuration lock refuses a competing CLI owner. The core wallet's
own file lock still coordinates access to the same encrypted blob. These local
locks do not synchronize separate wallets, backups, hosts or external signers.

## Evidence and remaining boundaries

Labeled fake-native tests exercise CLI filesystem/pin/output mechanics and actual
AES envelope authentication. A separate disposable process check verifies cleanup
of a native-style child in its own process session. The actual caller gate invokes
the CLI through the unchanged 22-check four-validator recipient-wallet journey.
It observes encrypted pre-proof holds, then exercises receive/import, cold reopen,
one external caller submission with a discarded response, signed exact recovery,
private delivery and genuine competing-spend reconciliation. The closed checker
checks receipt consistency; separate native replay verifies public evidence.

The fresh actual CLI journey requires clean-source qualification before it is
described as passed. Scope remains one trusted host and synthetic funds. No latest
state, hostile-host/rollback resistance, independent operators, scalable custody,
hardware/key recovery, production privacy/funds or public launch is qualified.
