# Protected P8 application operator workflow

The P8 recovery application has a small foreground CLI for one trusted Linux/WSL
host. It does not provision CometBFT, generate keys or genesis, choose network
trust, submit payments, repair stores or start public services. The engine remains
a separately owned process. Its private ABCI callbacks carry the existing trust
boundary described in [node recovery](PROTOCOL8_RECOVERY.md).

## Explicit inputs and setup

Use externally supplied complete P8 genesis bytes and their trusted SHA256, the
exact public 3,560-byte KAT proof, the verifier-only native binary and the existing
pinned CometBFT 0.38.25 binary. No command downloads or installs dependencies.
The application requires the existing Python `protobuf` dependency. The verifier
is measured against the genesis worker SHA, and the engine against the fixed
development SHA `218628da07bed5d27e178d38d0bef9ecf46f21b214c8e9fea402fd215fccc024`.
The engine version is identified by that exact known binary; doctor does not run it.

All paths must be absolute Linux paths. Keep the workspace in the Linux filesystem,
with owner-only mode 0700 and files mode 0600. Inputs must be owned regular files
with one link and no group/world write permission. Native executables need owner
execute permission. Symlink ancestry is refused. If Cargo created hard-linked
release binaries, make a new explicit single-link copy with the same SHA; never
change the original build to make a check pass.

```sh
python -B scripts/protocol8_operator.py init \
  --workspace /home/operator/1soft-p8-app \
  --genesis /home/operator/inputs/genesis.json --genesis-sha256 TRUSTED_FULL_GENESIS_SHA256 \
  --kat /home/operator/inputs/first.tx \
  --worker /home/operator/bin/recipient-consensus-bridge \
  --engine /home/operator/bin/cometbft
```

`init` first performs native KAT and genesis/network validation. It creates only
the new configuration workspace, copies public genesis/KAT bytes, and pins the
exact Python runtime file membership and hashes. It creates no database, wallet,
validator keys or engine home. Existing targets and partial creation refuse;
there is no automatic overwrite, repair or upgrade.

## Inspection, execution and reopening

```sh
python -B scripts/protocol8_operator.py doctor \
  --workspace /home/operator/1soft-p8-app --genesis-sha256 TRUSTED_FULL_GENESIS_SHA256
python -B scripts/protocol8_operator.py serve \
  --workspace /home/operator/1soft-p8-app --genesis-sha256 TRUSTED_FULL_GENESIS_SHA256
# After stopping the application:
python -B scripts/protocol8_operator.py audit \
  --workspace /home/operator/1soft-p8-app --genesis-sha256 TRUSTED_FULL_GENESIS_SHA256
```

`doctor` reads configuration and checks file ownership, modes, membership and pins.
It executes no native code or engine and does not verify database replay/schema.
Its configuration-valid result is not a healthy-node or consensus result.

`serve` revalidates all pins, holds an exclusive workspace lock, runs the actual
native startup checks and opens the strict recovery store. It uses only the fixed
owner-only `WORKSPACE/a.sock`; the engine's `proxy_app` must point to
`unix://WORKSPACE/a.sock`. The engine must separately match the complete genesis
and static roster. There is no TCP bind flag. Unknown/stale sockets are retained
and refused for owner diagnosis. SIGINT/SIGTERM shuts down the owned application
and removes only the server's own socket; SIGKILL cannot guarantee cleanup.
Keep engine and validator signing-state recovery separate from this application.

`audit` requires a stopped application and an existing recovery database. It opens
the actual store and performs full native replay, exact origin and real response
suffix validation. It emits only local height/AppHash, origin hashes, suffix heights
and measured worker receipts. Opening SQLite may change WAL bookkeeping; audit
does not edit monetary state, repair a malformed history or authenticate freshness.
Ordinary P8 stores and other schemas refuse with no silent migration.

Every command repeats the external full-genesis pin. Changing runtime files or
binaries invalidates the configuration; a stopped source upgrade needs a separately
reviewed migration/release procedure. An edited manifest is not a new trust anchor.
The operator command does not expose private note requests/openings, wallet keys,
validator keys, signed transactions or raw state payloads.

## Acceptance and limits

`tests/test_protocol8_operator.py` labels its fake worker and tests filesystem,
pin, locking, refusal and durable-state behavior. These are not cryptography tests.
`scripts/run_protocol8_operator.py` calls the actual CLI for five fresh workspaces,
launches normal private applications through it, and reuses the unchanged full
real CometBFT recovery/rejoin/recipient-spend/restart journey. The abrupt crash and
observed re-offer still use the separately token-gated test server; the production
operator command has no fault option. It audits all five stopped stores through
the CLI and checks graceful normal-server exit. The closed checker verifies both
the operator receipt and the underlying recovery receipt/artifacts; it is not an
independent proof of execution.

Qualification remains finite, synthetic and on one trusted host. Independent
operators, signer replacement/double-sign fencing, trust-period policy/freshness,
hostile hosts/networks, power-loss durability, production privacy/custody, pruning,
scale, economics, external review and public deployment remain open.
