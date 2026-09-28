# 1soft independent-operator testnet kit

This optional tool turns the current one-host validator evidence into a reproducible
**operator gate**. It does not deploy a public network, create validator keys,
choose economics, hold funds, or replace CometBFT/1soft consensus logic.

Source basis: draft PR #14 head
`12436b9fd47b09a471b327da927263b568370d75`, tree
`17fd2b4939e6f1cd5d55e87229604c97795566e0`. The kit is additive and does not
change native state, signing, ABCI, snapshots or wallet delivery.

## What it checks

A public `plan.json` pins:

- exact 1soft source commit/tree and root `SOURCE_MANIFEST.json` digest,
- exact CometBFT `0.38.25` binary SHA-256,
- exact common genesis SHA-256 and chain ID,
- operator names, P2P node IDs, validator public keys/power,
- explicit external P2P addresses,
- explicit RPC exposure decisions,
- two or more state-sync RPC providers plus an out-of-band trust height/hash,
- whether peers use public-routable addresses or a private overlay.

No private validator key, node key, password, seed phrase, wallet, or API secret
belongs in this plan or generated bundle.

`render.py` creates per-operator **public config patches**, not node homes.
`apply_config.py` patches a fresh CometBFT v0.38.25 `config.toml` only when every
expected key occurs exactly once and the resulting TOML parses.

The patch forces the tested 1soft operational boundary:

- exact UNIX ABCI socket supplied by the operator,
- unsafe RPC off, CORS empty, gRPC and pprof listeners disabled,
- explicit P2P external address and full persistent-validator peer set,
- PEX and seed mode off for this closed test gate,
- duplicate-IP allowance off,
- strict address book on public-routable plans (off only for an explicit private overlay),
- native transaction limit fixed at 16 KiB,
- state-sync snapshots capped at 64 chunks,
- validators start from genesis; the observer exercises state sync against at least
  two separately named RPC providers and an explicit trusted height/hash.

The kit does **not** decide firewall policy, TLS termination, OS users, disks,
systemd/container settings or cloud provider configuration.

## Per-host doctor

Each operator runs `doctor.py` locally with its existing node home, source checkout,
app database and CometBFT binary. It checks the exact Git commit/tree, clean tracked
worktree, every file in the root source manifest, engine digest/version, common
genesis, validator key/power in genesis, rendered config and read-only RPC state.

The RPC doctor issues only `status`, `net_info`, and `abci_info`. It checks chain
ID, node ID, application height, app version, catch-up status, validator power and
peer IDs. A state-sync observer must also retain its local state-sync marker and
have executed past the snapshot height.

Reports are hashed for accidental-change detection. They are operator self-reports,
not signatures, independent attestations, security audits or financial authority.

## Aggregate gate

`aggregate.py` accepts one report from every planned operator and requires:

- exact same source, engine and genesis identities,
- all nodes caught up with matching app/node height,
- at least four validator operators,
- at least two other planned validator peers visible from each validator,
- a connected validator peer graph,
- no unknown peers when `closed_peer_set` is enabled,
- heights within the explicit bounded skew,
- successful state-sync continuation for each state-sync observer.

A pass means **ready for independent-host fault drills**. It deliberately returns
`public_network_ready: false` and `real_funds_ready: false`.

## Commands

```sh
python tools/operator-kit/tools/verify.py

python tools/operator-kit/scripts/render.py \
  --plan /private/plan.json --output /private/new-operator-bundle

python tools/operator-kit/scripts/apply_config.py \
  --plan /private/plan.json --operator val-1 \
  --input /private/node/config/config.toml \
  --output /private/new-config.toml \
  --proxy-app unix:///var/lib/1soft/app.sock

python tools/operator-kit/scripts/doctor.py \
  --plan /private/plan.json --operator val-1 \
  --home /private/node --source-root /private/1soft \
  --app-db /private/app.sqlite --cometbft /private/bin/cometbft \
  --proxy-app unix:///var/lib/1soft/app.sock \
  --endpoint http://10.20.0.1:26657/ \
  --output /private/new-val-1-report.json

python tools/operator-kit/scripts/aggregate.py \
  --plan /private/plan.json \
  --report /private/val-1.json --report /private/val-2.json \
  --report /private/val-3.json --report /private/val-4.json \
  --report /private/observer-1.json \
  --output /private/new-testnet-readiness.json
```

The actual multi-host run is still required. Do not substitute five processes on
one machine or the PR #14 local state-sync evidence for independent operators.
