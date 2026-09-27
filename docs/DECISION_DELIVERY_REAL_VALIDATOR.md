# DecisionDelivery on local validators

The opt-in --decision-delivery runner path requires native protocol 3 and the
pinned CometBFT executable. It signs two development transfers with
CertifiedWallet, removes the temporary encrypted key files and clears the
ephemeral signing-key handles, then queues the exact recorded decision IDs
through DecisionDelivery.

```sh
python3 scripts/run_devnet.py --cometbft "$PWD/bin/cometbft" --protocol-version 3 --decision-delivery --output evidence/astra-decision-delivery-flat/devnet.json
```

```sh
python3 scripts/run_devnet.py --cometbft "$PWD/bin/cometbft" --protocol-version 3 --state-commitment smt-v1 --decision-delivery --output evidence/astra-decision-delivery-smt/devnet.json
```

The first payment crosses a temporary loopback proxy exactly once. The proxy
checks the real validator's successful broadcast_tx_sync response and then
closes the client connection without returning an HTTP response. The second
exact signed payment receives its upstream response normally. The proxy passes
only full-state abci_query and fixed-height block and commit reads after the
first payment. Each saved report separates transport status from wallet
obligation state and records queue, send, receipt-refresh, and reconciliation
states.

The runner reopens the original wallet and delivery journals after each send.
Receipt refresh must leave all wallet holds intact; DecisionDelivery.reconcile
then consumes the exact receipt packet and a bounded sequence of quorum-signed
headers. The protocol-3 fixture expects holds of 100, 40, then 0 units while
certified budget spend advances from 0 to 60 to 100.

This is an isolated local-engine acceptance run with disposable validator
keys. It uses no public endpoint or real funds. A passing report establishes
only the behavior exercised by this pinned local setup; it does not establish
production deployment, independent validator operation, or external settlement.
