# Authenticated P9 recipient wallet

10 October 2026. Bounded local development on one trusted POSIX host, with
disposable native keys and synthetic funds. No public deployment or migration.

The segmented P9 ledger now has its own encrypted recipient wallet and explicit
single-send caller. Alice paid Bob 400 units; Bob spent 50 of those received
units back to Alice. A real loopback receiver forwarded Alice's original wire
once and discarded the reply. Alice recovered exact execution from signed
history, and both wallets rejected further sends of the original payments.
Both encrypted wallets reopened with identical authenticated inventories and
results in a fresh Python process using a fresh native worker.

[Native journey receipt](../evidence/protocol9-wallet/20261010/native-02.json)
passed all 19 checks at clean source
`9122c0d5ee33f3245eae15bf07b8b961a5db895a`. Four actual pinned CometBFT
0.38.25 validators committed both payments. Signed observations bound state
heights 2, 5 and 9 to headers 3, 6 and 10. Synthetic conservation was
1,000 = Alice 649 + Bob 349 + fees 2. This arithmetic is an execution fixture,
not a supply, ticker, token valuation or public economic policy.

## Authentication and recovery

A compact P9 checkpoint signs a running history digest, so an isolated segment
or transaction query cannot prove membership. The wallet receives complete
bounded public history and a signed next header. It checks the external full
genesis, chain and static validator roster, authenticates the checkpoint, and
replays every transaction attempt with the pinned native worker. It reconstructs
notes, segment roots, spent-note nullifiers, request identities and exact receipts.
The exporter performs a consistent read-only database transaction; it is only
transport and does not confer trust. No supplied wallet index is accepted.

The input's authenticated segment determines its native membership path.
Global spent-note and intent indexes continue to apply across segments. The
encrypted P9 wallet has its own envelope/bootstrap pins; P8 files are refused
rather than migrated. It retains openings, original private proof requests,
public wires, signed observations, completed receipts and one-attempt markers
inside AES256-GCM, with owner-only files, locking and atomic durable replacement.

Preparation persists the input/intent hold before proving. An unknown proof
outcome does not regenerate a payment. Submission durably marks the original
wire attempted before exactly one bounded HTTP call to a literal loopback node.
Admission never establishes settlement. Recovery authenticates an exact receipt;
an absent or competing receipt keeps the obligation held, without retry/release.
Private opening delivery is explicit and is never included in the public logs.

## Developer interfaces

- `protocol9_certificate.export_history(path)` exports untrusted bounded public
  bytes; `verify_history(witness, header, external_genesis, worker)` authenticates
  and derives the wallet view through native replay.
- `protocol9_wallet.RecipientWallet` provides observe, explicit commitment/opening
  import, prepare, original export, one-attempt marking, reconciliation, private
  opening delivery and redacted inventory. Keys remain external to the file.
- `protocol9_payment.send_once(wallet, txid, endpoint)` submits the retained
  original once, with no automatic resend and no settlement assertion.
- `scripts/protocol9_wallet_reopen.py` reopens externally keyed wallets in a
  fresh process. Private inputs use bounded stdin, not argv/environment or logs.
- `scripts/run_protocol9_wallet_engine.py` runs the disposable actual-validator
  journey. [Reproduction and source scopes](../evidence/protocol9-wallet/20261010/REPRODUCE.md)
  include exact inputs, negative runs and process receipts.

## Explicit limits

This is complete bounded history authentication, **not compact per-record
proofs**. Replay and retained observation cost grow with history. Current client
bounds are 4,096 blocks, 512 decided attempts and a 6 MiB packet. The encrypted
wallet separately caps 32 imported notes, 16 obligations, eight observations,
256 revisions and a 16 MiB plaintext payload. A payload may exhaust its byte
capacity before a count capacity. These are fail-closed client limits, not P9
consensus limits or measured maximum-capacity performance. A process-local memo
only retains verified exact packet/header bytes; it is not persisted as authority.
Cold reopening replays retained observations with the native worker.

The wallet journey used five ledger notes and two payments. Selection among more
than sixteen global notes has a separate labeled unit mechanics test; the earlier
P9 backend's actual 21-note/10-payment gate remains separate. This wallet receipt
does not establish native wallet operation at segment rollover or beyond height64.
The small sixteen-note segment input set and public segment anchors are unchanged.
No new anonymity, network metadata privacy or scalable storage claim is made.

Signed observations establish AS-OF state under an externally pinned static
quorum, not freshness. Host compromise, local encrypted-file rollback, distributed
multi-caller coordination, production key custody/recovery, pruning/state sync,
independent operators, hostile networks, long-duration load and external security
review remain open. The P8 browser alpha remains a separate finite product path;
this P9 milestone does not connect that browser to P9 or change its pins.
