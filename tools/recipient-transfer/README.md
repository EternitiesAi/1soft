# Recipient-controlled spending

Separate experimental P8 native proof and bounded public state component.
Read [the authority and integration boundary](../../docs/PROTOCOL8_RECIPIENT.md)
and [the frozen profile](PROFILE_V1.json) before using it. There is no P7 note
migration or live validator/wallet integration in this increment.

```sh
cargo test --manifest-path tools/recipient-transfer/halo2/Cargo.toml --locked --offline --release --tests
cargo build --manifest-path tools/recipient-transfer/halo2/Cargo.toml --locked --offline --release --bins --example recipient-request-fixture
cargo build --manifest-path tools/recipient-transfer/halo2/Cargo.toml --locked --offline --release --no-default-features --bin recipient-verifier --target-dir /absolute/separate-verifier-target
python -m unittest tests.test_protocol8_transfer tests.test_protocol8_report -v
python scripts/run_protocol8_recipient.py --help
python scripts/check_protocol8_recipient_report.py --help
```

The fixture example is expressly synthetic; it is not key generation or wallet
custody. Do not record private request stdin. Proof/state receipts contain public
commitments and public wires and do not establish production privacy or finality.
