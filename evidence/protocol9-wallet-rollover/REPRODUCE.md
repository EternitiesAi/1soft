# P9 wallet rollover execution receipt

Native runner source `6959387506532523048cff7ef57895b5b7f2ba06`; separate public replay source
`2c2a3676569525a5a5b5df3af8ff1455ff84117a`. Later commits register evidence/documentation only.
All 25 native checks passed. Three wallet payments plus seven
setup-generator payments produced21notes/10fees. Actual older/newer-segment wallet
payments committed at heights[68, 70]. Five signed state heights:[1, 4, 65, 68, 70].
All four validators refused the distinct valid older-input competing proof.
Discarded-response recovery used the original wire once. Wallets reopened in a
fresh Python child, and sends stayed refused. All owned processes stopped.

Public replay authenticates signed history and exact receipts. Hidden private
input binding, balances and transport/custody exercises were checked by the
native wallet runner, not independently inferred by the public checker.
This is one trusted host with disposable keys and synthetic funds, not external
security review, independent operation, production custody or public launch.

See docs/PROTOCOL9_WALLET_ROLLOVER.md for supported commands and remaining limits.
Raw logs are sanitized only for the owned private runtime path; trailing spaces
and warnings are preserved. No private wallet stores, AES keys, openings,
validator homes, binaries or credential/Git bundles are included.
