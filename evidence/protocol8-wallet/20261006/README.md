# P8 recipient wallet evidence

Actual one-host qualification: 22 checks, four genuine native
proofs, three committed payments, four fresh CometBFT 0.38.25 validators.
The received payment is imported under signed state, reopened from encrypted
storage and spent through arbitrary native preparation/proving. One broadcast
reply is deliberately discarded; exact certified original-wire recovery is
idempotent after cold reopen with one caller attempt and no resubmission. A
distinct genuine conflicting spend produces certified conflict-held status.
Private output delivery is imported into a separate recipient wallet.

Seven fake envelope/worker unit methods are separate from actual proof evidence.
The independent replay run verifies four native proofs and three signed AS-OF
state witnesses. All owned processes stopped. Exact source/binary pins, public
proofs and sanitized raw logs are retained. Private requests, keys, openings,
wallet files, validator stores and compiled targets are excluded.

Source reviews are by AI peers, not external specialist certification. These
results establish no freshness, hostile-host custody, snapshot rollback
resistance, public deployment, real funds, P8 state sync, P7 migration or launch
readiness. Read docs/PROTOCOL8_RECIPIENT_WALLET.md for boundaries and limits.
