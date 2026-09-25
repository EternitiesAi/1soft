# Certificate-backed native signing — v0.8

This development component connects the existing fixed-validator certificate verifier to the encrypted offline signer and adds a durable local signing journal. It does not connect to a live network, download a trust anchor, run consensus, or broadcast payments. Every certificate exercised in the new tests is a locally constructed, explicitly synthetic fixture with real Ed25519 signatures.

## The path now exercised

An independently selected engine-genesis file is pinned by its exact SHA-256 digest in a local trust policy. The wallet accepts a bounded state witness (`schema`, `state`, `state_commit`) and authenticates it against the static genesis validator set. The application state at height h must be committed by the signed header at h+1. More than two-thirds of the pinned voting power must sign; the existing verifier checks all signature slots, including slots after a quorum has already been reached.

The wallet reconstructs the attested ledger in memory, checks its existing receipt and supply invariants, and reviews the exact proposed transaction against that snapshot. Checks include the controlling key, owner or grant nonce, grant epoch/revocation/expiry, permitted recipient, available allowance including fees, recipient existence, balance, and account-opening/key-rotation prerequisites. Incoming-key consent and owner/sponsor signing remain separate roles. Owner and agent keys are not interchangeable.

The resulting review binds the intention and signer to the exact header hash, state hash, policy hash, heights and attested balances. It explicitly states `authority_at_snapshot_verified: true` and `latest_state_guaranteed: false`. This is evidence about a particular historical snapshot, not knowledge of everything that has happened since it.

Signing reevaluates the evidence and the local checkpoint before key access. It reevaluates the policy deadline, snapshot age and local clock again after decryption, so a long unlock operation cannot silently turn an expired review into an approved signature. A signed native envelope is also exercised against the isolated snapshot using the existing ledger rules before it is released. Incoming-key consent cannot be fully executed until the separate owner/sponsor signature exists.

## Local trust policy

The policy is locally supplied, not accepted from an RPC response. Its exact fields are:

```json
{
  "schema": 1,
  "genesis_sha256": "<SHA-256 of separately trusted engine-genesis bytes>",
  "trust_expires_utc": "<an independently chosen UTC deadline>",
  "minimum_header_height": 1,
  "maximum_age_seconds": 300,
  "future_skew_seconds": 5
}
```

The placeholders are explanatory, not runnable defaults. The deadline is not automatically renewed. The policy identity is pinned in the journal, and changing it cannot silently reuse that journal. Maximum age is bounded to 1–86,400 seconds; future skew is bounded to 0–30 seconds. Those are development policy bounds, not universal security recommendations or economic protocol parameters.

This is not the general CometBFT light-client algorithm. There is no changing-validator-set verification, bisection, automatic trust renewal, peer diversity, or misbehavior-submission workflow. A chosen expiry and a recent timestamp cannot independently prove that validator keys are uncompromised. The static validator trust assumption remains explicit.

## Remembered state and signing decisions

Successful review records the greatest observed header height/hash and time in a local SQLite journal. Later reviews cannot go backwards or substitute a different header at an observed height. An adjacent header must link to the recorded header; skipping ahead relies on the fixed-validator quorum assumption rather than a delivered proof of every intermediate header. The locally observed clock must not move backwards.

Approval uses one SQLite write transaction to check the authority-nonce slot, generate/validate the signature, record the public result and update the checkpoint. Competing processes using this same journal cannot record different payments for the same authority nonce. A signature is not returned until its decision is committed. If the process dies or output-file creation fails afterward, `export` recovers the already signed envelope rather than signing a substitute payment. Export needs no vault password and remains available after the trust policy expires, while new review/sign operations fail on an expired policy.

The journal is not a network-wide lock, available-balance reservation, or custody service. A different journal, an older filesystem backup, a different signer installation or a compromised local account can evade local protections. Separate grants can still compete for the same balance; actual native execution must reject stale/nonexecutable transactions. No cross-route card/crypto spending budget is added here. Releasing a signed transaction for the first time is a separate operation; exporting one does not prove it was or was not previously broadcast.

## CLI

Use the complete v0.8 archive, not the current partial GitHub checkout. The supplied CLI reads bounded local files and does not make network calls. Create a private directory for the journal, and use a development vault from the existing wallet tool.

```sh
mkdir -m 700 .wallet-dev
python scripts/certified_wallet.py review \
  --genesis engine-genesis.json --policy local-policy.json \
  --journal .wallet-dev/decisions.sqlite \
  --witness certified-state.json --body intent.json \
  --signer-public-key PUBLIC_KEY
```

`sign` takes the same options plus `--vault` and a new `--output` filename. It requires an actual terminal, displays the certified review, requests its confirmation digest, and then prompts for the password. No password command-line argument or environment-variable unlock path is offered.

`export` takes the trusted genesis, same policy and journal, plus `--decision-id`. It does not request a password. Optional `--output` writes the previously recorded public envelope to a new file and refuses overwrite. An output error after signing does not mean signing failed; recover the displayed decision rather than creating a replacement transaction.

For incoming-key consent, select `--mode accept`; pass the resulting consent body to the owner/sponsor for an independent review and ordinary signature.

## Tests and limitations

47 new tests cover cryptographic evidence rejection, old/future snapshots, expired trust, clock reversal, signer/nonce/balance checks, grants and revocation, account opening and rotation, remembered rollback/conflicts, competing local signers, terminal signing, export without a key, crash recovery and occupied output files. Five targeted mutation checks confirm tests fail when controlling-key, age, rollback, post-unlock time, or authority-nonce reservation checks are weakened. These are bounded developer tests, not an independent audit.

A test explicitly demonstrates that another transaction can consume the nonce after a certified review, making the reviewed signature fail subsequent execution. Recent evidence is not guaranteed latest evidence. There is no claim of a live certificate, a settled payment, or a secure public Layer 1.

Key custody inherits the v0.7 limitations: Python does not promise memory zeroization; encryption at rest does not protect unlocked keys from a hostile machine. The journal assumes a private owned POSIX directory and trusted local filesystem; SQLite reopens its files, so the prechecks are not a hostile-filesystem race defense. Journal rows and local checkpoints are not externally authenticated against malicious same-user alteration. Full-state witnesses have 16 MiB and per-table 10,000-row development bounds; there are no compact account Merkle proofs or production scalability claims.

## Primary background

The upstream light-client specification distinguishes trusted-header assumptions, validator trust periods and bounded local-clock drift from merely receiving signed data. This implementation borrows that distinction, but does not claim implementation of the general algorithm:

https://docs.cosmos.network/cometbft/latest/spec/light-client/verification
https://github.com/cometbft/cometbft/blob/main/spec/light-client/README.md

The certificate algorithms, protobuf and cryptographic dependencies retain their prior attribution and limitations. No original cryptographic primitive, consensus algorithm or established novelty is claimed.
