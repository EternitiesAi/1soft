# Offline native-wallet signing laboratory

This is an original local signing interface for the existing native-coin application. It is development software, not an audited wallet, hardware security module, bank account, recovery system, or deployed network.

## What it does

- Generates a fresh Ed25519 key and stores it as encrypted PKCS8 using `cryptography` 46.0.4's `BestAvailableEncryption`. No new encryption or signature primitive is invented.
- Requires a private, owned POSIX directory and private key file. Descriptor-relative, no-follow opens reject symbolic links; key reads reject hard links, nonregular files, oversized data, unencrypted PEM and non-Ed25519 keys. Creation never overwrites an existing vault.
- Derives a review from trusted local genesis plus the exact transaction body and intended signer. Network/genesis, protocol, role, account, nonce, validity height, fee cap, amount, recipient and all operation fields are bound into a confirmation digest.
- Displays amounts as atomic integers, never as dollars or invented decimal precision. Grant allowances and the cost of creating a grant are different quantities.
- Requires terminal review and typed digest before an interactive password prompt. It accepts no password command-line argument, environment-variable shortcut, or plaintext-key import. The library is usable by tests, but is not a human-authentication boundary.
- Supports native transfers, grants, revocation, authority fencing, and two-sided account-opening/key-rotation consent. Signing as the incoming key returns a consent body, not a sponsor transaction. The sponsor/current key must review and sign the resulting body separately.
- Exports only a signed envelope or incoming-key consent. It has no network request, automatic retry, fee negotiation, or broadcast function. It never says a signed payment is settled.

## Basic interface

```sh
mkdir -m 700 .wallet-dev
python scripts/wallet.py create-key --vault .wallet-dev/owner.pem
python scripts/wallet.py review --genesis genesis.json --body intent.json --signer-public-key PUBLIC_KEY
python scripts/wallet.py sign --genesis genesis.json --body intent.json --signer-public-key PUBLIC_KEY --vault .wallet-dev/owner.pem --output signed-transaction.json
```

Use the public key printed by `create-key`, not the placeholder `PUBLIC_KEY`. Supply a transaction body in the existing native protocol's exact format; the app's `NativeLedger.body` helper constructs it. No genesis is downloaded or trusted automatically. Newly created keys do not acquire balances by being created.

For account opening or rotation, the incoming signer first uses `--mode accept` on the exact body with empty `acceptance`. The current owner/sponsor then uses ordinary `sign` on that returned body, including the verified incoming-key signature. Any changed funding/expiry/fee detail invalidates consent. The native ledger still independently enforces balances, nonces, authorization and fee policy.

## Important limits

The static review explicitly says `current_authority_verified: false`. It has no authenticated current-state source, cannot know that a balance/nonce remains usable, and does not prove that the claimed signer presently controls the account. An accepted ledger transaction or independently verified committed-state proof remains necessary. A locally prepared signature does not establish execution or settlement.

The confirmation digest binds the reviewed intention, but is not secret and does not authenticate a person. Whoever controls the password and process can sign. This interface is not a sandbox for autonomous agents and should not expose an owner's password or key to an agent. Agent funds remain subject to the existing native grant rules, not new cross-route budgets.

Encryption at rest does not protect an unlocked key from malware, a hostile OS, a debugger, memory dumps, same-user access or a weak password. Python does not guarantee memory zeroization. No hardware signer, backup/restore ceremony, multi-party recovery, production password-hardening assessment or independent audit is delivered. Keep this away from real funds.

The key file is created exclusively and synced. A crash during creation can leave an incomplete file; the operation does not claim crash-safe recovery or automatic cleanup of a partial key. The CLI refuses to overwrite transaction outputs. Native Windows permission handling is unassessed; Linux/WSL was tested.

## Observed tests

55 wallet tests passed, including real pseudo-terminal create/sign sessions with password echo checks, signature acceptance by the local ledger, amount/recipient/network mutations, wrong passwords/signers, file permissions/link handling, incoming-key consent, grants and account rotation. These are local development tests, not proof of secure production custody or distributed consensus.

## Primary implementation references

https://cryptography.io/en/46.0.4/hazmat/primitives/asymmetric/serialization/
https://cryptography.io/en/46.0.4/hazmat/primitives/asymmetric/ed25519/

Third-party primitives and their license terms remain upstream work. No affiliation, issuer partnership or novel cryptographic invention is claimed.
