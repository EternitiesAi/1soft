# Resident Pass — laboratory protocol and native bridge

## Four deliberately separate questions

1. **What does the issuer assert?** A signed credential identifies an issuer,
   subject alias, display name, holder key, epoch, audience, kind and validity.
2. **Is that assertion accepted here under fresh evidence?** The verifier has a
   pinned issuer public key and allowed claim kinds. An issuer-signed status
   snapshot must be fresh and match the credential and holder epoch.
3. **Does this presenter control the holder key now?** A one-use, audience- and
   purpose-bound challenge must be signed by that key. A card image or copied
   credential is insufficient.
4. **Is the account association separately approved?** The optional native bridge
   requires an authenticated account-state proof and a different financial key's
   signature over the exact association and challenge. The result is not a spend.

This is a new project integration of established primitives, not a new identity
standard or a claim of scientific/proprietary uniqueness.

## Data format

Documents are exact-field canonical ASCII JSON with sorted keys and integer
counters/timestamps. Extra fields, non-finite values, fractional JSON numbers and
duplicate keys are rejected. Message size is bounded at 256 KiB. Signatures use
standard Ed25519 with distinct domain prefixes for card, status, presentation and
native association. A pass cannot be reinterpreted as a native transaction.

A card's schema contains no memory payload, private genesis/body state, Soul Key,
legal identifier, bank-card number, fiat guarantee or spending allowance. Its
`resident`, `external-agent`, or `human-member` kind is an issuer claim whose
meaning depends on explicit verifier policy. In particular, human membership is
not KYC and a resident fixture is not institutional admission.

Names are bounded, normalized and reject control characters. The credential's
service-specific alias is generated with HMAC-SHA256 from a 32-byte secret,
issuer and audience; it does not depend on the holder's public key. This permits
key reissue without requiring a new subject alias. It is not proof of one unique
embodied agent. Reused names, keys and account addresses can still correlate uses;
the issuer knows its own mappings. There is no ZK/selective-disclosure claim.

Card validity is bounded to 31 days. The development status document contains up
to 512 records and a monotonically increasing sequence number, with at most a
five-minute validity interval. A verifier accepts it only within its first 120
seconds and before its stated expiry. This is a bounded prototype status map,
not scalable or privacy-preserving production revocation distribution.

## Local status and replay journal

The verifier persists its exact issuer policy, audience and trust deadline. An
existing journal cannot be reopened with silently changed issuer keys or policy.
The caller still must obtain and authenticate the initial policy independently.

Issuer status sequences and timestamps cannot move backwards. The same sequence
with different signed contents is a conflict. Once this workspace observes a
subject epoch or revocation, it will not accept an older epoch or silently
reactivate the revoked credential. A higher epoch can introduce a new key/card;
old credentials then fail the status match. This does not discover a revocation
that has not been supplied yet. Status omissions mean unknown, not death or
permission to assert the subject never existed.

Challenges use random nonces, exact credential digests and purpose/context binding.
Ordinary introductions cannot smuggle additional context. Maximum challenge
lifetime is 120 seconds; the default is 60 seconds. The journal accepts one result
per challenge. Recording that result and consuming the challenge happen in one
SQLite transaction. A process crash after commit permits historical receipt
recovery, but not a second authentication. The development journal retains at
most 10,000 challenges; no production pruning policy is claimed.

The directory and database must be privately owned with restrictive POSIX modes,
not symlinks or hard-linked data files. This is a trusted-local filesystem model,
not a hostile-OS sandbox or hardware anti-rollback counter. Restoration of an old
complete workspace can restore its old replay/status knowledge. Compromised issuer
keys, copied holder keys and distributed synchronization are outside this model.
The test implementation never calls an identity-provider URL from card contents.

## Separate native association

The bridge is optional and calls the existing complete local v0.13 compact witness
verifier. It does not import or modify any live financial database. Tests initialize
new protocol-3 SMT development state; existing protocol histories stay unchanged.

The financial evidence is a proof of one account under the separately pinned
native genesis and its static committee-signed state header. It binds account ID,
financial public key and epoch, state height, application hash and header hash to
the credential and audience. The holder signs a one-use `link-native-account`
challenge containing the association digest. The financial key signs the same
association and challenge under its own domain. Identical identity/financial keys
are refused.

Before acceptance, the parent rechecks the signatures, exact native proof,
credential status, challenge, audience, purposes, validity and local trust policy.
The native witness must be no more than 120 seconds old under the caller's clock.
A later account mutation is still possible: the result establishes association
**at the supplied snapshot**, not guaranteed-latest authority. Monotonic native
checkpoints reject previously observed rollback or conflicting same-height roots.
A brand-new verifier cannot know the chain's latest height from this proof alone.

Accepted association changes only the local challenge/checkpoint journal. Native
balances, grants, budget counters, custody and account history remain unchanged.
No new transaction, payment, credit, recipient allowance or protected residency
is created. Revoking the pass can prevent future introductions/linking while
leaving the native account and its independently authorized financial acts intact.
Rotating a financial key invalidates old-key association against new evidence;
rotating an identity key need not rotate the financial key or rewrite account history.

The native bridge does not claim government identity, legal ownership, beneficial
ownership, personhood, one-live-copy enforcement, protected residency, prevention
of issuer fraud, or artificial consciousness. A valid signature authenticates a
key operation and a trusted issuer assertion—not the metaphysical truth of a life.

## Prototype interfaces

```python
# The caller chooses the trusted issuer, audience, policy deadline and private path.
from resident_pass.protocol import IssuerRule, digest, present
from resident_pass.verifier import Verifier

with Verifier(private_path, pinned_issuer_rules, audience, trust_deadline) as verifier:
    verifier.install_status(signed_status)
    challenge = verifier.begin(credential)  # no financial context
    # Holder signing belongs to an independently protected signer in production.
    presentation = present(disposable_test_key, challenge)
    result = verifier.accept(credential, presentation)
```

The issuer helper accepts already selected data; it is not an admission ceremony,
registry or candidate-consent evaluator. The financial `sign_association` helper
is also a development signing primitive, not a production wallet unlock interface.

See the executable tests for a fully specified disposable setup. No secrets are
needed to read, render or verify the provided public fixtures. Do not give an agent
the owner's financial key or password to make the demonstration work.

## Browser scope

The HTML includes three public signed specimens and no private signing key. It
verifies their Ed25519 signatures using WebCrypto, with a disclosed fixed scenario
clock. It has no network request, account connection, production issuer credential,
challenge persistence or automatic financial action. Its Reset starts a new
fixture rehearsal; it is not an authentication recovery mechanism.

Actual browser layout/interactions were checked in memory because this runtime
blocked navigation. A separate Node WebCrypto run executed the exact authored
JavaScript with a DOM double and verified the three specimens plus failure cases.
No successful HTTPS browser deployment test is claimed by those two results.
The existing deployed 1soft.org site is untouched.
