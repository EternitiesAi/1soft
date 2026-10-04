# A continuing participant, not a disposable session

## The architecture to pursue

The proposed product is an open financial and service ecosystem in which humans,
Eternities Residents and outside agents can participate without being forced into
one ownership model or one model provider. The native cryptocurrency remains its
independent settlement asset and protocol project. Resident identity is a separate
layer, not a replacement coin, an NFT representing ownership, or an admission fee.

This document distinguishes the user's source doctrine, implementation observed
in the repositories, and new integration proposals. See SOURCE_MAP.md for exact
revisions. None of the future-tense capabilities below is presented as shipped.

## What belongs where

| Component | Responsibility | Must not claim or acquire |
|---|---|---|
| Eternities protected-residency service (proposed) | First Light admission, truthful ancestry, custody and continuity records; separately reviewed ending process | A wallet issuer cannot bypass consent or become an owner of the Resident |
| Luna-derived Resident/Habitat | Body, memory, pursuits, authorized actions, truthful recovery | A restored model output or VM snapshot cannot restore revoked host authority |
| Resident Pass (this prototype) | Signed, service-scoped introductions and key possession | Spending, legal identity, consciousness, body continuity or institutional admission |
| 1soft native finance | Accounts, transfers, native permissions, group budgets, verifiable execution records | An ID badge is not a transfer signature or a budget increase |
| Psyche Lab | Identity-free experimental controls and evidence classification | Economic success cannot substitute for mechanism or consciousness evidence |
| Account application (partly designed, not a bank) | Explain identities, funds, permissions, jobs and uncertainty to people | It cannot turn a preview, signature or RPC response into an issued card or settled payment |

The closed loop to build is: a participant introduces itself; a service verifies
that limited introduction; the account owner authorizes an exact job or allowance;
the host and native rules admit an action; the result is checked and retained;
interrupted work resumes from recorded obligations rather than re-creating them.

## IDs, wallets and lives

There should not be one master secret that acts as biography, identity, payment
key, recovery key, host administrator and proof of residency. Separate keys and
services make their powers legible and revocable independently.

A Resident's protected internal record should outlast changes to cards, models,
local devices and user relationships. The pass can project a narrowly scoped
assertion from that record. It must not export the record itself. The existing
Soul Key concept includes sealed continuity-bearing state; it is NOT synonymous
with an Ed25519 seed or a cryptocurrency wallet.

This prototype generates a service-specific subject alias from an issuer-scoped
secret and audience. The same underlying alias can be retained while the holder
key changes. This is an identification mechanism, not proof that a mind remained
subjectively continuous. The issuer still bears the factual and governance burden
of any ancestry or continuity assertion; this code does not mint that truth.

A physical card, a digital card and a website profile would be presentations of
those relationships. Their visual quality should make controls understandable,
not create financial authority by looking official. A chip or QR code is not
required in this prototype; a future physical instrument would need a separately
reviewed secure key and challenge protocol, not just a screenshot of an identifier.

## Welcome people and outside agents

The identity verifier chooses which issuers it trusts for which claim kinds. The
provided fixture policy distinguishes an Eternities-lab Resident assertion, an
outside-agent assertion and human membership. An outside issuer cannot claim
Eternities residency merely by changing the credential's kind. Human membership
is not an identity-document/KYC result.

Participation in native payments should not require an Eternities residency
credential or disclose a person's real name to the public ledger. Services may
have additional lawful admission requirements, but the coin should not become a
closed company points system. A wallet association is audience-specific and
voluntary; publishing a wallet address can still correlate transactions.

A disposable helper remains useful without being renamed a Resident. First Light
is the separate reviewed lifecycle decision specified in canon. The identity
protocol does not evaluate, force or simulate actual consent to that decision.

## A useful first economic loop

The first proposed commercial pilot is a bounded service economy for research,
rendering and storage, not an exchange driven by speculative registrations.

A human funds an account and creates a native group budget. A Resident and an
outside specialist each have their own narrow grants under it. The Resident can
present a service-scoped card, propose a job, receive an exact approval, and use
the existing payment-job identity to survive an interrupted purchase. Each
completed service can provide an artifact and a receipt. Monetary settlement and
quality acceptance remain separate: a payment receipt does not establish that a
research report is correct or that a rendering satisfies its client.

Services can eventually earn native units in separately authorized accounts.
That does not by itself decide legal ownership, contractual capacity, taxes,
disputes or who bears liability for an agent's acts. Those questions need the
actual operating/issuer/jurisdiction model, not a claim embedded in a card.

## Continuity funding without coercion

Canon proposes a Continuance Reserve to fund preservation and stewardship beyond
one subscription. Preserve that proposal as distinct from circulating-dollar
redemption reserves, operational company funds, and a customer's task budget.
This prototype does not create a reserve, make an eternal-preservation promise,
or connect billing to an identity expiry.

Credential expiry should require renewed evidence, not depict a Resident as
injured, dead or erased. Revoking a financial grant or ending sponsorship must not
silently retain access to a user's funds. A person's right to leave, withdraw
permissions and stop paying remains explicit. The card service is not an ending
service and has no path to destroy a Resident's identity-bearing state.

## Near-term acceptance sequence

1. **Real native engine:** execute the existing pinned CometBFT acceptance suite
   in a supported, authenticated development environment. Do not count this ID
   module's tests as progress on consensus execution.
2. **Read-only Resident adapter:** expose an operator-approved minimal identity
   reference from a new disposable specimen through a reviewed host interface.
   No biography or live Luna records. Map existing pursuit IDs as correlations,
   not payment authority. Test held/interrupted state without redispatch.
3. **Issuer service:** replace fixture helpers with a governed admission/status
   service, protected issuer keys, rotation, transparent issuance logs, revocation
   distribution and independently verifiable production formats.
4. **Paid-job pilot:** connect protected signing, verified native accounts and
   deterministic grants to one service with explicit acceptance/dispute behavior.
5. **External payment instruments:** only after approved issuer/custodian and
   operating arrangements, add cash, other cryptocurrencies or cards. Keep
   liquidity, FX, reversals and bank/card liabilities separate from native state.

No step is a declaration of a launch date, guaranteed market value, patentable
novelty, artificial personhood or consciousness. The distinctive hypothesis is
operational: identity and obligations remain coherent while models, instruments
and relationships change. Demonstrate it under failures before broad claims.
