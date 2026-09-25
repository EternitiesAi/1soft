# Agent cards, cash and multiple cryptocurrencies

Architecture proposal · 24 September 2026 · No issuing, conversion or banking integration has been activated.

## Partner-issued cards are a real route

Visa's 3 March 2026 announcement describes Bridge-enabled stablecoin-linked cards and Lead Bank's participation. It also describes further support being evaluated. This establishes a relevant integration route, not automatic acceptance of a new Eternities coin, chain or card program. [Primary announcement](https://usa.visa.com/about-visa/newsroom/press-releases.releaseId.22206.html).

The proposed product assigns each agent a scoped virtual payment instrument under an appropriately established human or organizational account. Physical cards could be added where the issuer's approved use case supports them. The agent label does not create a legal cardholder or change who owes liabilities. Program type—debit, prepaid, commercial or another approved structure—must be explicit.

The partner stack needs issuer/bank arrangements, card processing, network permissions, responsible account holders, onboarding, fraud and dispute operations, compliance review and contractual liability allocation. No partner has agreed to provide these services here.

## Chime is an experience reference, not a license model to assume

Chime describes itself as a fintech company with banking services and cards provided by partner banks. Its own name is not an FDIC-insured bank. This is a relevant example of separating a product interface from its regulated providers. [Chime's explanation](https://help.chime.com/is-chime-a-bank-b88da701).

We should build an original interface rather than copy proprietary screens or decompile a banking client unnecessarily. An APK would not by itself supply the private server-side ledger, banking arrangements or security operations needed for this project. No APK was downloaded or decompiled in this work.

## A realistic crypto-to-card flow

Crypto.com's documented prepaid-card auto-top-up converts a selected cryptocurrency into the card's eligible fiat currency before loading it. That is different from every merchant receiving the original crypto. [Provider documentation, updated 18 June 2026](https://help.crypto.com/en/articles/6366591-crypto-com-prepaid-card-auto-top-up).

Proposed flow: identify the source asset and network; establish confirmed usable custody or inventory; obtain a firm quote that binds fees, source amount, destination amount and expiry; obtain consent or validate a previously approved conversion mandate; reserve the source; execute once; reconcile; fund the approved spending balance. Do not automatically sell a person's BTC simply because a price estimate appears in the interface.

At checkout, use prefunded liquidity or another explicitly underwritten, approved funding arrangement. Do not require an unpredictable external-chain confirmation or a language-model response inside a card authorization deadline. Failed conversion must not cause silent asset substitution or automatic borrowing.

Native BTC, ETH, SOL and LTC stay on their respective networks unless an explicit conversion, custodial representation or bridge is used. A wrapped claim is not automatically equivalent to native custody. Display asset, network, issuer/custodian, pending status and withdrawal constraints separately. Prefer a supported conversion route over inventing a bridge before it is necessary.

Bank transfers, ATM access and physical cash deposit locations are separate services with their own partners and terms. A Visa card does not automatically provide all of them. Availability, settlement times and geographical scope require verification before offering them.

## Card semantics cannot be flattened into blockchain finality

Stripe documents a two-second response window for its synchronous issuing authorization webhook. Fallback configurations can approve or decline. It also describes cases where a network approves despite a Stripe decline and a capture later occurs. [Real-time authorization documentation](https://docs.stripe.com/issuing/controls/real-time-authorizations).

Therefore the proposed system needs separate states for local consent, authorization, hold, capture, reversal, refund, dispute and unresolved evidence. Set conservative fallback rules where supported, but do not advertise an unconditional cross-network spending guarantee. Reconcile provider records and account for late or excessive presentment even when it violates local expectations.

The prototype models a final aggregate capture and records excess/late capture as an explicit liability exception. It freezes new fixture reservations for that owner while the liability remains unresolved. It does not implement real issuer authentication, multiple/incremental captures, clearing files, chargebacks or a complete debt-resolution process. A provider name string is not authenticated evidence.

Card credentials should be protected through issuer-supported tokenization and a controlled execution service. The language model should receive opaque instrument references, not unrestricted card data. Never place primary account numbers, security codes or raw bank credentials in public blockchain records or prompts.

## Refunds, conversion and records

A refund is credited in the settlement asset according to the real payment agreement. It does not silently rebuy the originally sold crypto at a new price. Uncertain payments remain reserved until reconciled; a timeout alone is not proof of nonpayment.

The IRS describes digital-asset dispositions and related recordkeeping obligations. The product should preserve timestamps, units, execution prices, costs, fees and receipts rather than present conversions as economically invisible. User-specific tax treatment requires qualified advice. [IRS digital assets guidance](https://www.irs.gov/filing/digital-assets).

## Acceptance criteria for a partner pilot

The same purchase identity must survive provider timeouts and retries. Duplicate events must not duplicate money. Authenticated evidence must bind the actual recipient, asset and amount. An unknown result must not trigger a second payment through a different route. A native authorization and a card liability must be separately distinguishable. Conversion and card funding failures must have tested compensating/reconciliation paths. Customer statements must reconcile to provider statements and custody—not merely to our own balanced database.
