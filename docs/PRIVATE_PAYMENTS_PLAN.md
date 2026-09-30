# Private payments foundation: authorized local implementation

30 September 2026. Dom approved beginning the product direction and two Sol 6.1
xhigh agents. Root owns integration and verification. This branch retains the
complete qualified d14165d source; all runtime changes are additive.

Completion for this slice is a working, tested local flow: exact pinned merchant
quote -> unsigned request -> separately approved existing P4 signing -> one
existing delivery attempt -> independently replayed native receipt -> durable
merchant fulfillment. Invoice descriptions/contact/content are encrypted in a
dedicated persistent store and recover after reopening without replacing keys,
requests, wires or obligations. A concrete private-ledger successor design must
identify conservation, grants/budgets, disclosures, proof collection and custody
gates. No on-chain privacy, mainnet, stablecoin support or market validation is
implied by finishing this slice.

1. Preserve current P4/core/platform bytes; add reviewed envelope and x402-v2
   development scheme with behavioral negative tests.
2. Add separate encrypted invoice storage using a dedicated software data vault;
   keep secrets out of arguments/logs and public recipient/amount consent explicit.
3. Add durable merchant recipient assignment and payment consumption. Native
   signatures do not authenticate the quote/resource: never reuse the invoice's
   recipient and never infer merchant trust from incoming wrappers. Fulfillment
   has no external side-effect callback and is distinct from wallet reconciliation.
4. Integrate trusted caller/CLI and a genuine four-validator loopback acceptance
   profile, including no-payment/unknown states and exact cold recovery.
5. Verify new components, current source inventory and the existing local release
   without weakening any gate. Record exact final source identity, sanitized
   execution logs, passes/failures/unassessed items and return source/patch evidence.

No Actions, paid/public compute, public deployment/DNS, other projects, real funds,
production keys, force push/remote merge or customer/investor/ChatGPT contact.
No acquired SDK execution, automatic signing, financial resend, trust renewal,
hold release by merchant response, reset/cleanup of existing work or new native
consensus rules. Rendered/human premium feel and public custody remain unassessed.
