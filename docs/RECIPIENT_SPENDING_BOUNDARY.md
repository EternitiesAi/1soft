# Next native value-transfer boundary

The highest-value next native step is recipient-controlled spending of payment
proceeds. A useful cryptocurrency needs a recipient to receive value, retain it
safely, and later spend it. The merchant adapter proves a certified purchase and
retains a resource result; it does not yet implement that recipient spend.

## Exact current domains

Verified directly in tools/owner-treasury-lab/halo2/src/relation.rs:308-393:

| Domain | Current purpose |
|---|---|
|600|restricted input and CHANGE-note commitment|
|601|note-tree leaf hash|
|602|note-tree internal node hash|
|603|restricted input value nullifier|
|604|merchant payment-note commitment|

This corrects the domain labels in an earlier proposal/summary:602 is not the
ordinary note commitment and603 is not a CHANGE commitment. Preserve the older
packet as historical proposal evidence; use the actual native source for design.

`input_note` reconstructs a domain600 restricted note for the agent key. CHANGE
`p23` uses that same note schema. Merchant `p22` uses a different domain604 schema:
network/asset/mission, original request, issuer generation/owner epoch, expiry,
amount, recipient field, secret and blind. State appends both to the note list,
but inclusion in the pool does not establish a supported spend relation.

The issuer's agent secret, input nullifier and owner/grant authority are not the
merchant's ownership credentials. The current quoted recipient field is not an
authenticated identity or proven spending-key commitment. Synthetic fixture
recipient fields must not be reinterpreted as production ownership keys.

## Proposed successor design, not implemented

Design a separately versioned profile/state/client boundary, provisionally P8.
Keep the P7 profile/VK, wire schemas, historical replay and old receipts intact.
Do not add a permissive domain selector to P7 or silently transform a merchant
receipt into a restricted input.

1. Specify recipient-controlled ownership. New payment outputs need an explicit
   versioned recipient-key commitment or equivalent defined authorization
   relation. Distinguish identity, possession and task spending authority.
2. Specify a typed merchant-input opening. Retain original issuer request,
   generation and owner epoch as origin metadata, distinct from the recipient's
   current owner/grant lanes and new payment intent. Bind network/asset/mission,
   amount/expiry, exact pool membership and recipient authorization.
3. Define a separate redemption nullifier that binds exact note and recipient
   authority. It must prevent double spend across restarts and competing paths
   without reusing issuer input/authority nullifiers accidentally.
4. Prove conservation: a consumed payment note funds exactly the recipient's
   valid next outputs and fee. Define expiry/refund semantics explicitly; do not
   infer a refund authority merely because a payment note expires.
5. Implement encrypted recipient custody and durable prepared intent through the
   same exact-wire/certificate/no-automatic-retry discipline. Private note secret
   or blind possession alone must not silently become an identity claim.
6. Qualify the relation, range/nonzero/domain guards, profile/params/VK, prover,
   verifier-only worker, native state replay, and actual wallet/merchant callers.
   Require fresh four-validator tests for valid spend, unauthorized recipient,
   wrong origin/request/asset/epoch, overflow/conservation, replay/duplicate,
   expiry, lost acknowledgement, cold recovery and authenticated restart.

Migration of existing P7 merchant notes is a distinct decision and proof gate.
New successor payments with authenticated recipient commitments are the cleaner
initial scope; no conversion of old arbitrary recipient fields is presumed.

This remains a proposal. It establishes no production privacy, global settlement,
public launch, external audit, investment value or novelty. Scalable history,
independent operators, key recovery, economics/governance and public release
authorization remain separate from implementing a typed native transfer.
