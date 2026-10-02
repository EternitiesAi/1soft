# Targeted source review / continuation

24 September 2026. These are static component inspections, not whole-repository audits, node executions, consensus comparisons or proofs of security. No upstream cryptocurrency or MetaMask code was copied into the original models in this package. Blob identifiers identify the returned file content; default-branch reads are not a release dependency lock.

## Newly inspected components

| Project | Actual file and inspected range | Revision evidence | Observation and proposed use |
|---|---|---|---|
| Solana / Agave | `svm/src/transaction_processor.rs`, lines 620–790 | Blob `c3cdf522d4036f65d3ccca940b82837a70116c9f`; default `master` read | Successful execution and failed execution have distinct account-update paths. Failures can retain rollback fee/nonce effects, depending on configuration. Learn explicit failure semantics, not an unsupported speed claim. |
| XRP Ledger / rippled | `src/libxrpl/tx/transactors/payment/Payment.cpp`, lines 50–185 | Commit `30640a626fe8727974cf0a5afa69e89a5abe58c7`; blob `d2da1733451eb6548d3bd794e632c840a63cb70b` | Source maximum, destination amount, partial-payment flags and legal amount checks are separate concepts. A requested amount is not automatically delivered value. |
| Verge | `src/stealth.cpp`, lines 1–170 | Blob `8d55b3b993ef234730053c88993b2a4c7e2525c4`; default `master` read | Encoding separates scan and spend public keys and checks encoded data. This is an address-level implementation excerpt, not a verification of complete privacy or Wraith's end-to-end guarantees. |
| Proton / XPR Network | `contracts/eosio.msig/src/eosio.msig.cpp`, lines 1–160 | Commit `a3d9f9384a710dc8502dbf3c4e4f4b813b5ecb2a`; blob `99d706d1ecc190aed0ac602948185796a294339a` | Permission-level approvals, proposal expiry, optional proposal-hash checking and invalidation of old approvals. Learn exact authority boundaries, not automatic identity trust. |
| MetaMask Core | `packages/approval-controller/src/ApprovalController.ts`, lines 1–170 | Blob `73cf15154bee88493d68b961ac4671535f27bf37`; default `main` read | Pending approval UI state is marked nonpersistent. Keep a persistent financial obligation journal separate from transient approval UI. This does not assert that MetaMask discards settled transactions. |

The outdated rippled path `src/xrpld/app/tx/detail/Payment.cpp` returned 404. Repository code search located the actual path above. A guessed top-level MetaMask `LICENSE` path also returned 404; licensing clearance is still pending, not inferred from file availability.

## Prior inspection, retained as context

The preceding package recorded these files; they were not all fetched again during this continuation:

| Project | Previously inspected component | Blob | Design lesson |
|---|---|---|---|
| Litecoin | `src/consensus/tx_check.cpp` | `88bca494d78e58f585efc5fd77c80ef5bfa0e16f` | Monetary bounds and duplicate-input checks. |
| Stellar | `src/transactions/BeginSponsoringFutureReservesOpFrame.cpp` | `7d47be534bb2ffdf6e3be133d6785f6afe39f97e` | Explicit ledger-reserve sponsorship and recursion constraints. Not fiat reserve backing. |
| Cosmos SDK | `x/bank/types/send_authorization.go` | `d0357c6c21271fd50ce8966715afdff8c1d58828` | Remaining allowances and recipient controls; empty allowlists need careful interpretation. |
| Tempo | `crates/precompiles/src/account_keychain/mod.rs` | `0c5bcc03c386742fc12f4d8ac51220835ecd8987` | Scoped access keys, expiry and spending limits are existing prior art. |
| x402 | `typescript/packages/core/src/client/x402Client.ts` | `544aaa1c7cd8cfcb593f5df765d3860af193bcb3` | Client policies and hooks complement, but do not replace, an enforced signer boundary. |

The previous private-project references were Eternities canon Founder 09 at commit `0375a4fcbec79303ad41d60ee39f9a669aad3516`, and Luna2 pursuit/executive code at `35eea0ddc167e92768e38999b30dc5f2cb1dc71b`. Their conceptual continuity and interrupted-work patterns informed this proposal. Those repositories were not modified, and their complete tests were not rerun here.

## Source entry points

- [Agave transaction processor](https://github.com/anza-xyz/agave/blob/master/svm/src/transaction_processor.rs)
- [Pinned rippled payment code](https://github.com/XRPLF/rippled/blob/30640a626fe8727974cf0a5afa69e89a5abe58c7/src/libxrpl/tx/transactors/payment/Payment.cpp)
- [XRPL payment metadata](https://xrpl.org/docs/references/protocol/transactions/metadata)
- [Verge stealth-address implementation](https://github.com/vergecurrency/verge/blob/master/src/stealth.cpp)
- [Pinned XPR multisig implementation](https://github.com/XPRNetwork/proton.contracts/blob/a3d9f9384a710dc8502dbf3c4e4f4b813b5ecb2a/contracts/eosio.msig/src/eosio.msig.cpp)
- [MetaMask approval controller](https://github.com/MetaMask/core/blob/main/packages/approval-controller/src/ApprovalController.ts)
- [Litecoin](https://github.com/litecoin-project/litecoin)
- [Stellar Core](https://github.com/stellar/stellar-core)
- [Cosmos SDK](https://github.com/cosmos/cosmos-sdk)
- [Tempo](https://github.com/tempoxyz/tempo)

## Selection discipline

Do not combine incompatible consensus engines and claim the inherited security of all of them. Choose one coherent foundation after pinning a supported version, completing license/dependency review, building reproducibly and testing the same workloads and faults. Cosmos SDK/CometBFT and a coherent Tempo/EVM-derived approach remain comparison candidates, not decisions or tested performance winners.

Forking any chain does not inherit its validators, mining work, liquidity, issuers, exchange support or users. The independent network must establish its own operating and security assumptions.

No Chime APK was acquired or decompiled. Public product documentation and observed user-facing goals were sufficient for this original UI concept. No claim of novel cryptography, patentability, complete freedom to operate, audit completion or production readiness is made.


## v0.4 — CometBFT commit and block-boundary inspection

Date: 24 September 2026. Ref: `v0.38.25`. Exact source paths, observed Git blob hashes and inspected ranges are recorded in `evidence/v04/source-inspection.json`. This is a targeted review, not a complete network/implementation audit.

`types/tx.go` established that the engine budgets the protobuf `Data.txs` size. Our previous adapter counted only raw transaction bytes. The corrected calculation includes one field tag plus varint length plus payload for each transaction. Independently constructed Google-protobuf `Data` messages exercise the boundary.

`types/block.go` and `encoding_helper.go` supplied the ordered 14-leaf header-hash construction; `canonical.proto` supplied canonical vote encodings; `validator.go` and `validator_set.go` supplied validator byte representation, ordering and hash rules. The independent verifier uses Google's protobuf serializer and the existing Ed25519 implementation rather than hand-written cryptography.

`types/block_test.go` supplied the expected header hash `F740121F553B5418C3EFBD343C2DBFE9E007BB67B0D020A0741374BAB65242A4`. `types/vote_test.go` supplied five canonical vote-byte vectors. Local tests match these values. This does not establish the still-unassessed official Go codec or actual validator integration.

The source probe was expanded to nine actual-upstream checks, but dependency resolution failed before compilation. The test runner and evidence distinguish unavailable dependencies, compile/run failures, synthetic vectors and actual-network output. No upstream engine binary was obtained.

Upstream license terms and attribution for transcribed vectors are retained in `third_party/`; original project code is not automatically relicensed or declared novel.

## v0.5 implementation note

The account-onboarding, key-rotation, consent-domain, owner-scoped grant and independent-signature work is original code in this package. It is not copied from a new cryptocurrency repository. The previous upstream CometBFT source-derived vectors and component inspections remain narrow historical evidence; they do not imply that the official codec or engine executed. The current release does not claim that these feature ideas are unprecedented or patentable. See `ACCOUNT_LIFECYCLE.md` and `VERIFICATION.md` for precise behavior and limitations.
