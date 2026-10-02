# P4 owner key replacement

> Implement in the isolated device-transition branch. Preserve all previous
> source receipts and use proportionate current-source verification.

## Contract and completion condition

Replace an available owner key using existing native `rotate_key` rules. Keep the
account identity and payment history. Require explicit incoming-key consent and
separate owner approval of the exact body. Do not invent recovery authority for
someone who has lost every copy of the old key.

Use the canonical wallet `decisions` table and owner nonce lane. A new exact
rotation review carries the fee-only hold and no shared budget. No new financial
journal, SQL schema, native protocol, or transfer-review bytes. Pending rotation
quiesces new payer payments and original payment submission. Already signed
payments and consumed submission attempts remain intact. Only exact positive
execution proof retires the rotation hold. Expiry, revocation, absence and a new
owner key never retire uncertain payment holds.

`prepare_rotation` produces an unsigned exact review. `accept_rotation` verifies
that review before opening the incoming vault and returns full-intent consent
without reserving funds. `approve_rotation` verifies accepted review and current
wallet state before opening the old owner vault, then commits the original signed
wire and fee hold before returning. Existing `approve` remains transfer-only.
Explicit existing P4 delivery confirmation and one-shot claim apply to rotation.

`rotation_status` audits the original decision, verifies fresh extending evidence
and requires the exact successful receipt. It distinguishes historical rotation
from the current checkpoint owner and original grant epochs. Later key reuse
must not become a permanent device-fencing claim. Latestness, hardware/device
erasure and recovery-archive activation remain false.

The dedicated offline CLI requires a terminal with echo disabled for vault
passwords, bounded no-symlink inputs, private exclusive outputs and recovery of
the original wire after a lost post-commit output. No implicit network calls.

Completion: behavior and regression tests, independent diff review, necessary
integration checks, a draft stacked PR and a mode-preserving source/evidence ZIP
with exact failures and remaining limits. No Actions, paid/public compute,
installs, public deployment, DNS/site changes, other project work, real funds,
production keys, force pushes or merges.

## Implementation checklist

- [x] Meaningful failing tests: fee hold/nonce, consent and vault roles, stale
  confirmation, payer quiescence and preserved uncertain grant payments.
- [x] Add exact global review dispatch and wallet prepare/accept/approve APIs;
  audit stored rotation using original proof and signing time.
- [x] Add delivery quiescence and positive checkpoint rotation report, including
  later rotation back to the old key and original-epoch grant scope.
- [x] Add explicit terminal-safe CLI and tests for secret/output failure paths.
- [ ] Verify custody archive interoperability and legacy fail-closed behavior.
- [ ] Run bounded current-source suites and independent review; fix findings.
- [ ] Publish supported draft PR and sanitized mode-preserving return package.

## Evidence scope

Synthetic committee fixtures exercise real native/application rules and signed
proof verification; they are not independent operators or real-engine results.
Prior engine receipts remain attached to their original source. Run a new local
engine qualification only through an already installed pinned binary if the
feature requires it, and report its actual scope separately.
