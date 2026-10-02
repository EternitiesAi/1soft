# Local developer release architecture

The native Protocol 4 Layer 1 remains the foundation. This additive package
connects the existing cryptographic wallet, delivery, read store, explorer and
portable receipts to one local startup path and a browser workflow. It introduces
no new monetary journal or consensus rule. The 421-file parent is pinned at
`e1c53b1dade261625e581415501b1f04ae9e6a9d`; qualification checks its complete
membership, Git blobs, modes and SHA256 bytes rather than trusting ancestry alone.

## Intent, authority and evidence

| Component | Owns | Does not establish |
| --- | --- | --- |
| `payment_requests` | Canonical unsigned requests and one immutable review/decision binding | Merchant identity, signature, spending authority or execution |
| Existing `P4Wallet` | The sole signature/reservation journal for all selected local roles | Latest network state or global coordination of copied journals |
| Existing `P4Delivery` | One durable submission claim and collected exact receipt | Execution from endpoint admission, retries or hold retirement |
| Existing `P4ReadStore` / explorer | Reverified public ledger observations | Wallet headroom or permission to spend |
| Existing capsule/archive | Content-addressed full evidence under the original external policy | New trust, cancellation, refunds or release of a hold |
| `local_devnet` | Private development setup and handles for its four validators/apps | Public deployment, independent operators or production security |

Preparing a payment does not bind or reserve it. Approval compares the current
wallet review and the selected request before durably binding the decision ID;
key access occurs only after this correlation and the wallet's own locked checks.
The wallet commits the original signed wire before return. A failed return is
recovered by the same request/decision ID. A request's original bound review is
never replaced automatically, including after an unsuccessful unlock. If it later
becomes stale, the desk retains it for inspection instead of declaring that a new
signature or request is safe.

Signing and submission require separate exact confirmations. Submission commits
its one attempt before key-free network I/O. Collection and wallet reconciliation
are also separate. Receipt collection and archive retention do not release a
reservation. No cross-database/network atomicity or globally exactly-once payment
claim is made. Positive execution requires the original signed wire and complete
P4 block/header replay, including dynamic validator changes.

## Browser and host boundary

The HTTP server binds literal `127.0.0.1`, checks exact Host/Origin/Fetch metadata,
requires a per-process CSRF confirmation for every POST, rejects duplicate fields
and unknown routes, and bounds body/response work. GET has no financial mutation
or network collection. Assets are local, with restrictive CSP, no CORS, no
analytics and no remote fonts or scripts. User values enter the DOM as text.

Native atomic amounts stay exact decimal strings. Review JSON travels as opaque
canonical text with an exact digest, so the browser does not round/reconstruct a
signed body. Roles, encrypted vault filenames, external genesis/policy and endpoint
are chosen in the private operator-created workspace, never by browser input.
The service has no governance signing route. Unlock passwords are transient and
excluded from arguments, environment, persisted journals and logs. Python/HTTP
memory erasure and hostile local users/OS compromise are outside qualification.

## Network lifecycle and recovery

Initialization creates only a valueless development genesis and encrypted keys in
a new private POSIX workspace. The exact installed engine version and SHA256 are
checked before execution. Four validator homes and four P4 applications use
loopback RPC/P2P and private ABCI sockets. Setup uses three original signed native
operations only before the canonical wallet exists; original setup wires and
one-attempt claims are retained if interrupted, never automatically resent.

An exclusive workspace lock is inherited by the owned children. A foreground
owner cannot start another copy over live children. Graceful shutdown stops
validators before their applications, closes SQLite and removes only the
application server's owned socket through its existing cleanup. Unknown sockets,
modified configuration, partial first journal creation or unexpected ownership
are refused and retained for diagnosis. There is no process-name kill, automatic
repair, reset, new trust anchor or private-data cleanup command.

Reopening a completed workspace keeps its node databases, private vaults, exact
configuration, first-header policy, original signatures, attempts and receipts.
The actual product/CLI gates test both reconciled payments and an unresolved
signed obligation across cold restart. Parent termination/orphan diagnosis and
interruption during the first multi-journal creation are not qualified by those
ordinary restart tests. The existing actual bootstrap-after-turnover and
Commit-reply-loss gates remain separate node recovery evidence.

## Qualification and limits

`1soft.py qualify` checks exact clean source before/after each isolated gate,
all inherited byte/mode pins, installed dependencies, complete test identities
and official offline Go compatibility. It executes actual local consensus and
the native payment/receipt/recovery paths. Fixture committee signatures in the
component tests remain explicitly synthetic; the real-engine gates are separate.
Self-review is not independent review. API acceptance does not prove rendering,
mobile accessibility, human feel, independent validator hosts or public custody.

The release retains the 64-block RPC/512-block offline proof limits, fixed trust
deadline, existing wallet/delivery/storage capacities and no-eviction rules.
Unavailable evidence stays unknown; no missing result becomes unpaid, absent or
retryable. Production economics, public infrastructure, long-running proofs,
post-expiry archival verification and cross-device coordination remain unassessed.
No Actions, paid compute, public deployment, website/DNS change, other-project
mutation, real funds, production keys, force-push or remote merge is part of this
local developer release.
