# Persistent payment jobs — v0.11

A stable job identifies the continuing purchase, while a native transaction
identifies the particular signed payment. This adapter binds them once in a
private local workspace. It is not a new on-chain operation or economic policy.

Example: `atlas:order-149` remains the same job after an agent restarts, after
submission loses its response, and after the payment's receipt is verified.
Reusing that ID with another nonce, recipient, amount, fee limit, expiry, grant
or signer is refused. A different job cannot claim that same transaction or its
reserved local authority counter. A genuinely separate job may use another
counter; the caller must derive stable job IDs from its task/order system rather
than inventing a fresh ID on every retry.

## Implemented workflow

1. **Prepare.** Persist the exact unsigned native transfer, designated signer and
   job binding before asking a wallet to sign. Identical preparation retries
   return the existing job. New job preparation cannot retrospectively relabel a
   payment that was already queued outside the jobs interface.
2. **Review and sign using the existing wallet.** `signing-request` exports the
   unchanged transaction body. The job adapter has no password, vault-unlock,
   signing or automatic-submission function. Creation confers no money or authority.
3. **Attach.** Verify the supplied signature and require its exact body and signer
   to match the prepared job. The dispatcher atomically commits the envelope.
   Job status is derived from that queue: there is no separate signed-state flag
   to update afterward. An interruption after that commit recovers the original
   envelope without another signature.
4. **Send explicitly.** Dispatch requires the existing exact-byte dispatch
   confirmation, not the job's request digest. Endpoint admission, rejection and
   lost responses remain observations, not settlement. A deliberate replay uses
   the same bytes; there is no automatic payment retry.
5. **Refresh without paying again.** Use the existing read-only receipt collector
   and verifier. A verified historical receipt closes dispatch for this job.
   It never makes the ID reusable for a new payment, even after the account nonce
   advances. Export the original envelope or its verified receipt independently.

The job table lives in the dispatcher's SQLite file and shares its exclusive
POSIX process lock. It does not replace either wallet's signing journal. A crash
*before attachment* may leave a signature only in the wallet/outbox: recover it
there, then attach it. Job status cannot determine whether an external signer
has already produced a signature it never received. No distributed transaction
across the signing and dispatch databases is claimed.

## Development interface

With the already-pinned dependencies installed, run from the repository root:

```sh
PYTHONPATH=src:tests python -m unittest discover -s tests -p test_payment_jobs.py -v
```

There are 34 job tests at this checkpoint. Their source and shared dependencies
are inventoried in `PAYMENT_JOBS_MANIFEST.json` (17 files). The manifest does not
replace, reduce or complete the larger node inventory. To verify its declared
files using the existing verifier:

```sh
PYTHONPATH=scripts python -c 'from pathlib import Path; from verify_checkout import verify_checkout; r=verify_checkout(Path("."),"PAYMENT_JOBS_MANIFEST.json"); print(r); raise SystemExit(0 if r["status"]=="passed" else 1)'
```

`scripts/jobs.py` has explicit common flags for pinned genesis/digest, private
journal, literal-loopback endpoint and trust expiry. Use the same values on every
invocation. Its commands are `prepare`, `signing-request`, `attach`, `send`,
`replay`, `refresh`, `status`, `events`, `export` and `export-proof`. Each requires
`--job-id`. Preparation additionally takes `--body` and `--signer-public-key`;
attachment takes `--envelope`. Requests/exports refuse to overwrite existing
files. One terminal newline from the existing wallet export is accepted without
changing canonical transaction bytes.

An application can instead instantiate `PaymentJobs` and call its equivalent
methods. `prepare` and `status` expose explicit `signature_required`, `attempts`,
`receipt_verified`, `amount_atomic`, `fee_atomic` and status values. An exit code
of zero only means the command completed: inspect the status, not the exit code,
to decide whether payment evidence was verified. No value is presented as USD.

## Guarantees and exclusions

The job binding includes the complete native body, chosen public signer, job ID
and pinned dispatch configuration. It is a local integrity/approval reference,
not a secret, user authentication, merchant-signed invoice, or field in the coin's
native transaction. It does not prove service delivery or associate invoices
cryptographically on-chain.

The protection applies to participating processes sharing this private journal.
An agent that invents another job ID and another nonce, another device or journal,
a restored old workspace, a user signing directly, or a hostile OS can act outside
it. No exactly-once network delivery, global task deduplication, or cross-route
card/crypto budget is established. Raw wallet/dispatcher entrypoints remain
available; this wrapper is not a sandbox preventing their deliberate use.

The requested signer and amount undergo static validation, not a current-state
authorization check. Use the certificate-backed wallet and native ledger for
those separate checks. Creating multiple unsigned jobs does not reserve network
balances or grant additional spending authority. There is no job cancellation,
rebinding or recycling in this release. Failed or expired requests remain visible;
future replacement/refund flows require explicitly designed evidence and consent.

The new tables preserve existing dispatch data and reject unknown job schema
versions; no implicit wallet or chain migration occurs. Read paths recheck the
job binding and existing signature/proof. These are checks under the existing
trusted-local-filesystem assumption, not tamper-proof storage.

## Evidence and implementation scope

Tests exercise actual process termination after preparation and after queue
commit, same-job reuse across nonce changes, conflicting unsigned jobs, signature
substitution, legacy-payment relabeling, schema rejection and separate-process
CLI handoff. The complete fixture sequence uses encrypted Ed25519 signing,
loopback HTTP, real native-ledger execution, a lost response, read-only receipt
recovery and independent proof export. The committee certificates remain synthetic.
The fixture keys/password are public test material and are never production keys.

This code neither runs nor invents consensus. The native protocol and its public
monetary policy are unchanged. No Actions, DNS changes, public endpoint, paid
compute, customer funds, issuer backing, bank or card program is introduced.
