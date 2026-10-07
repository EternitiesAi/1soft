# P8 local payment caller AI source review

Root implemented the new caller. Two separate read-only AI peers reviewed the
design/source, owning distinct authority and native integration questions. Neither
edited the source, ran native gates or supplied execution evidence. AI review is
not external specialist certification or production approval. Completed actual
and replay evidence is assessed separately in `post-run-review.md`.

`/root/merchant_authority_review` accepted the wallet as monetary authority and a
separate authenticated public transport journal. It reviewed journal creation and
directory fsync before the attempt marker, exact-wire and identity binding, the
absence of resume/resend, the incomplete-record crash boundary, admission versus
execution, and suppressed private errors. It required distinct prepared/unknown
states and direct recovery linkage to the actual wire and signed witness.

`/root/merchant_native_review` reviewed the unchanged wallet/Comet integration,
CLI calls, native/process identities, exact owned proxy behavior, constructed
interruption labels and cleanup. It accepted the standalone Linux CLI's total
20-second main-thread alarm, which replaces no existing alarm. The focused slow
header test demonstrates that socket timeout alone is not the request deadline.

Actual run01 exposed an adapter error: the original stage helper also broadcasts
the initial funding fixture, before the prepared wallet payment exists. The
adapter had intercepted that fixture as a wallet caller request. That failed run
stopped its owned processes and remains failed evidence. The routing now permits
only exact `first.tx` and `executed-competing.tx` fixtures through the unchanged
real node path, and records those separately. Only the prepared wallet payment
uses the new caller/proxy. A regression detects this error. The native reviewer
accepted the strict split before fresh run02 at source
`a7dc356c640be4f001c5f5772eca35de72e1029e`.

The authority reviewer identified a closed-checker gap: repeated matching result
objects alone did not bind the claimed execution to its signed state and original
wire. Root added direct exact-receipt/height/AppHash/genesis linkage, held-input
conflict linkage, and journal envelope/hash binding before fresh run02. The native
reviewer accepted those additions. The checker verifies public consistency and
does not authenticate the journal MAC independently without external private keys.

The accepted source boundary remains one trusted Linux/WSL host, finite synthetic
funds and explicit external custody inputs. Endpoint routing is local, not node
identity authentication. Journal HMAC is not a backup rollback or hostile-user
defense. Actual marker process-kill/power-loss, production custody/privacy,
latest-state trust, independent operators/signers, scale, economics, specialist
review and public launch remain unassessed. The Alice interruption state is
constructed with a genuine encrypted-wallet marker; no process kill is claimed.
