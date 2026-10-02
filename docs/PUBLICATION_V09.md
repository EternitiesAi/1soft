# v0.9 publication and source lineage

The new transport is published in private `xnuonux/1soft` as commit
`449ab0329402d7cb4f826377368910caa6364318`, branch
`development/payment-dispatch-v09`, open pull request #2 into `main`.
It adds ten paths; no existing remote files were changed. The observed base is
`941c6241d89761f2074c121af29539c354f6cdcd`. It has not been merged.

The complete downloaded package instead descends from the previous complete
local v0.8 source (`c94d5c1`). Remote main contains a different wallet/outbox
variant. This is not a synchronization or replacement of that remote tree.
The transport consumes their common canonical exported signed transaction and
never opens either wallet's database. It has its own separate dispatch journal.

All ten required transport implementation/dependency files were compared with
GitHub blob identities and match. See evidence/v09/publication.json. That check
is source equality, not an independent audit or a full-remote-suite result.
The existing remote full-node source inventory is not shortened, and the blocked
ABCI transport remains absent remotely. No Actions workflows were introduced.

Full local tests: 498 across sixteen bounded processes. Published transport
subset: 56 of those cases. Other remote wallet tests are not added to that count.
The local commit and complete Git bundle have separate ancestry; never force-push
that full local history over main. Preserve both prior wallet implementations.
