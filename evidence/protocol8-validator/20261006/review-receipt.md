# P8 source review receipt

Two built-in AI peers reviewed source read-only. They did not run proofs, modify
code, use paid workers or inspect other projects. This is source review, not
specialist external cryptographic certification or actual execution evidence.

Reviewed committed source: 85ed46ed3c28855178544ffc21cde66ea33fcbc3.

Authority review checked the acyclic bootstrap/full-genesis distinction, P8-only
schema/domains, ordered replay, nonreserving admission, atomic checkpoint/block
commit, retained-response restart audit and signed H+1 state authentication.
It requested explicit behavior on unavailable verification and malformed state.
The final source validates malformed state and tests the private server's
quarantine/no-commit behavior separately from ordinary invalid-proof refusals.
The final reviewer found no concrete remaining defect in the runner/checker and
15-method unit coverage.

Native review checked measured opened-inode execution, empty environment,
bounded resource/reply/process cleanup, cache remeasurement, network pins,
separate fixture/prover feature mode and worker receipt counters. It initially
reported the earlier one-signature mutation; an exact live reread confirmed
the committed version corrupts two distinct non-nil voting signatures and the
old finding was withdrawn. No further definite defect was reported.

Cargo resolution was captured separately: recipient-consensus-bridge and
recipient-transfer resolve with no features in the verifier build. Opaque
binary feature exclusion is not inferred from a receipt string alone; the
source, separate build command, dependency resolution and executable digest
are the supporting evidence.

Actual qualification and separate public replay are recorded independently
in their raw logs/reports. Read this receipt alongside those artifacts.

The authority peer subsequently audited the exported completed evidence: 19
passed checks, five native proofs, 11 fixture/prover processes, 22 app/engine
lifecycles, 994 verifier calls reaped and AS-OF state height 3/header height 4.
It found no evidence inconsistency. Exact re-inventory corrected an assumed
P7 commands artifact: P8 has exactly 14 artifacts (four app logs, four engine
logs, five wires and genesis), with matching membership, sizes and SHA-256.
Separate public replay returned qualified=true and reaped 20 native processes.
