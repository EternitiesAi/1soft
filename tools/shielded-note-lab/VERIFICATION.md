# Shielded-note laboratory verification

The component verifier is an exact-source gate for this isolated model. It must run from a clean candidate commit and refuses success unless all of these conditions hold:

- every component file except the root manifest is listed once with its byte count and SHA-256 digest;
- the manifest's full test-ID inventory exactly matches discovery;
- no component symlink, `__pycache__` directory or `.pyc` file exists;
- the running Python version satisfies the declared minimum and the installed `cryptography` version matches both the repository pin and component dependency record;
- the repository commit and tree are valid, clean and unchanged before and after execution;
- every discovered test passes with no skip, expected failure or unexpected success;
- the required network-refusal test makes a blocked attempt;
- a Python child DNS probe is refused before child user code can use the network;
- an optional report is written outside the repository through exclusive no-clobber publication.

The offline policy covers Python socket and DNS APIs in the verifier process and Python children. Non-Python children and direct Python `os` spawn/exec entrypoints are refused during the suite. This policy does not claim an operating-system network namespace or resistance to malicious native code.

The adversarial suite freezes commitment, tree and nullifier vectors and exercises opening, secret, membership, position, signer, signature, domain, root, output order, conservation, bounds, capacity, expiry, replay, competing-spend, failed-state, export/reopen, lost-reply, disclosure, public-secret scan, subprocess determinism and offline-policy behavior.

A passed receipt always preserves these false claims:

- `production_privacy`
- `zero_knowledge`
- `consensus_integrated`
- `public_network`
- `real_funds`

Independent cryptographic review, consensus integration, network anonymity, production custody and external audit remain unassessed. Public reopen validates the retained public transcript; it does not re-prove the absent private witness. The wider repository current checker treats a missing, stale, source-mismatched or overstated verifier receipt as a failed local qualification.
