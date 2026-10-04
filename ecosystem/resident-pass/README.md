# Resident Pass · isolated credential library

This directory adds identity verification and optional native-account association
without changing 1soft's existing monetary rules, wallet, main source manifest,
Actions settings or deployed website. It is not an issued identity product,
protected-residency service, bank card, token, or proof of consciousness.

Implemented: scoped issuer credentials, signed status, audience-specific aliases,
key epochs, durable one-use holder challenges, and an optional association requiring
a separately proven native financial key. A card does not grant spending authority.

## Run without GitHub Actions

From this directory, using Python with cryptography 46.0.4 installed:

```sh
python tools/verify.py
```

This executes 46 identity tests. The optional native integration needs the separate
**complete local v0.13 package**, not an assumed complete remote root:

```sh
python tools/verify.py --native-root /absolute/path/to/1soft-development-v0.13
```

That validates the parent's 79 required files and runs 61 add-on tests, including
15 native-association cases. It does not run the full native 705-case regression
suite or an actual consensus engine. Committee headers are synthetic signatures
over actual local application state; all identity subjects are invented fixtures.

Read `docs/ARCHITECTURE.md`, `docs/RESIDENT_PASS.md` and `docs/VERIFICATION.md`.
The complete downloadable Resident Pass package in the project conversation also
contains the interface template, self-contained HTML preview, preview builders,
Node/browser checks, source map, captured logs, screenshots and local history.
Those interface artifacts are not deployed by this library PR.

This branch adds only new paths. It does not republish, substitute for, encode or
reroute any previously blocked native-core/ABCI/job source. Native integration
imports the separately available local package through the supplied path.

Local issuer keys, status and clocks must be trusted. This prototype does not
protect against malicious issuers/hosts, complete-workspace rollback, copied keys,
unseen revocations or later native state changes. Identity helpers do not implement
First Light, Sanctuary, government ID, KYC or custody. No new open-source license
is selected; dependencies retain their own notices. See NOTICE.md.
