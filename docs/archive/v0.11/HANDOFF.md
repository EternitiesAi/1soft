# 1soft continuation handoff — v0.11

Owner direction: genuine independent native Layer 1 plus human/agent financial
account experience; 1soft.org domain setup is a separate Codex lane. No GitHub
Actions, paid compute, DNS edits, production funds or public deployment here.

New files: src/payment_jobs.py, scripts/jobs.py, tests/test_payment_jobs.py,
PAYMENT_JOBS_MANIFEST.json and docs/PAYMENT_JOBS*.md. The adapter binds a stable
local task ID to one immutable native transaction body and designated signer
before signing. It uses the dispatcher's same database/lock, derives attached
status from the durable payment queue, and never signs/unlocks. A recovered or
verified job cannot be repurposed using a new nonce. Different IDs or other
workspaces/direct signing are outside this protection. Job IDs are NOT on-chain.

All 569 local Python cases passed across 16 complete batches; 34 are new. Separate
JS reference: 30. Three deliberate binding-check mutations triggered assertion
failures. Batch 13's first attempt hit the tool deadline and was not counted; its
completed retry and exact test-ID coverage are retained. The actual engine gate
remains unassessed with zero engine steps. Do not claim fixture HTTP/signatures
are actual CometBFT network evidence.

Full local parent: 7be0ab4b85899b5d9c8784fa7b23011700205cc4. Observed remote main:
941c6241d89761f2074c121af29539c354f6cdcd. Observed PR #2 parent:
29705061c3cbb8b09ac18001c2b980d3183215a1. Check current refs again before work.
Local full source and remote main's state wallet differ; preserve both. New files
consume the common canonical envelope. Do not overwrite main's wallet or force
push. The platform-blocked transport file is not rerouted by this adapter.

Use PAYMENT_JOBS_MANIFEST.json for the independently runnable 17-file job subset;
SOURCE_MANIFEST.json checks 64 files in the complete local tree. Do not trim the
full manifest to hide partial remote publication. The actual new source and
remote heads are recorded in RELEASE.json when packaging finishes.

Next priorities: obtain genuine official-engine execution in a supported local
runtime; run upstream codec and real four-validator acceptance including wallet,
dispatch and receipt recovery. The existing native engine runner remains the gate.
Do not equate more tests with achieved consensus. Keep protocol 1/2 unchanged until
measured integration results support further changes. Review maximum snapshot
size, storage growth and unauthenticated operational surfaces before public testnet.

The jobs layer cannot know if an external wallet produced a signature before
attachment. Recover that signature from its wallet outbox and attach it; never
invent a replacement nonce under the same business job. No cancellation/rebinding
or cross-journal atomicity is delivered. No job ID or untrusted agent text grants
permission to spend funds.

Publication outcome in this turn: the platform blocked a normal tree action
containing the two new job implementation/CLI files. No new remote commit or ref
was created. Do not encode, split, or reroute that blocked upload. The local
package contains the completed changes and test evidence. Existing PR #2 stays
at its previous head unless another actor independently updates it. This local
checkpoint must not be called published or merged.
