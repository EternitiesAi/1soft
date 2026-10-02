# 1soft v0.15 continuation

The owner selected 1soft as the coin name and wants this lane on the cryptocurrency, not Resident/Luna/Psyche development. They asked that work continue here without making Codex a prerequisite. Use local tools and preserve the no-Actions instruction. Do not modify the deployed website, domain, protected identities, real funds or paid cloud resources.

## Source and implementation

Parent complete local source: v0.14 `721437c4eef75cf15e7cf784f8025373a026f69e`. Current source commit is in RELEASE.json after packaging. This is not a clone of remote main's different wallet lineage. The observed remote main at the start of this checkpoint was `f4201151e27e44466d9ff6fafc7a69e1acc39e34`.

Read VALIDATED_EXECUTION.md and VERIFICATION.md. New execution_snapshot.py stores a process-local query-only SQLite image after full startup validation or native execution. BlockApplication forks it for checks/proposals/finalization, keeps a finalized candidate separate, and promotes it only after the existing durable commit. A reference execution_cache=False mode preserves the old reconstruction path for comparison. No monetary or protocol-version change, signature-domain replacement, proof-format change or new native private key.

## Evidence

797 Python cases passed across 16 completed groups; 37 new cases are included. 89 required sources matched. Existing 39/65-check application-process exercises and JS budget/proof comparisons passed. Five weakened controls caused assertion failures. Real committee consensus was not executed. The local measurement produced identical CheckTx decisions while removing per-request historical signature rescans; do not call it TPS.

## Next engineering priorities

The pinned CometBFT acceptance gate still needs actual engine execution. Codex has no special technical role: any supported authorized Linux/WSL environment with that engine and dependencies can run it. This chat environment's ordinary module-host lookup still fails. No user action is required merely to continue local implementation/testing, and no public node should be opened to compensate.

Keep full startup validation. Do not import cache images from peers, allow a pending image into CheckTx, or fall back silently if a cache checkpoint fails. Next storage work should reduce full-state finalization and database-page copying without changing authoritative roots or skipping necessary validation. Also retain explicit transaction admission/resource limits and the distinction between local locks and consensus security.

The old blocked source-upload actions remain a publication limitation. Do not reroute blocked content or force-replace remote history. Record implemented local work separately from any supported successful source publication. Archived Actions remain archived. Existing PRs are not automatically merged by this package.
