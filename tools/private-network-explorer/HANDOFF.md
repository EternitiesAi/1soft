# Explorer import handoff — 4 October 2026

User requested the approved private explorer be pushed to the 1soft GitHub repo,
explicitly endorsing its visual design. Preserve this look as the explorer design
baseline unless the owner requests a change.

- Source repository: `EternitiesAi/1soft` (former `xnuonux/1soft` path redirects).
- Import base: `9e53827518b7b6d6333f9fed392dfd63f55f490b`.
- Files added only under `tools/private-network-explorer/`.
- `dist/`, `tests/` and `package.json` match the deployed Sites source bytes.
- `README.md`, this handoff and `SOURCE_PROVENANCE.json` describe the repository
  import and provenance; they do not update the existing live Site.
- Targeted checks: 13/13 passing; no dependencies installed and no Actions used.
- Browser rendering, full native suites, engine qualification and independent
  review remain unassessed for this import.
- Deployment remains owner-only at
  https://onesoft-network-explorer.xnuonux.chatgpt.site
- Data stays synthetic fixture or explicit live-unavailable state. No approved
  live read source has been connected.

Next live-data work should preserve explicit source labels, historical checkpoint
semantics, exact integer units, absent/unknown distinctions and non-authorizing
recorded balances. Keep the existing P4 verifier's external pins and trust policy
as the authority boundary; this display application is not a proof verifier.
