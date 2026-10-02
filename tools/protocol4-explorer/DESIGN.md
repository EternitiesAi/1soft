# A checkpoint, made legible

This is a local P4 development ledger, built for someone checking where funds,
shared limits and completed transfers stood on one verified branch. The defining
visual is a proof ribbon: recorded state H flows into signed header H+1, with a
separate validator epoch. It explains the actual commitment instead of pretending
the page watches a live public network.

Tokens: porcelain #f6f8fc background, ink #182644, indigo #4957c7 action,
lake #167383 verified accent, blue-grey #dde4ef rules, muted violet #e8e7fa.
Segoe UI Variable/Segoe UI for prose, restrained monospace for keys and hashes.
Thin ledger rules, generous space, no decorative gradients or repeated metric-card
grid. Tables turn into scrollable ledger regions on narrow screens. Twenty rows
per page; local search; explicit refresh, no automatic network collector.

Semantics: integer atomic units, recorded balance and remaining limit, never
spendable balance. Native account key epochs and validator epochs stay distinct.
Receipt export is an explicit detail-panel action with full-history disclosure.
Escaped text, external local assets only, focus-visible controls, a labeled modal,
keyboard Escape/return focus and reduced-motion support.

Critique gate: inspect a real browser render, confirm checkpoint hierarchy and
legibility at desktop/narrow widths, exercise tabs/search/detail/refresh and
unavailable state. A synthetic demo must remain visibly synthetic. Automated
browser checks do not establish human usability or production custody.
