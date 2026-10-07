# Wallet interface direction

Subject: an operator's private recipient wallet, with a retained original and
explicit signed recovery. The interface should make decisions legible, not
invent a spendable balance or market valuation.

Palette: mist#e8eef3, steel#dee7ee, ink#162b45, secondary#526477,
action blue#246deb and recovery teal#1b6d70. Bahnschrift/Arial Narrow gives the
headline a compact, practical identity; Segoe UI/Tahoma carries forms. System
fonts keep the local app independent of third-party requests.

Layout: quiet left navigation; right-hand workspace starts with the wallet's
actual observation and ledger rows. Receive, preparation and recovery each get
one focused workspace. Review uses a local readable original-intent display and
a separate exact confirmation, not a one-click transfer card.

The initial balance-card idea was rejected because inventory does not authorize
a balance and generic dashboards hide the important recovery state. The final
direction uses note commitments and retained transaction rows. Rounded private
forms have a different hierarchy from ledger dividers; no repeated card grid or
decorative animations. Mobile collapses navigation into a horizontal rail.

Critique in browser at desktop/mobile widths, keyboard focus, reduced motion and
long identifiers. The canned preview fixture qualifies presentation only; it
cannot be presented as real custody, payments or validator acceptance.
