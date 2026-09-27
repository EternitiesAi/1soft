# dd096 return review and receipt-order continuation

The attached refreshed archive was verified directly, not inferred from its file
name or a PR summary. SHA-256:
`8395c131a62166dbcf57812b4c07f8a24c77fb118c1b182f71179e7b477576ee`.
All 294 packaged manifest entries matched; the 219 source files reconstructed
`5e1e7385033bdfa1f5e31821c7be8d1b101a2a40`, the GitHub tree at PR #12/dd096.
The 68 final evidence files were retained as supplied. The prior archive digest
B6C21... identifies the earlier packaging, not the uploaded refreshed ZIP.

The four reports contain 22, 39, 62 and 67 passing checks (190 total). Their runner
hash, manifest hash, clean-worktree declaration and source pins match dd096. Saved
full-state certificates, transaction inclusion and client-collected receipts were
cryptographically reverified against each separately identified development
genesis. All 28 native execution receipts were replayed from genesis using the
exact returned implementation. Receipt bytes, native state and all four final
application hashes matched. The two compact-record witnesses also verified.

The P3 report records were checked for exact transaction hashes, one submission
per payment, successful upstream CheckTx followed by the first downstream reply
drop, receipt-only collection preserving holds, and held/spent 100/0 -> 40/60 ->
0/100. These recorded observations are not independently observed network traffic.
The original engine binary was not in the archive and was not independently
rehash-verified or executed here. The review is NOT another validator run or an
independent security audit. The new source revision does not inherit a new
real-network acceptance result from this saved evidence.

The original dd096 delivery suite passed 51/51 again in this runtime. The follow-up
addresses older/duplicate receipt reconciliation only; see
`tools/wallet-delivery/RECEIPT_ORDER.md`. PR #11 remains a separate divergent line
and was not merged, copied, tested or credited by this continuation.

Original raw logs and source remain in the verified input ZIP included with the
continuation package. The package also contains offline-review tooling, exact
new test IDs, new test logs, the intentionally failing pre-fix regression and
three assertion-detected disposable mutations. Full native-suite execution,
public-network readiness, customer-funds safety and custody are not established.
