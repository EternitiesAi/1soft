# Encrypted history from the development browser

The local wallet and committed merchant browser offer **Download encrypted history**. This is an audited historical copy of the shared P4 wallet and delivery journals. Restoring it creates a recovery-only archive which can recover original signed wires, saved execution receipts and unresolved obligations. It cannot sign, send, renew trust, establish latestness or fence another device.

## Create and keep a download

Open the existing guarded loopback wallet at its exact printed `http://127.0.0.1:PORT/` address. Use the encrypted-history section, enter and repeat a separate backup passphrase of 16–1024 UTF-8 bytes, read the scope consent, and choose Download encrypted history. Keep that passphrase separately from the file: there is no password reset or key recovery in this format. The passphrase need not be the vault password, and the export never unlocks a vault.

The file includes **all retained history in this shared financial journal**, including other roles and signed generic decisions hidden from a selected merchant invoice screen. It includes original proof packets, signed decisions, attempted delivery records, transport observations, saved receipts and unresolved holds. It is not limited to the invoice currently selected.

Private keys, encrypted vaults, private invoice content/storage, unsigned request book, separate portable receipt book and derived ledger/read store are excluded. Back up those separately under an appropriate custody plan if they are needed; this download alone is not a complete account backup. Original genesis and external trust policy are still required for recovery. Existing browser startup still requires its configured development files; this does not add startup after lost keys or damaged catalogs.

The interface uses compressed authenticated backup **format 3**. The original logical stream and recovery decoder remain the same. The browser refuses a captured pair above **8 MiB original BLOB bytes** or an encrypted file above **16 MiB**. It never trims history to make it fit. Use the existing [custody CLI](../tools/protocol4-custody/README.md) with explicit format 3 for larger admitted journals; its original complete-journal limits still apply. Neither compression nor the browser limits change native history, wallet admission, proof verification or retention limits.

An export audits one complete captured pair, creates its entire encrypted file privately before sending headers, then streams the completed ciphertext. Source journal logical rows are not changed. If the browser loses a download, it can explicitly request a fresh encryption of the retained history; this neither signs nor submits a payment. Keep the successfully completed attachment, rather than treating a success banner alone as a verified backup. The download folder and local browser/OS remain the user's custody boundary. Field clearing and temporary file/object-URL cleanup do not guarantee memory zeroization or removal of a saved download.

## Historical authority

Backup remains available when current evidence or the original fixed policy is expired. The encrypted copy preserves historical obligations; it supplies no current trusted balance or spending authority. An unverified transport outcome remains unknown. A collected receipt still needs explicit wallet reconciliation to retire its hold. Creating or restoring a backup performs neither action.

Follow the [operator preservation and recovery guide](OPERATOR_HISTORY_RECOVERY.md): keep the exact original full `engine-genesis.json`, original independently selected `policy.json`, encrypted download, and a separately preserved backup passphrase. `app-genesis.json` is not the full wallet genesis. Use the existing [recovery-only archive workflow](../tools/protocol4-custody/README.md) with those original inputs. Recovering a signed wire is not permission to resend it. Copied journals, rollback, cross-device coordination and hostile hosts remain separate unresolved custody problems.

## Guard and qualification scope

Only an exact protected POST `/api/backup-history` is accepted, with the existing literal Host, same-origin, CSRF, body/type and exact-field guards. There is no arbitrary path or format selector, public endpoint, persistent download token or automatic job. Merchant export delegates to the same shared financial journal.

Qualification belongs to the exact tested source revision. The current-source suite, strict custody verifier, actual validator turnover and actual ordinary/merchant Chromium attachment downloads are separate gates. Test-only historical-clock injection is not a production trust-renewal option. Captured test receipts and screenshots do not establish human acceptance, hostile-host security, independent operators or production release. Historical manifest checkers retain their original snapshot and may refuse changed descendant sources; do not rewrite their pins to qualify this feature.
