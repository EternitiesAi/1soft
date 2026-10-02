# Try 1soft locally

**Follow one native payment from intent to verified receipt, then preserve its original history.** This is a private four-validator Protocol 4 development network on your computer. Its DEV atomic units have no monetary value. Private invoice content can be encrypted locally; ledger transactions remain public.

## Check your installation

Use Linux or Ubuntu WSL, Git, Node and the Python environment matching the exact versions in the repository's `requirements.txt`. You also need the already built CometBFT 0.38.25 binary pinned by the local platform. From the checkout root, replacing `/path/to/cometbft` with that binary:

```sh
python tools/local-platform/scripts/1soft.py doctor --engine /path/to/cometbft
```

`ready` means installed dependency versions, tool availability and the engine file hash passed. This diagnostic does not execute the engine, install software, start a network, inspect a workspace or qualify the source. `needs_attention` names missing or mismatched prerequisites in its JSON output. Even help and diagnostics work without loading the payment application.

To check this clean committed checkout with those installed prerequisites:

```sh
python tools/local-platform/scripts/1soft.py check --output "$HOME/1soft-current-check"
```

Choose a new output directory outside the checkout with an existing parent. The real current-source checker returns its actual exit status and retains raw component logs, exact test identities and source bindings. Component checks, real validator scenarios and rendered browser journeys are separate evidence. Historical `qualify` retains its original fixed 421-file scope and intentionally refuses later source.

## Open a fresh wallet

```sh
python tools/local-platform/scripts/1soft.py new \
  --workspace "$HOME/1soft-demo" --engine /path/to/cometbft
```

Use a new, short path outside the source on an owned private POSIX filesystem; the Unix socket requires about 85 path bytes or fewer. Creation refuses an existing workspace. Enter a vault password of at least 16 UTF-8 bytes at the terminal and repeat it. Open the printed `http://127.0.0.1:PORT/` exactly; the listener guards its literal local origin. Keep the terminal open while the wallet is running.

**Complete a short demonstration and stop the network.** The RPC proof collector accepts only 64 blocks. Four-second commits provide roughly four minutes of active collection, including startup. The original trust interval is one hour and continues expiring while the network is stopped. An expired policy or exhausted collector is a visible development limit, not permission to replace the anchor or reset retained obligations.

## Make one small payment

The wallet starts with a 1,000-unit treasury. Three setup operations cost two units each. Raven and Atlas share a 100-unit agent budget and one financial journal.

1. Leave the prefilled development recipient in place. Enter **10** DEV units and a short note, then choose **Create a 10-minute request**. The note stays off chain; the request is unsigned intent.
2. Select the request, choose **Raven**, then **Review payment**. Inspect the recipient, 10-unit amount, 2-unit fee, 12-unit total debit, block validity and decision digest. Approve that exact review, enter the vault password and choose **Sign and reserve**. This saves an original signature and fee-inclusive hold; it does not send anything.
3. Choose **Review submission**, approve one submission of the original bytes and choose **Send once**. Endpoint admission does not prove execution. A lost reply leaves the original obligation; do not create a replacement payment to compensate.
4. After a block commits, choose **Collect receipt evidence**. If the first observation is unavailable, retain the obligation and collect again explicitly after a later block. Collection does not resend the payment.
5. Choose **Reconcile wallet** once the exact receipt is verified. This is the operation that releases the hold. The original payment should now appear as verified execution, with no pending debit for it.
6. Choose **Keep portable receipt**, then **Export verified capsule**. It includes full related proof history, including unrelated accounts and transactions. Verification requires the original external genesis, policy and checked time; the capsule does not renew trust or prove latestness.

**Collect ledger** updates the read store. **Use ledger in wallet** explicitly reconciles that observation. Reloading a view performs neither action. Recorded balance, pending obligations and uncommitted units describe different facts and can remain unavailable if current evidence cannot be authenticated.

## Preserve history, stop and reopen

In **Keep the original decisions**, enter and repeat a separate backup passphrase, consent to the complete shared wallet/delivery scope and choose **Download encrypted history**. Keep the encrypted attachment, passphrase and original genesis/policy pins privately. A lost passphrase cannot be recovered.

This history contains retained proofs, signed originals, attempts, responses, receipts and unresolved holds from all roles. It excludes keys, vaults, private invoice content, request/invoice/separate receipt books and the derived ledger. It restores only to a historical recovery archive. It is not an active account restore, trust renewal, latestness guarantee or device fence. Browser export caps original captured BLOBs at 8 MiB and ciphertext at 16 MiB; larger complete exports use the existing custody CLI with format 3.

Press **Ctrl+C** in the running terminal. The command stops its owned applications, validators and wallet listener, retaining the private workspace. Inspect retained configuration:

```sh
python tools/local-platform/scripts/1soft.py status --workspace "$HOME/1soft-demo"
```

`status` does not probe running processes or modify data. To resume the same retained chain while its original policy and bounds permit:

```sh
python tools/local-platform/scripts/1soft.py start \
  --workspace "$HOME/1soft-demo" --engine /path/to/cometbft
```

There is no automatic new genesis, new journal, reset or trust renewal. If current evidence expires, preserve the workspace and use the [operator recovery guide](OPERATOR_HISTORY_RECOVERY.md) and [browser history guide](BROWSER_HISTORY_BACKUP.md). Historical recovery retains originals without creating spending authority. All signing paths for these funds must use the one shared journal; copying a database does not coordinate another device.

## Where to go next

- [Local platform reference](../tools/local-platform/README.md): commands, reservations, refusals and finite limits.
- [Current qualification](CURRENT_QUALIFICATION.md): component, actual engine and browser evidence boundaries.
- [Merchant checkout](MERCHANT_INVOICE_BROWSER.md): signed invoice terms and separately verified fulfillment.
- [Development roadmap](ROADMAP.md): independent operators, security/custody review, long-term history and public-release decisions.

Rendered automated workflows and one-host consensus do not establish human acceptance, production custody or independent validator security. Use this product to explore the mechanisms with valueless development keys.
