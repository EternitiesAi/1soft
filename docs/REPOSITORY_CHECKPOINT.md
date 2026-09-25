# Published checkpoint

The observed private remote `xnuonux/1soft/main` is commit
`5a5d609847009a0815430b645bd719fc4d713eb4`.
All 18 published files (including the owner's unchanged placeholder) match the
local bytes by the Git blob identifiers returned from the connected GitHub tree.
See `evidence/v06/publication-inventory.json`. This is not a full remote clone.

The published subset includes six of the 43 required source files. The other 37
remain absent remotely; the full v0.6 archive has all 43. A local reconstruction
using the verified remote file bytes produced the following results:

- 35 native-core tests passed.
- 33 checkout/test-runner tests passed.
- Complete-source verification failed, reporting the missing required files.
- The full test gate refused to execute that incomplete checkout.

These subset test results overlap the full 320-test run; do not add them to it.
The test execution was local, not a GitHub runner result. Issue #1 records both
publication and hosted-execution blockers, with exact observed run references:
https://github.com/xnuonux/1soft/issues/1

The complete archive's local source commit is recorded separately in RELEASE.json.
Do not push that historical branch over the owner repository with force. No
public release, tag, website deployment, financial connection or new asset was
created. The owner's repository name is a development destination, not a branding
or ticker decision.
