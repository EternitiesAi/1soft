# CometBFT protocol and test-vector attribution

This package's independent verifier encodes fields described in the CometBFT v0.38.25 public protocol, and `tests/test_commit_verifier.py` contains transcribed fixed vectors from `types/vote_test.go` (cases 0–4) and `types/block_test.go` (`TestHeaderHash`). These remain attributable to the CometBFT/Tendermint contributors and upstream sources; they are not claimed as proprietary inventions of this project.

Original sources:

- https://github.com/cometbft/cometbft/blob/v0.38.25/types/vote_test.go
- https://github.com/cometbft/cometbft/blob/v0.38.25/types/block_test.go
- https://github.com/cometbft/cometbft/blob/v0.38.25/proto/tendermint/types/canonical.proto
- https://github.com/cometbft/cometbft/blob/v0.38.25/LICENSE

The upstream project provides the Apache License, Version 2.0. A copy of those license terms is included in `Apache-2.0.txt`. The test values were transcribed into Python tests; upstream Go test functions and consensus implementation are not vendored. The independent Python verifier, application changes and test harnesses were authored for this project.

The optional engine and Go probe load upstream dependencies when available. They retain their upstream terms. This notice does not grant an open-source license to the original project as a whole, resolve patentability, or imply upstream affiliation, endorsement or audit. Complete dependency and redistribution review remains a release requirement before public distribution of an engine build.
