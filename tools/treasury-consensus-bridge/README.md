# P6 verifier-only bridge

This release-only development executable reuses the frozen treasury circuit and root primitives without editing their source. It has three fixed operations: verify, context-root and note-root. Verification returns exact OK or INVALID only after parameter/VK initialization succeeds; profile/startup failures are fatal. Inputs are bounded to 4096 bytes; proof transcript consumption is exact. There is no fixture, proving, ledger, owner or wallet command.

Use through src/protocol6_worker.py and scripts/protocol6_worker_exec.py with an exact genesis-pinned binary hash. See docs/PROTOCOL6_TREASURY.md for resource limits and trusted-host restrictions. This is not the hardened P5 worker, seccomp isolation or public-node readiness.
