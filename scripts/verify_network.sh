#!/usr/bin/env bash
# Linux/WSL. Uses installed dependencies and cached engine. No implicit installs.
set -euo pipefail
cd "$(dirname "$0")/.."
PYTHON="${PYTHON:-python3}"
"$PYTHON" scripts/local_dev.py test --scope full
"$PYTHON" scripts/local_dev.py network "$@"
