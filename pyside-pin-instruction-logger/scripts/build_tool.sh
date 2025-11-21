#!/bin/bash

set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd -- "$SCRIPT_DIR/.." && pwd)
PIN_ROOT=${PIN_ROOT:-/home/researchdev/Downloads/pin4}

echo "Building Intel PIN tool via $PIN_ROOT"
make -C "$REPO_ROOT/pin-tool" PIN_ROOT="$PIN_ROOT" "$@"
echo "Build completed successfully."