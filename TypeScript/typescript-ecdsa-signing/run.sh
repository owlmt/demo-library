#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

if ! command -v npx >/dev/null 2>&1; then
  echo "npx not found. Install Node.js 18+ and try again."
  exit 1
fi

npx --yes ts-node ecdsa_signing_demo.ts
