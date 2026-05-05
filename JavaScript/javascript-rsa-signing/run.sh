#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

if ! command -v node >/dev/null 2>&1; then
  echo "node not found. Install Node.js 18+ and try again."
  echo "  macOS:  brew install node"
  echo "  Ubuntu: apt install nodejs"
  exit 1
fi

node rsa_signing_demo.js
