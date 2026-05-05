#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

if ! command -v go >/dev/null 2>&1; then
  echo "go not found. Install Go 1.21+ and try again."
  echo "  macOS:  brew install go"
  echo "  Ubuntu: snap install go --classic"
  exit 1
fi

go run rsa_signing_demo.go
