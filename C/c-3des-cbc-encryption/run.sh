#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

if ! command -v gcc >/dev/null 2>&1 && ! command -v cc >/dev/null 2>&1; then
  echo "No C compiler found. Install gcc or clang."
  echo "  macOS:  xcode-select --install"
  echo "  Ubuntu: apt install build-essential libssl-dev"
  exit 1
fi

CC="${CC:-cc}"

echo "Compiling..."
$CC -O2 -Wall -Wextra -o 3des_cbc_demo 3des_cbc_demo.c -lssl -lcrypto

echo "Running..."
echo
./3des_cbc_demo
