#!/usr/bin/env bash
# Compile and run the RSA-2048 signing demo.
# Requires: javac + java (JDK 11 or newer).

set -euo pipefail
cd "$(dirname "$0")"

if ! command -v javac >/dev/null 2>&1; then
  echo "javac not found. Install OpenJDK 11+ and try again."
  echo "  macOS:  brew install openjdk@21"
  echo "  Ubuntu: apt install default-jdk"
  exit 1
fi

echo "Compiling..."
javac RsaSigningDemo.java

echo "Running..."
echo
java RsaSigningDemo