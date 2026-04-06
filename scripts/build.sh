#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

mkdir -p bin
env GOCACHE="${GOCACHE:-/tmp/go-cache}" go build -o bin/wuwa-auth ./cmd/authd
