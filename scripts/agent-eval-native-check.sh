#!/bin/sh
# Native Linux/macOS entry, including macOS CI. No remote calls or credentials.
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root/contracts/agent-evaluation/go"
go test ./...
cd "$root/cli/agent-eval"
go test ./...
CGO_ENABLED=0 go run ./cmd/agent-eval version
CGO_ENABLED=0 go run ./cmd/agent-eval metrics
