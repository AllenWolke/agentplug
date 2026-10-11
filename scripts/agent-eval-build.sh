#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
output=${1:-"$root/.local-secrets/agent-eval/bin"}
mkdir -p "$output"
output=$(CDPATH= cd -- "$output" && pwd)
cd "$root/cli/agent-eval"
for target_os in linux darwin windows; do
  for target_arch in amd64 arm64; do
    suffix=''
    if [ "$target_os" = windows ]; then suffix='.exe'; fi
    CGO_ENABLED=0 GOOS="$target_os" GOARCH="$target_arch" go build -trimpath -ldflags='-s -w' -o "$output/agent-eval-$target_os-$target_arch$suffix" ./cmd/agent-eval
  done
done
