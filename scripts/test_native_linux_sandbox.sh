#!/usr/bin/env bash
# Linux host acceptance: actual systemd cgroups, non-root and seccomp.
set -euo pipefail
project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
run_root="$(mktemp -d "${TMPDIR:-/tmp}/agentplug-native-sandbox.XXXXXX")"
run_root_real="$(realpath "$run_root")"
unit="agentplug-native-sandbox-${run_root##*.}"
privilege=()
service_uid="$(id -u)"
service_gid="$(id -g)"
if [[ "$service_uid" == 0 ]]; then
  service_uid=65534
  service_gid=65534
else
  privilege=(sudo -n)
fi
cleanup() {
  "${privilege[@]}" systemctl stop "${unit}.service" >/dev/null 2>&1 || true
  "${privilege[@]}" systemctl stop "${unit}-root.service" >/dev/null 2>&1 || true
  "${privilege[@]}" systemctl stop "${unit}-unbounded.service" >/dev/null 2>&1 || true
  if [[ -d "$run_root" && "$(realpath "$run_root")" == "$run_root_real" ]]; then
    "${privilege[@]}" rm -rf -- "$run_root"
  fi
}
trap cleanup EXIT
chmod 0755 "$run_root"
mkdir "$run_root/cache"
export GOCACHE="$run_root/cache" GOMAXPROCS=2 CGO_ENABLED=0 GOFLAGS=-p=2
cd "$project_root/workers/metric-runner"
go test -c -o "$run_root/sandbox.test" ./internal/sandbox
"${privilege[@]}" chown -R "$service_uid:$service_gid" "$run_root/cache"
"${privilege[@]}" systemd-run --unit="$unit" --wait --pipe --collect \
  --property="User=$service_uid" --property="Group=$service_gid" \
  --property=MemoryMax=768M --property=TasksMax=128 \
  --property=NoNewPrivileges=yes --property=ProtectControlGroups=yes \
  --property="WorkingDirectory=$PWD" --setenv="PATH=$PATH" \
  --setenv="GOCACHE=$GOCACHE" --setenv=GOMAXPROCS=2 --setenv=CGO_ENABLED=0 --setenv=GOFLAGS=-p=2 \
  "$run_root/sandbox.test" -test.v -test.run='^TestSandbox' 2>&1 | tee "$run_root/bounded.txt"
for required in TestSandboxRunsRegisteredPluginUnderTheSharedResultContract TestSandboxBlocksMaliciousPlugins TestSandboxSeccompDeniesEgress TestSandboxKillsRunawayPlugin; do
  if ! grep -F -- "--- PASS: $required" "$run_root/bounded.txt" >/dev/null; then
    printf 'required native sandbox assertion missing: %s\n' "$required" >&2
    exit 1
  fi
done
"${privilege[@]}" systemd-run --unit="${unit}-root" --wait --pipe --collect \
  --property=User=0 --property=Group=0 --property=MemoryMax=768M --property=TasksMax=128 \
  --property=NoNewPrivileges=yes --property=ProtectControlGroups=yes \
  --property="WorkingDirectory=$PWD" --setenv="PATH=$PATH" \
  --setenv="GOCACHE=$GOCACHE" --setenv=GOMAXPROCS=2 --setenv=CGO_ENABLED=0 --setenv=GOFLAGS=-p=2 \
  "$run_root/sandbox.test" -test.v -test.run='^TestSandboxRefusesUnsignedOrTamperedArtifacts$/root_is_refused_by_default$' 2>&1 | tee "$run_root/root.txt"
grep -F -- '--- PASS: TestSandboxRefusesUnsignedOrTamperedArtifacts/root_is_refused_by_default' "$run_root/root.txt" >/dev/null
"${privilege[@]}" systemd-run --unit="${unit}-unbounded" --wait --pipe --collect \
  --property="User=$service_uid" --property="Group=$service_gid" \
  --property=MemoryMax=infinity --property=TasksMax=infinity \
  --property=NoNewPrivileges=yes --property=ProtectControlGroups=yes \
  --property="WorkingDirectory=$PWD" --setenv="PATH=$PATH" \
  --setenv="GOCACHE=$GOCACHE" --setenv=GOMAXPROCS=2 --setenv=CGO_ENABLED=0 --setenv=GOFLAGS=-p=2 \
  "$run_root/sandbox.test" -test.v -test.run='^TestSandboxRefusesMissingCgroupBounds$' 2>&1 | tee "$run_root/unbounded.txt"
grep -F -- '--- PASS: TestSandboxRefusesMissingCgroupBounds' "$run_root/unbounded.txt" >/dev/null
printf 'NATIVE LINUX BOUNDED SANDBOX PASS\n'
