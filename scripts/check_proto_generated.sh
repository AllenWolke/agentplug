#!/usr/bin/env bash
# POSIX host-independent twin of scripts/check_proto_generated.ps1.
#
# It regenerates the Go and Python bindings from the single authoritative Proto
# contract and fails when any committed artifact drifts. The step list, the
# compared file pairs, the one allowed Python post-process and the exit-code
# semantics are identical to the PowerShell gate; only the host plumbing
# differs, so a POSIX host (Linux/macOS) runs exactly the same check.
# 本脚本是 scripts/check_proto_generated.ps1 的宿主无关 POSIX 孪生实现：从唯一权威
# Proto 契约重新生成 Go/Python 绑定，并在任何已提交产物漂移时失败。步骤顺序、比较的
# 文件对、唯一允许的 Python 后处理与退出码语义与 PowerShell 门禁完全一致，仅宿主管道
# 不同，使 POSIX 宿主（Linux/macOS）运行同一套检查。
#
# scripts/check_proto_generated.ps1 的对应关系见该文件；两者必须同步修改。
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
project_root="$(cd "${script_dir}/.." && pwd)"

if ! command -v docker >/dev/null 2>&1; then
    echo "docker is required for the protobuf generated-code gate" >&2
    exit 1
fi

# Nested `docker run` bind mounts are resolved by the Docker daemon on the
# *host*, so when this gate itself runs inside a container the caller must pass
# the host-side repository path. On a plain POSIX host the checkout path is the
# host path and the default is correct.
# 嵌套 `docker run` 的绑定挂载由 *宿主* 上的 Docker 守护进程解析，因此当门禁自身在容器
# 内运行时，调用方必须传入宿主机上的仓库路径；在普通 POSIX 宿主上检出路径即宿主路径，
# 默认值正确。
docker_root="${LEXAGENT_DOCKER_MOUNT_ROOT:-${project_root}}"
docker_root="${docker_root//\\//}"

run_id="$(date -u +%Y%m%d%H%M%S)-$$"
relative_temp=".tmp/contract-codegen/${run_id}"
temp="${project_root}/${relative_temp}"
go_out="${temp}/go"
python_out="${temp}/python"
mkdir -p "${go_out}" "${python_out}"

cleanup() { rm -rf "${temp}"; }
trap cleanup EXIT

echo "[protobuf generated-code gate] generating Go bindings"
docker run --rm \
    -v "${docker_root}/contracts/proto:/defs" \
    -v "${docker_root}/${relative_temp}/go:/out" \
    namely/protoc-all:1.51_2 -f agent_execution_v2.proto -l go -o /out --go-source-relative

echo "[protobuf generated-code gate] generating Python bindings"
docker run --rm \
    -v "${docker_root}/contracts/proto:/defs" \
    -v "${docker_root}/${relative_temp}/python:/out" \
    namely/protoc-all:1.51_2 -f agent_execution_v2.proto -l python -o /out --with-pyi

hash_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    else
        shasum -a 256 "$1" | awk '{print $1}'
    fi
}

compare() {
    local generated="$1" stored="$2"
    if [[ ! -f "${generated}" ]]; then
        echo "generated contract is missing: ${generated}" >&2
        exit 1
    fi
    if [[ ! -f "${stored}" ]]; then
        echo "committed contract is missing: ${stored}" >&2
        exit 1
    fi
    if [[ "$(hash_of "${generated}")" != "$(hash_of "${stored}")" ]]; then
        echo "generated contract drift: ${stored}" >&2
        exit 1
    fi
}

compare "${go_out}/agent_execution_v2.pb.go" "${project_root}/platform/internal/agentgateway/proto/agent_execution_v2.pb.go"
compare "${go_out}/agent_execution_v2_grpc.pb.go" "${project_root}/platform/internal/agentgateway/proto/agent_execution_v2_grpc.pb.go"
compare "${python_out}/agent_execution_v2_pb2.py" "${project_root}/sdk/python/agent_platform_sdk/proto/agent_execution_v2_pb2.py"
compare "${python_out}/agent_execution_v2_pb2.pyi" "${project_root}/sdk/python/agent_platform_sdk/proto/agent_execution_v2_pb2.pyi"
compare "${python_out}/agent_execution_v2_pb2_grpc.pyi" "${project_root}/sdk/python/agent_platform_sdk/proto/agent_execution_v2_pb2_grpc.pyi"

# The package-local relative import is the only intentional Python post-process.
# 包内相对导入是 Python 生成物唯一允许的确定性后处理。
if ! diff -q \
    <(sed -E 's/^import agent_execution_v2_pb2/from . import agent_execution_v2_pb2/' "${python_out}/agent_execution_v2_pb2_grpc.py") \
    "${project_root}/sdk/python/agent_platform_sdk/proto/agent_execution_v2_pb2_grpc.py" >/dev/null; then
    echo "generated Python gRPC contract drift" >&2
    exit 1
fi

echo "protobuf generated-code gate passed"
