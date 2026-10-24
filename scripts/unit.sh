#!/usr/bin/env bash
# POSIX host-independent twin of scripts/unit.ps1.
#
# Same step order, same commands, same assertions and the same fail-closed exit
# semantics as the PowerShell gate. It exists because the acceptance gate must be
# runnable on any POSIX host (Linux/macOS) instead of being bound to Windows
# PowerShell; a green run on Linux therefore exercises exactly the same checks
# the Windows gate performs.
# 本脚本是 scripts/unit.ps1 的宿主无关 POSIX 孪生实现：步骤顺序、命令、断言与失败闭合的
# 退出码语义与 PowerShell 门禁完全一致。它的存在是为了让验收门禁可在任意 POSIX 宿主
# （Linux/macOS）运行，而不被绑定到 Windows PowerShell；因此在 Linux 上跑绿即等价于执行了
# Windows 门禁的同一套检查。
#
# 同步维护：scripts/unit.ps1 ↔ scripts/unit.sh。
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
project_root="$(cd "${script_dir}/.." && pwd)"

# Host toolchain resolution. `python` is the Windows/Compose spelling; POSIX
# hosts normally expose `python3`. Both are honoured so the same gate runs on
# either host without editing the script.
# 宿主工具链解析：`python` 是 Windows/Compose 的写法，POSIX 宿主通常提供 `python3`。
# 两者都支持，使同一门禁无需改脚本即可在任一类宿主运行。
PYTHON_BIN="${PYTHON:-}"
if [[ -z "${PYTHON_BIN}" ]]; then
    if command -v python >/dev/null 2>&1; then PYTHON_BIN="python"; else PYTHON_BIN="python3"; fi
fi

go_temp_root="${project_root}/.tmp/go-test/${RANDOM}-$$"
mkdir -p "${go_temp_root}"
export GOTMPDIR="${go_temp_root}"
npm_cache_root="${project_root}/.cache/npm"
mkdir -p "${npm_cache_root}"
export npm_config_cache="${npm_cache_root}"
black_cache_root="${project_root}/.tmp/black-cache"
mkdir -p "${black_cache_root}"
export BLACK_CACHE_DIR="${black_cache_root}"
pytest_temp_root="${project_root}/.tmp/pytest"
mkdir -p "${pytest_temp_root}"
pytest_run_root="${pytest_temp_root}/$$-${RANDOM}"
mkdir -p "${pytest_run_root}"

step() { echo "[$1]"; }

step "secret scan"
# The scanner itself skips Git-ignored runtime `.env*` files (see
# is_git_ignored in scripts/scan_secrets.py), so the direct invocation and this
# gate share one definition of scope. Tracking a real `.env*` is still caught.
# 扫描器内部会跳过被 Git 忽略的运行时 `.env*`（见 scan_secrets.py 的 is_git_ignored），
# 因此直接调用与本门禁口径完全一致；真正被跟踪的 `.env*` 仍会被拦截。
"${PYTHON_BIN}" "${project_root}/scripts/scan_secrets.py"
"${PYTHON_BIN}" "${project_root}/scripts/test_scan_secrets.py"
"${PYTHON_BIN}" "${project_root}/scripts/sync_public_sdks.py" --check

step "format and documentation links"
"${PYTHON_BIN}" "${project_root}/scripts/verify_modular_boundaries.py"
"${PYTHON_BIN}" "${project_root}/scripts/verify_modular_process.py"
"${PYTHON_BIN}" "${project_root}/scripts/verify_productization_behavior.py" --compact
"${PYTHON_BIN}" "${project_root}/scripts/check_gofmt.py"
"${PYTHON_BIN}" "${project_root}/scripts/check_contract_breaking.py"
"${PYTHON_BIN}" "${project_root}/scripts/lint_execution_contract.py"
bash "${project_root}/scripts/check_proto_generated.sh"
"${PYTHON_BIN}" "${project_root}/scripts/check_removed_architecture.py"
"${PYTHON_BIN}" -m pytest -q -p no:cacheprovider --basetemp "${pytest_run_root}/removed-architecture" "${project_root}/tests/release-validation/legacy_architecture_forbidden_test.py"
"${PYTHON_BIN}" -m pytest -q -p no:cacheprovider --basetemp "${pytest_run_root}/production-topology" "${project_root}/tests/release-validation/modular_production_topology_test.py"
"${PYTHON_BIN}" -m pytest -q -p no:cacheprovider --basetemp "${pytest_run_root}/postgres-backup" "${project_root}/tests/release-validation/postgres_backup_test.py"
"${PYTHON_BIN}" -m pytest -q -p no:cacheprovider --basetemp "${pytest_run_root}/publication" "${project_root}/tests/release-validation/publication_test.py"
"${PYTHON_BIN}" -m pytest -q -p no:cacheprovider --basetemp "${pytest_run_root}/native" "${project_root}/tests/release-validation/native_deployment_test.py"
"${PYTHON_BIN}" "${project_root}/scripts/check_publication.py"
"${PYTHON_BIN}" -m pytest -q -p no:cacheprovider --basetemp "${pytest_run_root}/clean-cutover" "${project_root}/tests/e2e/clean_cutover_test.py"
"${PYTHON_BIN}" "${project_root}/scripts/check_markdown_links.py"
"${PYTHON_BIN}" "${project_root}/scripts/check_agent_productization_contracts.py"
"${PYTHON_BIN}" "${project_root}/scripts/check_agent_code_ownership.py"

go_modules=(
    "platform"
    "cli/agentctl"
    "cli/agent-eval"
    "contracts/agent-evaluation/go"
    "contracts/code-runtime"
    "adapters/grpc-mapping"
    "adapters/legacy-http"
    "adapters/process"
    "adapters/sidecar"
    "workers/metric-runner"
    "workers/code-runtime"
    "frontend"
    "sdk/go"
    "examples/go-operations"
    "agents/examples/go-eino"
    "templates/go-generic"
    "templates/go-eino"
)
for module in "${go_modules[@]}"; do
    step "go test ${module}"
    (cd "${project_root}/${module}" && go test ./...)
done

step "metric sandbox: malicious plugin fixtures"
# PF-16 runtime evidence. The sandbox is Linux-only, so -- unlike every other Go
# module -- this check cannot run on a non-Linux host. It runs the real runner and
# the real malicious fixtures in an unprivileged Linux container. The kernel
# enforces cgroup ceilings, file limits and per-plugin seccomp egress denial.
# A lane that silently skips its own assertions is treated as a failure.
# PF-16 运行态证据。沙箱仅支持 Linux，因此与其它 Go 模块不同，本检查无法在非 Linux 宿主
# 运行。它在非 root Linux 容器中验证 cgroup 上限、文件限制与插件级 seccomp 出网拒绝。
# 当前实现无需特权网络命名空间通道。
# 静默跳过自身断言的通道一律按失败处理。
sandbox_evidence="${project_root}/.tmp/pf16-malicious-linux.log"
mkdir -p "$(dirname "${sandbox_evidence}")"
: >"${sandbox_evidence}"
# Nested `docker run` bind mounts resolve on the *host*, so an in-container run
# must be told the host-side repository path; on a plain POSIX host the checkout
# path already is the host path.
# 嵌套 `docker run` 的绑定挂载在 *宿主* 上解析，因此容器内运行必须被告知宿主机仓库路径；
# 在普通 POSIX 宿主上检出路径本身就是宿主路径。
sandbox_mount="${LEXAGENT_DOCKER_MOUNT_ROOT:-${project_root}}"
sandbox_mount="${sandbox_mount//\\//}"

run_sandbox_lane() {
    local name="$1" required="$2"
    shift 2
    local extra=("$@")
    step "metric sandbox ${name}"
    local output exit_code
    set +e
    output="$(docker run --rm \
        --memory 512m \
        --pids-limit 128 \
        -e GOCACHE=/tmp/go-build \
        -e GOPATH=/tmp/go \
        -e HOME=/tmp \
        -e GOTOOLCHAIN=local \
        -v "${sandbox_mount}:/workspace" \
        -w /workspace/workers/metric-runner \
        "${extra[@]}" \
        golang:1.26.10-bookworm \
        go test -count=1 -v -run TestSandbox ./internal/sandbox/... 2>&1)"
    exit_code=$?
    set -e
    {
        echo "# lane ${name} (exit ${exit_code})"
        printf '%s\n' "${output}"
    } >>"${sandbox_evidence}"
    if [[ ${exit_code} -ne 0 ]]; then
        echo "metric sandbox ${name} lane failed" >&2
        exit 1
    fi
    local marker
    while IFS= read -r marker; do
        [[ -z "${marker}" ]] && continue
        if ! grep -qF -- "${marker}" <<<"${output}"; then
            echo "metric sandbox ${name} lane did not prove '${marker}'" >&2
            exit 1
        fi
    done <<<"${required}"
}

run_sandbox_lane "unprivileged" \
    $'--- PASS: TestSandboxBlocksMaliciousPlugins\n--- PASS: TestSandboxRunsRegisteredPluginUnderTheSharedResultContract\n--- PASS: TestSandboxSeccompDeniesEgress\n--- PASS: TestSandboxKillsRunawayPlugin' \
    --user 65532:65532

step "Agent SDK contract fixtures"
export PYTHONPATH="${project_root}/sdk/python"
"${PYTHON_BIN}" -m pytest -q "${project_root}/sdk/python/tests" "${project_root}/sdk/python/agent_platform_sdk/test_runtime.py"

step "Python document example business tests"
"${PYTHON_BIN}" -m pytest -q "${project_root}/examples/python-documents/tests"

step "LangGraph checkpoint SPI tests"
"${PYTHON_BIN}" -m pytest -q "${project_root}/templates/python-langgraph/platform_entry"

step "python-generic capability PEP tests"
"${PYTHON_BIN}" -m pytest -q "${project_root}/templates/python-generic/platform_entry"

step "Java Agent SDK contract reactor"
# The reactor root builds the SDK, the Spring Boot starter (interceptor plus OTel
# seam) and the framework example together, so a starter regression can never
# slip through a module-only run.
# 反应堆根目录同时构建 SDK、Spring Boot Starter（拦截器与 OTel 接缝）与框架示例，
# 避免仅构建单模块时漏掉 Starter 回归。
java_modules=("sdk/java" "templates/java-generic" "templates/java-spring-ai")
java_attempts=3
maven_cache="${project_root}/.cache/m2"
mkdir -p "${maven_cache}"
maven_command="$(command -v mvn || true)"
for java_module in "${java_modules[@]}"; do
    step "java test ${java_module}"
    attempt=1
    while true; do
        set +e
        if [[ -n "${maven_command}" ]]; then
            (cd "${project_root}/${java_module}" && "${maven_command}" --batch-mode --no-transfer-progress test)
        else
            # Keep the Java contract gate reproducible on hosts without a local
            # Maven installation; the image is pinned by tag in the local
            # validation environment and no source runs outside it.
            # 在无本地 Maven 的宿主上保持 Java 契约门禁可复现；镜像在本地验收环境中按 tag
            # 固定，源码不在其外执行。
            docker run --rm \
                -v "${sandbox_mount}:/workspace" \
                -v "${maven_cache}:/root/.m2" \
                -w "/workspace/${java_module}" \
                maven:3.9.9-eclipse-temurin-21 \
                mvn '-Djava.net.preferIPv4Stack=true' '-Dmaven.wagon.http.retryHandler.count=3' '-Dmaven.wagon.rto=90000' --batch-mode --no-transfer-progress test
        fi
        code=$?
        set -e
        if [[ ${code} -eq 0 ]]; then break; fi
        if [[ ${attempt} -ge ${java_attempts} ]]; then
            echo "Java Agent SDK contract tests failed: ${java_module}" >&2
            exit 1
        fi
        echo "[Java Agent SDK contract] ${java_module} attempt ${attempt}/${java_attempts} failed (exit ${code}); retrying..."
        sleep 5
        attempt=$((attempt + 1))
    done
done

step "template live conformance"
"${PYTHON_BIN}" "${project_root}/scripts/run_template_conformance.py"

step "agent create timing"
"${PYTHON_BIN}" "${project_root}/scripts/run_agent_create_timing.py"

step "critical package coverage thresholds"
"${PYTHON_BIN}" "${project_root}/scripts/verify_public_knowledge_postgres.py" --suite identity-full --coverage --batch-id "unit-${RANDOM}-$$"

step "frontend test/build"
(
    cd "${project_root}/frontend"
    npm ci
    npm test
    npm run build
)

# SDK and framework template tests above remain mandatory. Independent public
# example execution and RAG integration gates are added with their implementations.

step "compose config"
# Validate syntax on clean checkouts without a deployment .env. These ephemeral
# values are used only by `config --quiet`, never to start services.
# 在无部署 .env 的全新检出上校验语法；这些临时值仅用于 `config --quiet`，绝不用于启动服务。
context_key_json="$(${PYTHON_BIN} "${project_root}/scripts/generate_context_key.py")"
"${PYTHON_BIN}" -c 'import base64,json,sys; from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey; d=json.loads(sys.argv[1]); p=Ed25519PrivateKey.from_private_bytes(base64.b64decode(d["private"])); assert base64.b64encode(p.public_key().public_bytes_raw()).decode()==d["public"]' "${context_key_json}"
validation_names=(DB_PASSWORD INTERNAL_TOKEN INTERNAL_SIGNING_SECRET PLATFORM_CONTEXT_PUBLIC_KEY MEMORY_ENCRYPTION_KEY DEMO_PASSWORD_SYSTEM_ADMIN)
declare -A validation_defaults=()
for name in "${validation_names[@]}"; do
    if [[ -z "${!name:-}" ]]; then
        validation_defaults["${name}"]="__unset__"
        export "${name}=$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"
    fi
done
# Syntax validation does not start services.
(cd "${project_root}" && docker compose --profile modular -f compose.yaml config --quiet)
for name in "${!validation_defaults[@]}"; do
    unset "${name}"
done

echo "LOCAL UNIT AND BUILD CHECKS PASS"
