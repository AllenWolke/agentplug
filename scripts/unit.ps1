[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$projectRoot = Split-Path -Parent $scriptRoot
# The repository contains many Go packages and the host also runs the Docker
# acceptance stack. Bound package/build parallelism so a full Windows gate is
# reproducible instead of failing in the Go compiler with a host-level OOM.
# 仓库包含大量 Go 包，宿主机同时运行 Docker 验收栈；限制包/构建并发，
# 让 Windows 全量门禁可复现，避免 Go 编译器因宿主内存峰值 OOM。
if (-not $env:GOMAXPROCS) { $env:GOMAXPROCS = "2" }
if (-not $env:GOFLAGS -or $env:GOFLAGS -notmatch '(^|\s)-p(?:=|\s)') {
    $env:GOFLAGS = (($env:GOFLAGS + " -p=2").Trim())
}
$goTempRoot = Join-Path $projectRoot (".tmp\go-test\" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Force -Path $goTempRoot | Out-Null
$env:GOTMPDIR = $goTempRoot
# Go's t.TempDir/os.MkdirTemp uses the OS temp directory, not GOTMPDIR.
# Some Windows temp ACLs deny the generator's atomic rename even when Go
# compilation succeeds. Keep test scratch space inside this workspace.
# Go 测试临时目录不读取 GOTMPDIR；固定到工作区，避免 Windows 用户 Temp ACL
# 拒绝 Adapter 原子 rename。Linux/macOS 使用相同显式目录。
$osTempRoot = Join-Path $goTempRoot "os-temp"
New-Item -ItemType Directory -Force -Path $osTempRoot | Out-Null
$env:TMP = $osTempRoot
$env:TEMP = $osTempRoot
$env:TMPDIR = $osTempRoot
# Local ExecutionServer and Agent HTTP tests must not be intercepted by a
# developer HTTP_PROXY (common on Windows clash/v2ray setups). 127.0.0.1 502
# from the proxy is not an SDK failure.
# 本地 ExecutionServer 与 Agent HTTP 测试不得被开发机 HTTP_PROXY 劫持（Windows
# clash/v2ray 常见）；代理返回的 127.0.0.1 502 不是 SDK 失败。
if (-not $env:NO_PROXY) { $env:NO_PROXY = "localhost,127.0.0.1,::1" }
elseif ($env:NO_PROXY -notmatch "127\.0\.0\.1") { $env:NO_PROXY = "$($env:NO_PROXY),localhost,127.0.0.1,::1" }
$env:no_proxy = $env:NO_PROXY
$npmCacheRoot = Join-Path $projectRoot ".cache\npm"
New-Item -ItemType Directory -Force -Path $npmCacheRoot | Out-Null
$env:npm_config_cache = $npmCacheRoot
# Bound dependency extraction concurrency on Windows workstations.
$env:npm_config_jobs = "1"
if (-not $env:NODE_OPTIONS) { $env:NODE_OPTIONS = "--max-old-space-size=1024" }
$blackCacheRoot = Join-Path $projectRoot ".tmp\black-cache"
New-Item -ItemType Directory -Force -Path $blackCacheRoot | Out-Null
$env:BLACK_CACHE_DIR = $blackCacheRoot
$pytestTempRoot = Join-Path $projectRoot ".tmp\pytest"
New-Item -ItemType Directory -Force -Path $pytestTempRoot | Out-Null
$pytestRunRoot = Join-Path $pytestTempRoot ([guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Force -Path $pytestRunRoot | Out-Null

Write-Host "[secret scan]" -ForegroundColor Cyan
# The scanner itself skips Git-ignored runtime `.env*` files (see
# is_git_ignored in scripts/scan_secrets.py), so the direct invocation and this
# gate share one definition of scope. Tracking a real `.env*` is still caught.
# 扫描器内部会跳过被 Git 忽略的运行时 `.env*`（见 scan_secrets.py 的
# is_git_ignored），因此直接调用与本门禁口径完全一致；真正被跟踪的 `.env*`
# 仍会被拦截。
& python (Join-Path $projectRoot "scripts\scan_secrets.py")
if ($LASTEXITCODE -ne 0) { throw "secret scan failed" }
& python (Join-Path $projectRoot "scripts\test_scan_secrets.py")
if ($LASTEXITCODE -ne 0) { throw "secret scanner self-tests failed" }

Write-Host "[format and documentation links]" -ForegroundColor Cyan
& python -m pytest -q -p no:cacheprovider --basetemp (Join-Path $pytestRunRoot "table-boundary") (Join-Path $projectRoot "tests\release-validation\modular_table_boundary_test.py")
if ($LASTEXITCODE -ne 0) { throw "table boundary negative fixtures failed" }
& python (Join-Path $projectRoot "scripts\verify_modular_boundaries.py") --report (Join-Path $projectRoot "docs\新增需求\github作品改造\T3-03-模块边界检查报告.md") --json (Join-Path $projectRoot "docs\新增需求\github作品改造\T3-03-模块边界检查报告.json")
if ($LASTEXITCODE -ne 0) { throw "modular boundary/ownership gate failed" }
& python (Join-Path $projectRoot "scripts\verify_modular_process.py")
if ($LASTEXITCODE -ne 0) { throw "modular process boundary gate failed" }
& python (Join-Path $projectRoot "scripts\verify_productization_behavior.py") --compact
if ($LASTEXITCODE -ne 0) { throw "current modular productization behavior gate failed" }
& python (Join-Path $projectRoot "scripts\check_gofmt.py")
if ($LASTEXITCODE -ne 0) { throw "gofmt gate failed" }
& python (Join-Path $projectRoot "scripts\check_contract_breaking.py")
if ($LASTEXITCODE -ne 0) { throw "Agent Execution Contract compatibility gate failed" }
& python (Join-Path $projectRoot "scripts\lint_execution_contract.py")
if ($LASTEXITCODE -ne 0) { throw "Agent Execution Contract lint failed" }
# Validate the source/document cutover before Docker-dependent protobuf
# generation. A broken daemon must not hide a deterministic archive regression.
# 先运行纯源码/文档的切换门禁，再执行依赖 Docker 的 protobuf 校验；
# Docker 故障不应掩盖可独立发现的历史文档回归。
& python -m pytest -q -p no:cacheprovider --basetemp (Join-Path $pytestRunRoot "production-topology") (Join-Path $projectRoot "tests\release-validation\modular_production_topology_test.py")
if ($LASTEXITCODE -ne 0) { throw "modular production topology tests failed" }
& python -m pytest -q -p no:cacheprovider --basetemp (Join-Path $pytestRunRoot "postgres-backup") (Join-Path $projectRoot "tests\release-validation\postgres_backup_test.py")
if ($LASTEXITCODE -ne 0) { throw "PostgreSQL backup integrity and failure tests failed" }
& python -m pytest -q -p no:cacheprovider --basetemp (Join-Path $pytestRunRoot "publication") (Join-Path $projectRoot "tests\release-validation\publication_test.py")
if ($LASTEXITCODE -ne 0) { throw "publication regression tests failed" }
& python -m pytest -q -p no:cacheprovider --basetemp (Join-Path $pytestRunRoot "native") (Join-Path $projectRoot "tests\release-validation\native_deployment_test.py")
if ($LASTEXITCODE -ne 0) { throw "native deployment configuration tests failed" }
& python (Join-Path $projectRoot "scripts\check_publication.py")
if ($LASTEXITCODE -ne 0) { throw "GitHub publication candidates failed audit" }
& python -m pytest -q -p no:cacheprovider --basetemp (Join-Path $pytestRunRoot "production-release-preflight") (Join-Path $projectRoot "tests\release-validation\production_release_preflight_test.py") (Join-Path $projectRoot "tests\release-validation\template_conformance_mount_test.py") (Join-Path $projectRoot "tests\release-validation\supply_chain_release_gate_test.py") (Join-Path $projectRoot "tests\performance\agent_platform_v2\test_gate.py")
if ($LASTEXITCODE -ne 0) { throw "production release and performance preflight tests failed" }
& (Join-Path $projectRoot 'tests\release-validation\production_apply_mock_test.ps1')
if ($LASTEXITCODE -ne 0) { throw "production release ordering and lock mock failed" }
& python -m pytest -q -p no:cacheprovider --basetemp (Join-Path $pytestRunRoot "clean-cutover") (Join-Path $projectRoot "tests\e2e\clean_cutover_test.py")
if ($LASTEXITCODE -ne 0) { throw "clean cutover tests failed" }
& (Join-Path $projectRoot "scripts\check_proto_generated.ps1")
if ($LASTEXITCODE -ne 0) { throw "protobuf generated-code gate failed" }
& python (Join-Path $projectRoot "scripts\check_removed_architecture.py")
if ($LASTEXITCODE -ne 0) { throw "removed architecture migration gate failed" }
$removedArchitectureTemp = Join-Path $pytestRunRoot "removed-architecture"
& python -m pytest -q -p no:cacheprovider --basetemp $removedArchitectureTemp (Join-Path $projectRoot "tests\release-validation\legacy_architecture_forbidden_test.py")
if ($LASTEXITCODE -ne 0) { throw "removed architecture scanner tests failed" }
& python (Join-Path $projectRoot "scripts\check_markdown_links.py")
if ($LASTEXITCODE -ne 0) { throw "Markdown link gate failed" }
& python (Join-Path $projectRoot "scripts\check_agent_productization_contracts.py")
if ($LASTEXITCODE -ne 0) { throw "Agent productization contract gate failed" }
& python (Join-Path $projectRoot "scripts\check_agent_code_ownership.py")
if ($LASTEXITCODE -ne 0) { throw "Agent code ownership gate failed" }
foreach ($module in @("platform", "cli\agentctl", "adapters\grpc-mapping", "adapters\legacy-http", "adapters\process", "adapters\sidecar", "workers\metric-runner", "frontend", "sdk\go", "examples\go-operations", "templates\go-generic", "templates\go-eino")) {
    Write-Host "[go test] $module" -ForegroundColor Cyan
    Push-Location (Join-Path $projectRoot $module)
    try { & go test ./...; if ($LASTEXITCODE -ne 0) { throw "go test failed: $module" } }
    finally { Pop-Location }
}

Write-Host "[metric sandbox: malicious plugin fixtures]" -ForegroundColor Cyan
# PF-16 runtime evidence. The sandbox is Linux-only, so this check runs the real
# runner and malicious fixtures in one unprivileged, resource-bounded Linux
# container. Network denial is enforced by the per-plugin seccomp filter; no
# CAP_SYS_ADMIN or relaxed container seccomp profile is required.
# A lane that silently skips its assertions is treated as a failure.
# PF-16 运行态证据。沙箱仅支持 Linux，因此本检查在一个非特权、带资源上限的 Linux 容器中运行
# 真实 Runner 与恶意夹具。网络访问由每个插件进程的 seccomp 过滤器阻断，无需 CAP_SYS_ADMIN，
# 也无需放宽容器 seccomp 配置。静默跳过自身断言的通道一律按失败处理。
$sandboxEvidence = Join-Path $projectRoot ".tmp\pf16-malicious-linux.log"
New-Item -ItemType Directory -Force -Path (Split-Path $sandboxEvidence) | Out-Null
# Reset the evidence artifact every run so it reflects exactly this gate run.
# 每次运行重置证据产物，使其精确反映本次门禁。
[IO.File]::WriteAllText($sandboxEvidence, "# PF-16 metric sandbox lanes (Linux container evidence)" + [Environment]::NewLine, (New-Object System.Text.UTF8Encoding($false)))
$sandboxMount = $projectRoot.Replace('\', '/')
$sandboxLanes = @(
    @{ Name = "unprivileged"; Extra = @("--user", "65532:65532"); Required = @("--- PASS: TestSandboxBlocksMaliciousPlugins", "--- PASS: TestSandboxRunsRegisteredPluginUnderTheSharedResultContract", "--- PASS: TestSandboxSeccompDeniesEgress") }
)
foreach ($lane in $sandboxLanes) {
    Write-Host "[metric sandbox] $($lane.Name)" -ForegroundColor Cyan
    # The lane's Docker flags (--user) must precede the image name.
    # Appending them after the container command hands them to the test binary,
    # which then aborts with "flag provided but not defined: -user" and the lane
    # never runs its assertions (non-root tests silently skip when run as root).
    # 通道的 Docker 标志（--user）必须位于镜像名之前。若追加到容器命令之后，
    # 它们会被交给测试二进制，随即以 "flag provided but not defined: -user" 中止，通道
    # 永不执行其断言（以 root 运行时非 root 测试会静默跳过）。
    $sandboxCommand = @(
        "run", "--rm",
        "--memory", "512m",
        "--pids-limit", "128"
    ) + $lane.Extra + @(
        "-e", "GOCACHE=/tmp/go-build",
        "-e", "GOPATH=/tmp/go",
        "-e", "HOME=/tmp",
        "-e", "GOTOOLCHAIN=local",
        "-v", "${sandboxMount}:/workspace",
        "-w", "/workspace/workers/metric-runner",
        "golang:1.25",
        "go", "test", "-count=1", "-v", "-run", "TestSandbox", "./internal/sandbox/..."
    )
    $sandboxOutput = & docker @sandboxCommand 2>&1
    $sandboxExit = $LASTEXITCODE
    Add-Content -Path $sandboxEvidence -Value "# lane $($lane.Name) (exit $sandboxExit)"
    $sandboxOutput | Add-Content -Path $sandboxEvidence
    if ($sandboxExit -ne 0) { throw "metric sandbox $($lane.Name) lane failed" }
    foreach ($required in $lane.Required) {
        if (-not ($sandboxOutput | Select-String -SimpleMatch $required -Quiet)) {
            throw "metric sandbox $($lane.Name) lane did not prove '$required'"
        }
    }
}

Write-Host "[Agent SDK contract fixtures]" -ForegroundColor Cyan
$env:PYTHONPATH = (Join-Path $projectRoot "sdk\python")
& python -m pytest -q -p no:cacheprovider (Join-Path $projectRoot "sdk\python\tests") (Join-Path $projectRoot "sdk\python\agent_platform_sdk\test_runtime.py")
if ($LASTEXITCODE -ne 0) { throw "Python Agent SDK contract tests failed" }

Write-Host "[Python document example business tests]" -ForegroundColor Cyan
& python -m pytest -q -p no:cacheprovider (Join-Path $projectRoot "examples\python-documents\tests")
if ($LASTEXITCODE -ne 0) { throw "Python document example business tests failed" }

Write-Host "[LangGraph checkpoint SPI tests]" -ForegroundColor Cyan
& python -m pytest -q -p no:cacheprovider (Join-Path $projectRoot "templates\python-langgraph\platform_entry")
if ($LASTEXITCODE -ne 0) { throw "LangGraph checkpoint SPI tests failed" }

Write-Host "[python-generic capability PEP tests]" -ForegroundColor Cyan
& python -m pytest -q -p no:cacheprovider (Join-Path $projectRoot "templates\python-generic\platform_entry")
if ($LASTEXITCODE -ne 0) { throw "python-generic capability PEP tests failed" }
Push-Location (Join-Path $projectRoot "sdk\java")
try {
    # Force the pinned container path; host Maven plugins and ~/.m2 caches are
    # not part of the reproducible repository validation environment.
    $mavenCommand = $null
    # Maven resolves plugins and dependencies from Maven Central on every run
    # (no persistent plugin cache is mounted), so a transient Docker DNS or
    # proxy hiccup can fail the gate even though the SDK is correct. Retry a
    # bounded number of times: a real compile/contract failure reproduces on
    # every attempt and still fails the gate.
    $javaAttempts = 3
    # The reactor root builds the SDK, the Spring Boot starter (interceptor plus
    # OTel seam) and the framework example together, so a starter regression can
    # never slip through a module-only run.
    # 反应堆根目录同时构建 SDK、Spring Boot Starter（拦截器与 OTel 接缝）与框架示例,
    # 避免仅构建单模块时漏掉 Starter 回归。
    $javaModules = @("sdk/java", "templates/java-generic", "templates/java-spring-ai")
    # Maven Central is reached over a flaky link here: a truncated download
    # ("Premature end of Content-Length delimited message body") fails the whole
    # module even after the bounded retries. Keep one persistent local
    # repository across attempts and gate runs so each artifact is downloaded
    # once and later attempts reuse it instead of redownloading the whole tree.
    # 本机到 Maven Central 的链路不稳：单次下载被截断（Content-Length 未达）会让整个
    # 模块在重试后仍失败。因此保留一份持久本地仓库，构件只下载一次，后续重试与后续
    # 门禁轮次复用，而非每次重下整棵依赖树。
    $mavenCache = Join-Path $projectRoot ".cache\m2"
    New-Item -ItemType Directory -Force -Path $mavenCache | Out-Null
    $mavenCacheMount = ($mavenCache -replace '\\', '/')
    foreach ($javaModule in $javaModules) {
        Write-Host "[java test] $javaModule" -ForegroundColor Cyan
        for ($attempt = 1; $attempt -le $javaAttempts; $attempt++) {
            if ($mavenCommand) {
                Push-Location (Join-Path $projectRoot $javaModule)
                try { & $mavenCommand.Source --batch-mode --no-transfer-progress test }
                finally { Pop-Location }
            }
            else {
                # Keep the Java contract gate reproducible on Windows hosts without a
                # local Maven installation. The image is pinned by tag in the local
                # validation environment; no source code is executed outside it.
                $mountRoot = $projectRoot.Replace('\', '/')
                # Prefer IPv4 inside the container; some Windows Docker DNS setups
                # expose Maven Central over IPv6 only, which makes the gate fail even
                # though the registry is reachable.  This keeps the check deterministic
                # without changing the Java SDK contract or its source tree.  The
                # wagon retry handler makes Maven itself retry a truncated or reset
                # transfer instead of failing the module.
                # 容器内优先 IPv4：部分 Windows Docker DNS 只对 Maven Central 暴露
                # IPv6，会让门禁在仓库可达时仍失败。wagon 重试处理器让 Maven 自身对
                # 被截断或中断的传输重试，而不是直接判定模块失败。
                & docker run --rm -v "${mountRoot}:/workspace" -v "${mavenCacheMount}:/root/.m2" -w "/workspace/$javaModule" maven:3.9.9-eclipse-temurin-21 mvn '-Djava.net.preferIPv4Stack=true' '-Dmaven.wagon.http.retryHandler.count=3' '-Dmaven.wagon.rto=90000' --batch-mode --no-transfer-progress test
            }
            if ($LASTEXITCODE -eq 0) { break }
            if ($attempt -lt $javaAttempts) {
                Write-Host "[Java Agent SDK contract] $javaModule attempt $attempt/$javaAttempts failed (exit $LASTEXITCODE); retrying..." -ForegroundColor Yellow
                Start-Sleep -Seconds 5
            }
        }
        if ($LASTEXITCODE -ne 0) { throw "Java Agent SDK contract tests failed: $javaModule" }
    }
}
finally { Pop-Location }

Write-Host "[template live conformance]" -ForegroundColor Cyan
& python (Join-Path $projectRoot "scripts\run_template_conformance.py")
if ($LASTEXITCODE -ne 0) { throw "template live conformance failed" }

Write-Host "[agent create timing]" -ForegroundColor Cyan
& python (Join-Path $projectRoot "scripts\run_agent_create_timing.py")
if ($LASTEXITCODE -ne 0) { throw "agent create timing gate failed" }

Write-Host "[critical package coverage thresholds]" -ForegroundColor Cyan
& python (Join-Path $projectRoot "scripts\check_go_coverage.py")
if ($LASTEXITCODE -ne 0) { throw "critical package coverage gate failed" }

Write-Host "[frontend test/build]" -ForegroundColor Cyan
$npmCommand = (Get-Command npm.cmd -ErrorAction SilentlyContinue).Source
if (-not $npmCommand) { $npmCommand = (Get-Command npm -ErrorAction Stop).Source }
Push-Location (Join-Path $projectRoot "frontend")
try {
    & $npmCommand ci; if ($LASTEXITCODE -ne 0) { throw "npm ci failed" }
    & $npmCommand test; if ($LASTEXITCODE -ne 0) { throw "frontend tests failed" }
    & $npmCommand run build; if ($LASTEXITCODE -ne 0) { throw "frontend build failed" }
}
finally { Pop-Location }

# SDK and framework template tests above remain mandatory. Independent public
# example execution and RAG integration gates are added with their implementations.

Write-Host "[compose config]" -ForegroundColor Cyan
Push-Location $projectRoot
$validationDefaults = @{}
try {
    $contextKeyJSON = & python (Join-Path $projectRoot "scripts\generate_context_key.py")
    if ($LASTEXITCODE -ne 0) { throw "modular context key helper failed" }
    $contextKeyJSON = $contextKeyJSON -join "`n"
    # PowerShell may remove JSON quotes when passing a JSON object as one
    # native-process argument.  Parse it here and pass opaque base64 fields
    # separately so validation is identical on Windows, Linux, and macOS.
    # PowerShell 将 JSON 对象作为单个原生命令参数传递时可能剥离引号；
    # 先在此解析，再分别传递不含引号的 base64 字段，确保跨平台一致。
    try { $contextKey = $contextKeyJSON | ConvertFrom-Json -ErrorAction Stop } catch { throw "invalid generated modular context key JSON" }
    if (-not $contextKey.private -or -not $contextKey.public) { throw "generated modular context key is incomplete" }
    & python -c "import base64,sys; from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey; p=Ed25519PrivateKey.from_private_bytes(base64.b64decode(sys.argv[1])); assert base64.b64encode(p.public_key().public_bytes_raw()).decode()==sys.argv[2]" $contextKey.private $contextKey.public
    if ($LASTEXITCODE -ne 0) { throw "modular context key helper produced an invalid pair" }
    # Validate syntax on clean checkouts without a deployment .env. These
    # ephemeral values are used only by `config --quiet`, never to start services.
    foreach ($name in @("DB_PASSWORD", "INTERNAL_TOKEN", "BROWSER_GATEWAY_TOKEN", "INTERNAL_SIGNING_SECRET", "PLATFORM_CONTEXT_PUBLIC_KEY", "MEMORY_ENCRYPTION_KEY", "DEMO_PASSWORD_SYSTEM_ADMIN")) {
        if (-not [Environment]::GetEnvironmentVariable($name, "Process")) {
            $validationDefaults[$name] = [Environment]::GetEnvironmentVariable($name, "Process")
            [Environment]::SetEnvironmentVariable($name, [guid]::NewGuid().ToString("N"), "Process")
        }
    }
    # Syntax validation does not start services.
    & docker compose --profile modular -f compose.yaml config --quiet
    if ($LASTEXITCODE -ne 0) { throw "compose config validation failed" }
}
finally {
    foreach ($name in $validationDefaults.Keys) { [Environment]::SetEnvironmentVariable($name, $validationDefaults[$name], "Process") }
    Pop-Location
}

Write-Host "LOCAL UNIT AND BUILD CHECKS PASS" -ForegroundColor Green
