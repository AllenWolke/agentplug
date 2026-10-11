param(
    [string]$BaseUrl = "http://127.0.0.1:6060",
    [Parameter(Mandatory = $true)][string]$Token,
    [string]$OutputDir = "artifacts/pprof",
    [int]$CPUSeconds = 5
)

$ErrorActionPreference = "Stop"
if ($CPUSeconds -lt 1 -or $CPUSeconds -gt 30) { throw "CPUSeconds must be between 1 and 30" }
New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
$headers = @{ Authorization = "Bearer $Token" }

# 未认证请求必须失败，避免报告建立在误暴露的调试端点上。
try {
    Invoke-WebRequest -Uri "$BaseUrl/debug/pprof/" -UseBasicParsing | Out-Null
    throw "security check failed: unauthenticated pprof request succeeded"
} catch {
    if ($_.Exception.Response.StatusCode.value__ -ne 401) { throw }
}

Invoke-WebRequest -Uri "$BaseUrl/debug/pprof/goroutine?debug=1" -Headers $headers -OutFile "$OutputDir/goroutine.txt" -UseBasicParsing
Invoke-WebRequest -Uri "$BaseUrl/debug/pprof/heap" -Headers $headers -OutFile "$OutputDir/heap.pb.gz" -UseBasicParsing
Invoke-WebRequest -Uri "$BaseUrl/debug/pprof/profile?seconds=$CPUSeconds" -Headers $headers -OutFile "$OutputDir/cpu.pb.gz" -UseBasicParsing

go tool pprof -top "$OutputDir/cpu.pb.gz" | Set-Content -Encoding UTF8 "$OutputDir/cpu-top.txt"
go tool pprof -top -inuse_space "$OutputDir/heap.pb.gz" | Set-Content -Encoding UTF8 "$OutputDir/heap-top.txt"
$goroutineHeader = Get-Content "$OutputDir/goroutine.txt" -TotalCount 1
if ($goroutineHeader -match 'total\s+(\d+)') {
    $goroutineCount = [int]$Matches[1]
} else {
    throw "cannot parse goroutine profile header"
}

@"
# 受保护 pprof 实战采样报告

- 采样时间：$(Get-Date -Format o)
- 目标：$BaseUrl
- 未认证访问：401（通过）
- CPU 采样：$CPUSeconds 秒
- goroutine 栈数量：$goroutineCount
- 原始证据：`cpu.pb.gz`、`heap.pb.gz`、`goroutine.txt`
- 聚合证据：`cpu-top.txt`、`heap-top.txt`

分析时先看 CPU flat/cum 热点，再看 heap inuse_space，最后将 goroutine 阻塞栈与请求量对照。生产环境仅临时启用，绑定管理网或 loopback，并在采样后关闭。
"@ | Set-Content -Encoding UTF8 "$OutputDir/report.md"

Write-Host "pprof evidence written to $OutputDir"
