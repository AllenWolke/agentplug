[CmdletBinding()]
param(
    [string]$PythonPath = "D:\developtool\Python313\python.exe",
    [ValidateRange(30, 900)][int]$StartupGraceSeconds = 300,
    [ValidateRange(5, 300)][int]$HealthIntervalSeconds = 15,
    [ValidateRange(1, 20)][int]$FailureThreshold = 4
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot "../..")).Path
$serverScript = Join-Path $PSScriptRoot "local_openai_server.py"
$logRoot = Join-Path $projectRoot "tmp/release-validation/model-supervisor"
New-Item -ItemType Directory -Force -Path $logRoot | Out-Null

if (-not (Test-Path -LiteralPath $PythonPath -PathType Leaf)) {
    throw "Python executable does not exist: $PythonPath"
}
if (-not (Test-Path -LiteralPath $serverScript -PathType Leaf)) {
    throw "Model server script does not exist: $serverScript"
}

$env:LOCAL_MODEL_PATH = (Resolve-Path (Join-Path $projectRoot "tmp/models/Qwen2.5-3B-Instruct")).Path
$env:LOCAL_MODEL_NAME = "Qwen2.5-3B-Instruct"
$env:LOCAL_EMBEDDING_MODEL_PATH = (Resolve-Path (Join-Path $projectRoot "tmp/models/bge-small-zh-v1.5")).Path
$env:LOCAL_EMBEDDING_MODEL_NAME = "BAAI/bge-small-zh-v1.5"
$env:LOCAL_RERANK_MODEL_PATH = (Resolve-Path (Join-Path $projectRoot "tmp/models/bge-reranker-base")).Path
$env:LOCAL_RERANK_MODEL_NAME = "BAAI/bge-reranker-base"
$env:LOCAL_MODEL_CPU_THREADS = "8"
$env:LOCAL_MODEL_MAX_NEW_TOKENS = "512"
$env:LOCAL_MODEL_MAX_INPUT_TOKENS = "8192"
$env:LOCAL_EMBEDDING_MAX_INPUT_TOKENS = "512"
$env:LOCAL_RERANK_MAX_INPUT_TOKENS = "512"
$env:LOCAL_CHAT_CONCURRENCY = "1"
$env:LOCAL_EMBEDDING_CONCURRENCY = "1"
$env:LOCAL_RERANK_CONCURRENCY = "1"
$env:LOCAL_CHAT_QUEUE_SIZE = "8"
$env:LOCAL_EMBEDDING_QUEUE_SIZE = "32"
$env:LOCAL_RERANK_QUEUE_SIZE = "32"
$env:LOCAL_MODEL_QUEUE_WAIT_SECONDS = "300"
$env:LOCAL_MODEL_HOST = "127.0.0.1"
$env:LOCAL_MODEL_PORT = "18000"

$mutex = [Threading.Mutex]::new($false, "Local\LexAgentLocalModel18000")
if (-not $mutex.WaitOne(0)) {
    throw "Another LexAgent local-model supervisor is already running."
}

try {
    while ($true) {
        $stamp = [DateTime]::Now.ToString("yyyyMMdd-HHmmss")
        $stdout = Join-Path $logRoot "model-$stamp.stdout.log"
        $stderr = Join-Path $logRoot "model-$stamp.stderr.log"
        $child = Start-Process -FilePath $PythonPath `
            -ArgumentList $serverScript `
            -WorkingDirectory $projectRoot `
            -WindowStyle Hidden `
            -RedirectStandardOutput $stdout `
            -RedirectStandardError $stderr `
            -PassThru

        $startedAt = [DateTime]::UtcNow
        $consecutiveFailures = 0
        while (-not $child.HasExited) {
            Start-Sleep -Seconds $HealthIntervalSeconds
            $child.Refresh()
            if ($child.HasExited) { break }

            try {
                $health = Invoke-RestMethod "http://127.0.0.1:18000/health" -TimeoutSec 5
                if ($health.status -ne "ok") { throw "health status is not ok" }
                $consecutiveFailures = 0
            }
            catch {
                if (([DateTime]::UtcNow - $startedAt).TotalSeconds -lt $StartupGraceSeconds) {
                    continue
                }
                $consecutiveFailures++
                if ($consecutiveFailures -ge $FailureThreshold) {
                    Stop-Process -Id $child.Id -Force -ErrorAction SilentlyContinue
                    break
                }
            }
        }

        Start-Sleep -Seconds 5
    }
}
finally {
    $mutex.ReleaseMutex()
    $mutex.Dispose()
}
