param(
    [Parameter(Mandatory)][int]$ExpectedProcessId,
    [ValidateRange(1,16)][int]$Threads = 4,
    [ValidateRange(0,128)][int]$RerankQueueSize = 8,
    [ValidateRange(0,128)][int]$EmbeddingQueueSize = 8,
    [string]$EvidenceDirectory = 'tmp/release-validation/latency-threads4-20260906'
)
$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$process = Get-CimInstance Win32_Process -Filter "ProcessId=$ExpectedProcessId"
if (-not $process -or $process.CommandLine -notmatch 'tests[/\\]release-validation[/\\]local_openai_server\.py') {
    throw 'PID does not identify the expected project model service; refusing to stop it.'
}
$health = Invoke-RestMethod 'http://127.0.0.1:18000/health' -TimeoutSec 10
foreach ($route in @('chat','embedding','rerank')) {
    if ($health.routes.$route.running -ne 0 -or $health.routes.$route.queued -ne 0) {
        throw 'Model has active work; refusing to interrupt requests.'
    }
}
$output = Join-Path $repo $EvidenceDirectory
New-Item -ItemType Directory -Force $output | Out-Null
$env:LOCAL_MODEL_PATH = Join-Path $repo 'tmp/models/Qwen2.5-3B-Instruct'
$env:LOCAL_MODEL_NAME = 'Qwen2.5-3B-Instruct'
$env:LOCAL_EMBEDDING_MODEL_PATH = Join-Path $repo 'tmp/models/bge-small-zh-v1.5'
$env:LOCAL_EMBEDDING_MODEL_NAME = 'BAAI/bge-small-zh-v1.5'
$env:LOCAL_RERANK_MODEL_PATH = Join-Path $repo 'tmp/models/bge-reranker-base'
$env:LOCAL_RERANK_MODEL_NAME = 'BAAI/bge-reranker-base'
$env:LOCAL_MODEL_CPU_THREADS = "$Threads"
$env:LOCAL_MODEL_MAX_NEW_TOKENS = '512'
$env:LOCAL_MODEL_MAX_INPUT_TOKENS = '8192'
$env:LOCAL_EMBEDDING_MAX_INPUT_TOKENS = '512'
$env:LOCAL_RERANK_MAX_INPUT_TOKENS = '512'
$env:LOCAL_CHAT_CONCURRENCY = '1'
$env:LOCAL_EMBEDDING_CONCURRENCY = '1'
$env:LOCAL_RERANK_CONCURRENCY = '1'
$env:LOCAL_MODEL_QUEUE_SIZE = '8'
$env:LOCAL_CHAT_QUEUE_SIZE = '8'
$env:LOCAL_RERANK_QUEUE_SIZE = [string]$RerankQueueSize
$env:LOCAL_EMBEDDING_QUEUE_SIZE = [string]$EmbeddingQueueSize
$env:LOCAL_MODEL_QUEUE_WAIT_SECONDS = '300'
$env:LOCAL_MODEL_HOST = '127.0.0.1'
$env:LOCAL_MODEL_PORT = '18000'
Stop-Process -Id $ExpectedProcessId
$launched = Start-Process -FilePath $process.ExecutablePath -ArgumentList 'tests/release-validation/local_openai_server.py' -WorkingDirectory $repo -WindowStyle Hidden -RedirectStandardOutput (Join-Path $output 'model.stdout.log') -RedirectStandardError (Join-Path $output 'model.stderr.log') -PassThru
Write-Output "started_pid=$($launched.Id) threads=$Threads logs=$output"
