param(
    [ValidateSet('identity-full', 'schema', 'administration', 'capability', 'capability-recovery', 'capability-billing', 'execution', 'execution-recovery', 'conversation', 'erasure-audit', 'platform-ports', 'process', 'maintenance', 'usage', 'kafka', 'scale', 'source', 'index')]
    [string]$Suite = 'identity-full'
)
$ErrorActionPreference = 'Stop'
$verifier = Join-Path $PSScriptRoot 'verify_public_knowledge_postgres.py'
$env:PYTHONDONTWRITEBYTECODE = '1'
$env:PYTHONUTF8 = '1'
& python $verifier --suite $Suite
if ($LASTEXITCODE -ne 0) { throw "Isolated PostgreSQL verification failed: $Suite" }
