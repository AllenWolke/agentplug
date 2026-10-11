param([switch]$FullSDK)
$ErrorActionPreference = 'Stop'
$taskRoot = [IO.Path]::GetFullPath((Split-Path -Parent $PSScriptRoot))
$taskArguments = @((Join-Path $taskRoot 'scripts/verify_public_knowledge_postgres.py'), '--suite', 'checkpoint')
if ($FullSDK) { $taskArguments += '--sdk-full' }
& python @taskArguments
if ($LASTEXITCODE -ne 0) { throw 'Isolated PostgreSQL SDK validation failed; see saved evidence and cleanup receipt' }
