[CmdletBinding()]
param(
    [string]$TaskName = "LexAgent-LocalModel-18000",
    [string]$PythonPath = "D:\developtool\Python313\python.exe"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$supervisor = (Resolve-Path (Join-Path $PSScriptRoot "run_local_model_supervisor.ps1")).Path
$powerShell = (Get-Process -Id $PID).Path

if (-not (Test-Path -LiteralPath $PythonPath -PathType Leaf)) {
    throw "Python executable does not exist: $PythonPath"
}

# Never terminate an arbitrary listener. Only replace the known project model process.
$listener = Get-NetTCPConnection -LocalPort 18000 -State Listen -ErrorAction SilentlyContinue | Select-Object -First 1
if ($listener) {
    $process = Get-CimInstance Win32_Process -Filter "ProcessId=$($listener.OwningProcess)"
    if (-not $process -or $process.CommandLine -notmatch "tests[/\\]release-validation[/\\]local_openai_server\.py") {
        throw "Port 18000 is occupied by a non-project process; refusing to stop it."
    }
    Stop-Process -Id $listener.OwningProcess -Force
    Start-Sleep -Seconds 2
}

$arguments = '-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}" -PythonPath "{1}"' -f $supervisor, $PythonPath
$action = New-ScheduledTaskAction -Execute $powerShell -Argument $arguments -WorkingDirectory (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
$settings = New-ScheduledTaskSettingsSet `
    -StartWhenAvailable `
    -RestartCount 999 `
    -RestartInterval (New-TimeSpan -Minutes 1) `
    -ExecutionTimeLimit ([TimeSpan]::Zero) `
    -MultipleInstances IgnoreNew

Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings -Description "Supervise the LexAgent local Chat, Embedding and Rerank service on port 18000." -Force | Out-Null
Start-ScheduledTask -TaskName $TaskName

$deadline = [DateTime]::UtcNow.AddMinutes(6)
do {
    try {
        $health = Invoke-RestMethod "http://127.0.0.1:18000/health" -TimeoutSec 5
        if ($health.status -eq "ok") {
            Write-Output "task=$TaskName status=ready"
            exit 0
        }
    }
    catch {}
    Start-Sleep -Seconds 5
} while ([DateTime]::UtcNow -lt $deadline)

throw "Scheduled model service did not become healthy within six minutes."
