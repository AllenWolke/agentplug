# Platform stack launcher; never evaluates environment values as shell code.
$ErrorActionPreference = "Stop"
$taskPython = if ($env:PYTHON) { $env:PYTHON } else { "python" }
$taskArguments = if ($args.Count) { $args } else { @("up") }
& $taskPython (Join-Path $PSScriptRoot "compose.py") @taskArguments
exit $LASTEXITCODE
