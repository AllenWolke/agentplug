[CmdletBinding()]
param([string]$BaseUrl = "http://localhost:3000", [string]$Username = "system.admin")
$ErrorActionPreference = "Stop"
& python (Join-Path $PSScriptRoot "smoke.py") --base-url $BaseUrl --username $Username
exit $LASTEXITCODE
