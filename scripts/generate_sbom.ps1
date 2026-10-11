param([Parameter(Mandatory=$true)][string]$Image, [Parameter(Mandatory=$true)][string]$Output)
$ErrorActionPreference = 'Stop'
if (-not (Get-Command syft -ErrorAction SilentlyContinue)) { throw 'syft is required to generate an SBOM' }
if ($Image -notmatch '@sha256:[0-9a-f]{64}$') { throw 'image must be pinned by sha256 digest' }
syft $Image -o "spdx-json=$Output"
if ($LASTEXITCODE -ne 0) { throw 'SBOM generation failed' }
