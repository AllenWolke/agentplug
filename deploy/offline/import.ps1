param([Parameter(Mandatory=$true)][string]$BundleDirectory)
$ErrorActionPreference="Stop"
$archive=Join-Path $BundleDirectory "images.tar";$sumFile=Join-Path $BundleDirectory "SHA256SUMS"
if(-not (Test-Path $archive) -or -not (Test-Path $sumFile)){throw "Incomplete offline bundle"}
$expected=((Get-Content $sumFile)[0] -split '\s+')[0].ToLowerInvariant();$actual=(Get-FileHash -Algorithm SHA256 $archive).Hash.ToLowerInvariant()
if($expected -ne $actual){throw "Offline bundle checksum mismatch"}
docker load --input $archive
Write-Host "Offline images imported and checksum verified"

