param([Parameter(Mandatory=$true)][string]$Release,[string]$OutputDirectory="lexagent-offline-$Release")
$ErrorActionPreference="Stop"
New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
$images=Get-Content (Join-Path $PSScriptRoot "images.txt") | Where-Object { $_.Trim() -and -not $_.StartsWith("#") } | ForEach-Object { $_.Replace("RELEASE",$Release) }
foreach($image in $images){ docker image inspect $image | Out-Null }
$archive=Join-Path $OutputDirectory "images.tar"
docker save --output $archive $images
$images | Set-Content -Encoding utf8 (Join-Path $OutputDirectory "images.txt")
(Get-FileHash -Algorithm SHA256 $archive).Hash.ToLowerInvariant()+"  images.tar" | Set-Content -Encoding ascii (Join-Path $OutputDirectory "SHA256SUMS")
Write-Host "Offline bundle created: $OutputDirectory"
