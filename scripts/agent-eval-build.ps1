param([string]$OutputDirectory = '.local-secrets/agent-eval/bin')
$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$buildOutput = [IO.Path]::GetFullPath((Join-Path $repoRoot $OutputDirectory))
New-Item -ItemType Directory -Force -Path $buildOutput | Out-Null
$previousCGO = $env:CGO_ENABLED
$previousGOOS = $env:GOOS
$previousGOARCH = $env:GOARCH
Push-Location (Join-Path $repoRoot 'cli/agent-eval')
try {
    $env:CGO_ENABLED = '0'
    foreach ($targetOS in @('linux', 'darwin', 'windows')) {
        foreach ($targetArch in @('amd64', 'arm64')) {
            $env:GOOS = $targetOS
            $env:GOARCH = $targetArch
            $suffix = if ($targetOS -eq 'windows') { '.exe' } else { '' }
            $binaryPath = Join-Path $buildOutput "agent-eval-$targetOS-$targetArch$suffix"
            & go build -trimpath -ldflags='-s -w' -o $binaryPath ./cmd/agent-eval
            if ($LASTEXITCODE -ne 0) { throw "Build failed: $targetOS/$targetArch" }
        }
    }
} finally {
    $env:CGO_ENABLED = $previousCGO
    $env:GOOS = $previousGOOS
    $env:GOARCH = $previousGOARCH
    Pop-Location
}
