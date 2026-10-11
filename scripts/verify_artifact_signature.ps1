param([Parameter(Mandatory=$true)][string]$Image, [Parameter(Mandatory=$true)][string]$CertificateIdentity, [Parameter(Mandatory=$true)][string]$Issuer)
$ErrorActionPreference = 'Stop'
if (-not (Get-Command cosign -ErrorAction SilentlyContinue)) { throw 'cosign is required to verify artifacts' }
if ($Image -notmatch '@sha256:[0-9a-f]{64}$') { throw 'image must be pinned by sha256 digest' }
cosign verify --certificate-identity $CertificateIdentity --certificate-oidc-issuer $Issuer $Image
if ($LASTEXITCODE -ne 0) { throw 'artifact signature verification failed' }
