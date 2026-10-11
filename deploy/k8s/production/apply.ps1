param(
  [string]$Namespace = "lexagent",
  [int]$RolloutTimeoutSeconds = 900,
  [string]$KustomizePath = "",
  [string]$ReleaseManifestPath = "",
  [string]$SignatureIdentity = "",
  [string]$SignatureIssuer = ""
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$manifestRoot = if ($KustomizePath) { (Resolve-Path -LiteralPath $KustomizePath).Path } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
$releaseLockName = 'agentplug-production-release-lock'
$releaseLockOwner = [guid]::NewGuid().ToString('N')
$releaseLockOwned = $false
Push-Location $manifestRoot
try {
  # Fail before applying anything if the release overlay still contains examples
  # or unresolved immutable image coordinates.
  # 在应用任何资源前 fail closed，避免示例值或未解析的不可变镜像坐标进入集群。
  $rendered = kubectl kustomize .
  if ($LASTEXITCODE -ne 0) { throw "production kustomize render failed" }
  $renderedText = @($rendered) -join "`n"
  if ($renderedText -match "\.example\.com|\.invalid|(?i)replace|sha256:0{64}") {
    throw "production manifests still contain template placeholders; render an approved overlay first"
  }

  if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    throw 'Python with PyYAML is required for production release preflight'
  }
  if (-not $ReleaseManifestPath) { throw 'an approved release manifest is required before deployment' }
  $releaseManifest = (Resolve-Path -LiteralPath $ReleaseManifestPath).Path
  $sourceCommit = git -C $PSScriptRoot rev-parse --verify HEAD
  if ($LASTEXITCODE -ne 0) { throw 'release source has no resolvable Git commit' }
  $sourceCommit = (@($sourceCommit) -join "`n").Trim()
  $sourceChanges = git -C $PSScriptRoot status --porcelain --untracked-files=normal
  if ($LASTEXITCODE -ne 0 -or @($sourceChanges | Where-Object { $_ }).Count -ne 0) {
    throw 'release source is not a clean Git checkout; commit the candidate before deployment'
  }
  $releaseValidator = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '../../../scripts/validate_production_release.py')).Path
  $preflightJSON = $renderedText | python $releaseValidator --namespace $Namespace --manifest $releaseManifest --commit $sourceCommit
  if ($LASTEXITCODE -ne 0) { throw 'production release bundle failed structural preflight' }
  $releaseBundle = ($preflightJSON | Out-String | ConvertFrom-Json)

  # Render once and apply only the approved documents in dependency order.
  # 一次性渲染后按依赖顺序应用，迁移失败时不替换旧运行实例。
  $documents = @([regex]::Split($renderedText, '(?m)^---\s*$') | Where-Object { $_.Trim() })
  $allowedKinds = @('Namespace', 'ConfigMap', 'NetworkPolicy', 'ServiceAccount', 'Service', 'Job', 'Deployment', 'Ingress')
  foreach ($document in $documents) {
    $kind = [regex]::Match($document, '(?m)^kind:\s*([A-Za-z]+)\s*$')
    if (-not $kind.Success -or $kind.Groups[1].Value -notin $allowedKinds) {
      throw 'unrecognized rendered resource kind; review the release bundle before applying it'
    }
  }

  $namespaceDocuments = @($documents | Where-Object { $_ -match '(?m)^kind:\s*Namespace\s*$' })
  if ($namespaceDocuments.Count -ne 1 -or $namespaceDocuments[0] -notmatch "(?m)^  name:\s*$([regex]::Escape($Namespace))\s*$") {
    throw "rendered Namespace does not match '$Namespace'"
  }
  if (-not $SignatureIdentity -or -not $SignatureIssuer) {
    throw 'approved signature identity and issuer are required before deployment'
  }
  if (-not (Get-Command cosign -ErrorAction SilentlyContinue)) {
    throw 'cosign is required before deployment'
  }
  foreach ($image in @($releaseBundle.images)) {
    cosign verify -a "source_commit=$sourceCommit" --certificate-identity $SignatureIdentity --certificate-oidc-issuer $SignatureIssuer $image | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "artifact signature verification failed for $image" }
    cosign verify-attestation --type spdxjson --certificate-identity $SignatureIdentity --certificate-oidc-issuer $SignatureIssuer $image | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "signed image SBOM verification failed for $image" }
  }

  function Apply-RenderedKind([string]$ResourceKind, [string]$ResourceName = '', [string[]]$SkipNames = @()) {
    foreach ($document in $documents) {
      if ($document -notmatch "(?m)^kind:\s*$ResourceKind\s*$") { continue }
      if ($ResourceName -and $document -notmatch "(?m)^  name:\s*$ResourceName\s*$") { continue }
      $documentName = [regex]::Match($document, '(?m)^  name:\s*([^\s]+)\s*$').Groups[1].Value
      if ($documentName -in $SkipNames) { continue }
      $document | kubectl apply -n $Namespace -f -
      if ($LASTEXITCODE -ne 0) { throw "failed to apply $ResourceKind $ResourceName" }
    }
  }

  # Secrets are externally managed and must already exist in the target
  # namespace. Do not mutate Namespace before checking every dependency.
  # 外部 Secret 必须预置；核对全部依赖前不得先改 Namespace。
  kubectl get namespace $Namespace -o name | Out-Null
  if ($LASTEXITCODE -ne 0) { throw "target namespace '$Namespace' must be provisioned before release" }

  # Check Secret data-key names and nonempty encoded values before Jobs start;
  # never print or decode them. External Secrets/Vault owns their values.
  # 作业启动前检查 Secret 键名及编码值非空；不打印或解码，由外部系统管理凭证。
  foreach ($reference in $releaseBundle.secret_keys.PSObject.Properties) {
    $secret = $reference.Name
    $secretJSON = kubectl get secret $secret -n $Namespace -o json
    if ($LASTEXITCODE -ne 0) { throw "required External Secret '$secret' is missing in namespace '$Namespace'" }
    try { $secretRecord = (@($secretJSON) -join "`n") | ConvertFrom-Json -ErrorAction Stop }
    catch { throw "could not parse External Secret '$secret' metadata" }
    if (-not $secretRecord.data -or @($secretRecord.data.PSObject.Properties).Count -eq 0) {
      throw "required External Secret '$secret' has no data keys"
    }
    $availableKeys = @($secretRecord.data.PSObject.Properties.Name)
    foreach ($key in @($reference.Value)) {
      if ($key -notin $availableKeys) { throw "required Secret '$secret' is missing key '$key'" }
      if ([string]::IsNullOrWhiteSpace([string]$secretRecord.data.PSObject.Properties[$key].Value)) {
        throw "required Secret '$secret' has an empty key '$key'"
      }
    }
  }

  # Kubernetes creation is atomic. A second release must fail before either
  # release deletes/recreates the immutable migration Job.
  # ConfigMap 创建是原子的；并发发布必须在任何一方重建 Job 前被拦截。
  kubectl create configmap $releaseLockName -n $Namespace --from-literal=owner=$releaseLockOwner | Out-Null
  if ($LASTEXITCODE -ne 0) { throw "another release holds '$releaseLockName'; inspect the owner before retrying" }
  $releaseLockOwned = $true

  Apply-RenderedKind 'Namespace'

  # Replace only this release-owned migration Job, never a database or volume.
  # 只重建本发布拥有的迁移Job，不删除数据库或数据卷。
  kubectl delete job platform-schema-migrate -n $Namespace --ignore-not-found=true --wait=true
  if ($LASTEXITCODE -ne 0) { throw "could not replace platform migration Job" }

  Apply-RenderedKind 'ConfigMap'
  # Only the deny baseline and migration egress policy are needed before the
  # migration. Changing runtime ingress/egress while old Pods still serve
  # traffic would make a failed migration disrupt the previous release.
  Apply-RenderedKind 'NetworkPolicy' 'default-deny'
  Apply-RenderedKind 'NetworkPolicy' 'platform-migration-traffic'
  Apply-RenderedKind 'ServiceAccount'
  Apply-RenderedKind 'Service'
  Apply-RenderedKind 'Job' 'platform-schema-migrate'

  # Runtime startup fails closed until this deployment-owned migration completes.
  # 运行进程在部署迁移完成前拒绝Schema版本；迁移完成才可验收平台。
  kubectl wait --for=condition=complete --timeout=("{0}s" -f $RolloutTimeoutSeconds) job/platform-schema-migrate -n $Namespace
  if ($LASTEXITCODE -ne 0) { throw "platform schema migration did not complete" }
  Apply-RenderedKind 'NetworkPolicy' '' @('default-deny', 'platform-migration-traffic')
  Apply-RenderedKind 'Deployment'
  Apply-RenderedKind 'Ingress'
  kubectl rollout status deployment/platform-app -n $Namespace --timeout=("{0}s" -f $RolloutTimeoutSeconds)
  if ($LASTEXITCODE -ne 0) { throw "platform-app rollout failed" }
  kubectl rollout status deployment/metric-runner -n $Namespace --timeout=("{0}s" -f $RolloutTimeoutSeconds)
  if ($LASTEXITCODE -ne 0) { throw "metric-runner rollout failed" }
  kubectl rollout status deployment/frontend -n $Namespace --timeout=("{0}s" -f $RolloutTimeoutSeconds)
  if ($LASTEXITCODE -ne 0) { throw "frontend rollout failed" }
  kubectl rollout status deployment/oauth2-proxy -n $Namespace --timeout=("{0}s" -f $RolloutTimeoutSeconds)
  if ($LASTEXITCODE -ne 0) { throw "oauth2-proxy rollout failed" }
} finally {
  try {
    if ($releaseLockOwned) {
      $currentOwner = kubectl get configmap $releaseLockName -n $Namespace -o 'jsonpath={.data.owner}'
      if ($LASTEXITCODE -eq 0 -and (@($currentOwner) -join "`n").Trim() -eq $releaseLockOwner) {
        kubectl delete configmap $releaseLockName -n $Namespace --wait=true | Out-Null
        if ($LASTEXITCODE -ne 0) { Write-Warning "release lock cleanup failed; inspect '$releaseLockName' before the next release" }
      } else {
        Write-Warning "release lock owner changed or cannot be read; inspect '$releaseLockName' before the next release"
      }
    }
  } catch {
    Write-Warning "release lock cleanup failed; inspect '$releaseLockName' before the next release"
  } finally {
    Pop-Location
  }
}
