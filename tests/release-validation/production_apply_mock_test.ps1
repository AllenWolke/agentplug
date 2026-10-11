$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$root = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$apply = Join-Path $root 'deploy/k8s/production/apply.ps1'
$manifestRoot = Join-Path $root 'deploy/k8s/production'
$digest = '1' * 64
# Share the complete safe bundle fixture with the Python structural tests.
$fixture = & python -c "import runpy,yaml; print(yaml.safe_dump_all(runpy.run_path('tests/release-validation/production_release_preflight_test.py')['bundle']()))"
if ($LASTEXITCODE -ne 0) { throw 'could not render release fixture' }
$renderedFixture = @($fixture) -join "`n"
$allKeys = @{}
foreach ($key in @('DB_DSN','BROWSER_GATEWAY_TOKEN','INTERNAL_TOKEN','INTERNAL_SIGNING_SECRET','KNOWLEDGE_DATABASE_DSN','PLATFORM_CONTEXT_PRIVATE_KEY','PLATFORM_CONTEXT_PUBLIC_KEY','METRIC_RUNNER_TOKEN','CHECKPOINT_DSN','context-public.b64','issuer_url','client_id','client_secret','step_up_redirect_url')) {
  $allKeys[$key] = 'YQ=='
}
$global:releaseTestState = @{
  rendered = $renderedFixture
  secret = (@{data = $allKeys} | ConvertTo-Json -Compress)
  events = [System.Collections.Generic.List[string]]::new()
  locked = $false
  owner = ''
  failMigration = $false
  failSBOM = $false
  failSignature = $false
  failRollout = ''
  dirty = $false
  missingSecret = $false
  missingNamespace = $false
}
$global:releaseTestState.commit = 'a' * 40
$manifestFile = New-TemporaryFile
$validator = Join-Path $root 'scripts/validate_production_release.py'
$draft = $global:releaseTestState.rendered | python $validator --namespace lexagent --draft-manifest --commit $global:releaseTestState.commit
if ($LASTEXITCODE -ne 0) { throw 'could not build release manifest fixture' }
Set-Content -LiteralPath $manifestFile.FullName -Value (@($draft) -join "`n") -Encoding utf8

function global:git {
  $global:LASTEXITCODE = 0
  if (@($args) -contains 'status') {
    if ($global:releaseTestState.dirty) { return ' M deploy/k8s/production/config.yaml' }
    return
  }
  return $global:releaseTestState.commit
}

function global:kubectl {
  $parts = @($args)
  $verb = $parts[0]
  switch ($verb) {
    'kustomize' {
      $global:LASTEXITCODE = 0
      return $global:releaseTestState.rendered
    }
    'get' {
      if ($parts[1] -eq 'namespace') {
        $global:releaseTestState.events.Add('get-namespace')
        $global:LASTEXITCODE = if ($global:releaseTestState.missingNamespace) { 1 } else { 0 }
        if ($global:releaseTestState.missingNamespace) { return }
        return 'namespace/lexagent'
      }
      if ($parts[1] -eq 'secret') {
        $global:releaseTestState.events.Add("get-secret:$($parts[2])")
        $global:LASTEXITCODE = if ($global:releaseTestState.missingSecret) { 1 } else { 0 }
        if ($global:releaseTestState.missingSecret) { return }
        return $global:releaseTestState.secret
      }
      if ($parts[1] -eq 'configmap') {
        $global:LASTEXITCODE = 0
        return $global:releaseTestState.owner
      }
    }
    'create' {
      if ($parts[1] -ne 'configmap') { throw 'unexpected create' }
      $global:releaseTestState.events.Add('create-lock')
      if ($global:releaseTestState.locked) { $global:LASTEXITCODE = 1; return }
      $global:releaseTestState.locked = $true
      $global:releaseTestState.owner = (@($parts | Where-Object { $_ -like '--from-literal=owner=*' })[0] -replace '^--from-literal=owner=', '')
      $global:LASTEXITCODE = 0
      return
    }
    'delete' {
      if ($parts[1] -eq 'configmap') {
        $global:releaseTestState.events.Add('delete-lock')
        $global:releaseTestState.locked = $false
      } else {
        $global:releaseTestState.events.Add("delete-job:$($parts[2])")
      }
      $global:LASTEXITCODE = 0
      return
    }
    'apply' {
      $document = @($input) -join "`n"
      $kind = [regex]::Match($document, '(?m)^kind:\s*(\w+)').Groups[1].Value
      $name = [regex]::Match($document, '(?m)^  name:\s*([^\s]+)').Groups[1].Value
      $global:releaseTestState.events.Add("apply:$kind/$name")
      $global:LASTEXITCODE = 0
      return
    }
    'wait' {
      $job = @($parts | Where-Object { $_ -like 'job/*' })[0]
      $global:releaseTestState.events.Add("wait:$job")
      $global:LASTEXITCODE = if ($global:releaseTestState.failMigration -and $job -eq 'job/platform-schema-migrate') { 1 } else { 0 }
      return
    }
    'rollout' {
      $global:releaseTestState.events.Add("rollout:$($parts[2])")
      $global:LASTEXITCODE = if ($parts[2] -eq $global:releaseTestState.failRollout) { 1 } else { 0 }
      return
    }
  }
  throw "unexpected kubectl command: $($parts -join ' ')"
}

function global:cosign {
  $verb = @($args)[0]
  $global:releaseTestState.events.Add("cosign:$verb")
  if ($verb -eq 'verify' -and @($args) -notcontains "source_commit=$($global:releaseTestState.commit)") {
    throw 'signature was not bound to the candidate commit'
  }
  $global:LASTEXITCODE = if (($verb -eq 'verify-attestation' -and $global:releaseTestState.failSBOM) -or ($verb -eq 'verify' -and $global:releaseTestState.failSignature)) { 1 } else { 0 }
}

function Assert-True([bool]$condition, [string]$message) {
  if (-not $condition) { throw $message }
}

try {
  & $apply -Namespace lexagent -KustomizePath $manifestRoot -ReleaseManifestPath $manifestFile.FullName -SignatureIdentity signer -SignatureIssuer issuer
  $events = $global:releaseTestState.events
  Assert-True (-not $global:releaseTestState.locked) 'successful release left its lock behind'
  Assert-True ($events.IndexOf('create-lock') -lt $events.IndexOf('delete-job:platform-schema-migrate')) 'migration Job was deleted before lock acquisition'
  Assert-True ($events.IndexOf('get-secret:lexagent-oidc-secret') -lt $events.IndexOf('apply:Namespace/lexagent')) 'Namespace was mutated before Secret preflight'
  Assert-True ($events.IndexOf('apply:NetworkPolicy/default-deny') -lt $events.IndexOf('apply:Job/platform-schema-migrate')) 'deny baseline was not installed before migration'
  Assert-True ($events.IndexOf('apply:NetworkPolicy/platform-migration-traffic') -lt $events.IndexOf('apply:Job/platform-schema-migrate')) 'migration egress policy was not installed before migration'
  foreach ($target in @('apply:NetworkPolicy/frontend-platform-traffic','apply:NetworkPolicy/platform-app-traffic','apply:Deployment/platform-app')) {
    Assert-True ($events.IndexOf('wait:job/platform-schema-migrate') -lt $events.IndexOf($target)) 'runtime changed before migration completed'
  }
  Assert-True ($events.Contains('rollout:deployment/metric-runner')) 'runner rollout was not checked'
  Assert-True (@($events | Where-Object { $_ -eq 'cosign:verify-attestation' }).Count -eq 6) 'all six unique workload image SBOMs were not verified'
  Assert-True ($events.IndexOf('cosign:verify-attestation') -lt $events.IndexOf('create-lock')) 'SBOM verification happened after release mutation'
  Assert-True ($events[$events.Count - 1] -eq 'delete-lock') 'lock was not released last'

  $events.Clear()
  $global:releaseTestState.commit = 'b' * 40
  $staleRejected = $false
  try { & $apply -Namespace lexagent -KustomizePath $manifestRoot -ReleaseManifestPath $manifestFile.FullName -SignatureIdentity signer -SignatureIssuer issuer }
  catch { $staleRejected = $_.Exception.Message -like '*structural preflight*' }
  Assert-True $staleRejected 'manifest for a different commit was not rejected'
  Assert-True (-not @($events | Where-Object { $_ -eq 'create-lock' -or $_ -like 'apply:*' }).Count) 'stale release manifest mutated cluster'
  $global:releaseTestState.commit = 'a' * 40

  $events.Clear()
  $global:releaseTestState.dirty = $true
  $dirtyRejected = $false
  try { & $apply -Namespace lexagent -KustomizePath $manifestRoot -ReleaseManifestPath $manifestFile.FullName -SignatureIdentity signer -SignatureIssuer issuer }
  catch { $dirtyRejected = $_.Exception.Message -like '*clean Git checkout*' }
  Assert-True $dirtyRejected 'dirty release source was not rejected'
  Assert-True (-not @($events | Where-Object { $_ -eq 'create-lock' -or $_ -like 'apply:*' }).Count) 'dirty release source mutated cluster'
  $global:releaseTestState.dirty = $false

  $events.Clear()
  $global:releaseTestState.missingSecret = $true
  $missingSecretRejected = $false
  try { & $apply -Namespace lexagent -KustomizePath $manifestRoot -ReleaseManifestPath $manifestFile.FullName -SignatureIdentity signer -SignatureIssuer issuer }
  catch { $missingSecretRejected = $_.Exception.Message -like '*External Secret*missing*' }
  Assert-True $missingSecretRejected 'missing external Secret was not rejected'
  Assert-True (-not @($events | Where-Object { $_ -eq 'create-lock' -or $_ -like 'apply:*' -or $_ -like 'delete-job:*' }).Count) 'missing Secret mutated release resources'
  $global:releaseTestState.missingSecret = $false

  $events.Clear()
  $global:releaseTestState.missingNamespace = $true
  $missingNamespaceRejected = $false
  try { & $apply -Namespace lexagent -KustomizePath $manifestRoot -ReleaseManifestPath $manifestFile.FullName -SignatureIdentity signer -SignatureIssuer issuer }
  catch { $missingNamespaceRejected = $_.Exception.Message -like '*target namespace*must be provisioned*' }
  Assert-True $missingNamespaceRejected 'missing namespace was not rejected'
  Assert-True (-not @($events | Where-Object { $_ -eq 'create-lock' -or $_ -like 'apply:*' }).Count) 'missing namespace mutated release resources'
  $global:releaseTestState.missingNamespace = $false

  $events.Clear()
  $global:releaseTestState.failSBOM = $true
  $rejectedSBOM = $false
  try { & $apply -Namespace lexagent -KustomizePath $manifestRoot -ReleaseManifestPath $manifestFile.FullName -SignatureIdentity signer -SignatureIssuer issuer }
  catch { $rejectedSBOM = $_.Exception.Message -like '*signed image SBOM verification failed*' }
  Assert-True $rejectedSBOM 'missing signed image SBOM was not rejected'
  Assert-True (-not @($events | Where-Object { $_ -eq 'create-lock' -or $_ -like 'apply:*' -or $_ -like 'delete-job:*' }).Count) 'missing image SBOM mutated the release'
  $global:releaseTestState.failSBOM = $false

  $events.Clear()
  $global:releaseTestState.failSignature = $true
  $rejectedSignature = $false
  try { & $apply -Namespace lexagent -KustomizePath $manifestRoot -ReleaseManifestPath $manifestFile.FullName -SignatureIdentity signer -SignatureIssuer issuer }
  catch { $rejectedSignature = $_.Exception.Message -like '*artifact signature verification failed*' }
  Assert-True $rejectedSignature 'wrong image signature was not rejected'
  Assert-True (-not @($events | Where-Object { $_ -eq 'create-lock' -or $_ -like 'apply:*' -or $_ -like 'delete-job:*' }).Count) 'signature failure mutated the release'
  $global:releaseTestState.failSignature = $false

  $events.Clear()
  $global:releaseTestState.locked = $true
  $global:releaseTestState.owner = 'other-release'
  $rejected = $false
  try { & $apply -Namespace lexagent -KustomizePath $manifestRoot -ReleaseManifestPath $manifestFile.FullName -SignatureIdentity signer -SignatureIssuer issuer }
  catch { $rejected = $_.Exception.Message -like '*another release holds*' }
  Assert-True $rejected 'concurrent release was not rejected'
  Assert-True (-not @($events | Where-Object { $_ -like 'delete-job:*' }).Count) 'concurrent release deleted a Job'
  Assert-True ($global:releaseTestState.locked -and $global:releaseTestState.owner -eq 'other-release') 'concurrent release removed another owner lock'

  $events.Clear()
  $global:releaseTestState.locked = $false
  $global:releaseTestState.failMigration = $true
  $failed = $false
  try { & $apply -Namespace lexagent -KustomizePath $manifestRoot -ReleaseManifestPath $manifestFile.FullName -SignatureIdentity signer -SignatureIssuer issuer }
  catch { $failed = $_.Exception.Message -like '*platform schema migration did not complete*' }
  Assert-True $failed 'migration failure was not surfaced'
  Assert-True (-not @($events | Where-Object { $_ -like 'apply:Deployment/*' }).Count) 'migration failure replaced a workload'
  Assert-True (-not @($events | Where-Object { $_ -in @('apply:NetworkPolicy/frontend-platform-traffic', 'apply:NetworkPolicy/platform-app-traffic') }).Count) 'migration failure changed the previous runtime network boundary'
  Assert-True (-not $global:releaseTestState.locked) 'migration failure left the release lock behind'
  $global:releaseTestState.failMigration = $false

  $events.Clear()
  $global:releaseTestState.failRollout = 'deployment/frontend'
  $failedReadiness = $false
  try { & $apply -Namespace lexagent -KustomizePath $manifestRoot -ReleaseManifestPath $manifestFile.FullName -SignatureIdentity signer -SignatureIssuer issuer }
  catch { $failedReadiness = $_.Exception.Message -like '*frontend rollout failed*' }
  Assert-True $failedReadiness 'required frontend readiness failure was not surfaced'
  Assert-True (-not $global:releaseTestState.locked) 'readiness failure left the release lock behind'
  Write-Host 'production release ordering and lock mock PASS'
} finally {
  Remove-Item Function:\kubectl -ErrorAction SilentlyContinue
  Remove-Item Function:\cosign -ErrorAction SilentlyContinue
  Remove-Item Function:\git -ErrorAction SilentlyContinue
  Remove-Variable releaseTestState -Scope Global -ErrorAction SilentlyContinue
  Remove-Item -LiteralPath $manifestFile.FullName -Force -ErrorAction SilentlyContinue
}
