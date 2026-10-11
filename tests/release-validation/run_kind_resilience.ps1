param(
    [string]$ClusterName = "lexagent-release-verify",
    [string]$KindPath = ".tools/kind.exe",
    [switch]$KeepCluster
)

$ErrorActionPreference = "Stop"
$workspace = (Resolve-Path (Join-Path $PSScriptRoot "../..")).Path
$kind = (Resolve-Path (Join-Path $workspace $KindPath)).Path
$clusterConfig = Join-Path $workspace "tests/release-validation/kind-multinode.yaml"
$workload = Join-Path $workspace "tests/release-validation/kind-frontend-workload.yaml"
$evidenceDir = Join-Path $workspace "tmp/release-validation/kind-resilience-$([DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ'))"
$evidence = Join-Path $evidenceDir "result.txt"
New-Item -ItemType Directory -Force $evidenceDir | Out-Null

function Record([string]$Title, [scriptblock]$Action) {
    "`n===== $Title =====" | Tee-Object -FilePath $evidence -Append
    & $Action 2>&1 | Tee-Object -FilePath $evidence -Append
    if ($LASTEXITCODE -ne 0) { throw "$Title failed with exit code $LASTEXITCODE" }
}

$existingClusters = @(& $kind get clusters)
if ($LASTEXITCODE -ne 0) { throw "cannot inspect existing clusters" }
if ($existingClusters -contains $ClusterName) { throw "cluster already exists; use a new isolated ClusterName" }
try {
    Record "CREATE THREE-NODE CLUSTER" { & $kind create cluster --name $ClusterName --config $clusterConfig --wait 180s }
    Record "LOAD PROJECT IMAGE" { & $kind load docker-image lexagent-release-verify-frontend:latest --name $ClusterName }
    Record "APPLY PROJECT WORKLOAD" { kubectl --context "kind-$ClusterName" apply -f $workload }
    Record "INITIAL ROLLOUT" { kubectl --context "kind-$ClusterName" -n lexagent-resilience rollout status deployment/frontend --timeout=180s }
    Record "INITIAL DISTRIBUTION" { kubectl --context "kind-$ClusterName" -n lexagent-resilience get pods -l app=frontend -o wide }
    Record "HEALTH ENDPOINT" { kubectl --context "kind-$ClusterName" -n lexagent-resilience exec deployment/frontend -- wget -qO- http://127.0.0.1/healthz }

    $before = kubectl --context "kind-$ClusterName" -n lexagent-resilience get pods -l app=frontend -o jsonpath='{.items[0].metadata.name}'
    Record "POD DELETE" { kubectl --context "kind-$ClusterName" -n lexagent-resilience delete pod $before --wait=true }
    Record "POD REPLACEMENT READY" { kubectl --context "kind-$ClusterName" -n lexagent-resilience rollout status deployment/frontend --timeout=180s }
    $afterNames = kubectl --context "kind-$ClusterName" -n lexagent-resilience get pods -l app=frontend -o jsonpath='{range .items[*]}{.metadata.name}{"`n"}{end}'
    if ($afterNames -contains $before) { throw "deleted pod $before was not replaced" }
    "deleted_pod=$before`nreplacement_pods=$($afterNames -join ',')" | Tee-Object -FilePath $evidence -Append

    $worker = kubectl --context "kind-$ClusterName" get nodes -l '!node-role.kubernetes.io/control-plane' -o jsonpath='{.items[0].metadata.name}'
    Record "CORDON WORKER" { kubectl --context "kind-$ClusterName" cordon $worker }
    Record "DRAIN WORKER" { kubectl --context "kind-$ClusterName" drain $worker --ignore-daemonsets --delete-emptydir-data --timeout=180s }
    Record "NODE FAILOVER READY" { kubectl --context "kind-$ClusterName" -n lexagent-resilience rollout status deployment/frontend --timeout=180s }
    Record "POST-FAILOVER DISTRIBUTION" { kubectl --context "kind-$ClusterName" -n lexagent-resilience get pods -l app=frontend -o wide }
    Record "UNCORDON WORKER" { kubectl --context "kind-$ClusterName" uncordon $worker }

    Record "ROLLING UPDATE" { kubectl --context "kind-$ClusterName" -n lexagent-resilience set env deployment/frontend RELEASE_MARKER=v2 }
    Record "ROLLING UPDATE READY" { kubectl --context "kind-$ClusterName" -n lexagent-resilience rollout status deployment/frontend --timeout=180s }
    Record "FINAL STATE" { kubectl --context "kind-$ClusterName" -n lexagent-resilience get deployment,pod,pdb -o wide }
    Record "FINAL HEALTH" { kubectl --context "kind-$ClusterName" -n lexagent-resilience exec deployment/frontend -- wget -qO- http://127.0.0.1/healthz }
}
finally {
    if (-not $KeepCluster) {
        & $kind delete cluster --name $ClusterName 2>&1 | Tee-Object -FilePath $evidence -Append
    }
}
