param([switch]$Apply)
$ErrorActionPreference = 'Stop'
# 只删除能够确认归属、无标签且没有任何容器引用的历史构建。
$containers = @(docker ps -aq)
if ($LASTEXITCODE -ne 0) { throw 'Cannot inspect containers' }
$used = @{}
foreach ($container in $containers) {
    $info = docker inspect $container | ConvertFrom-Json
    if ($LASTEXITCODE -ne 0) { throw 'Cannot resolve container image' }
    $used[$info[0].Image] = $true
}
$ids = @(docker images --filter dangling=true --format '{{.ID}}')
if ($LASTEXITCODE -ne 0) { throw 'Cannot list images' }
foreach ($id in $ids) {
    $image = (docker image inspect $id | ConvertFrom-Json)[0]
    if ($LASTEXITCODE -ne 0) { throw 'Cannot inspect image' }
    $project = $image.Config.Labels.'com.docker.compose.project'
    if ($project -ne 'lexagent-release-verify' -or $used.ContainsKey($image.Id) -or $image.RepoTags.Count -gt 0) { continue }
    Write-Output "superseded=$($image.Id) project=$project service=$($image.Config.Labels.'com.docker.compose.service')"
    if ($Apply) {
        # 不使用force；并发新增容器引用时让Docker拒绝删除。
        docker image rm $image.Id
        if ($LASTEXITCODE -ne 0) { throw "Image deletion refused: $id" }
    }
}
