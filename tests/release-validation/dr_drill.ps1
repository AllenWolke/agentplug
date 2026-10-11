param([switch]$Execute)
$ErrorActionPreference='Stop'
if (-not $Execute) { throw 'DR drill is destructive to the isolated drill namespace; rerun with -Execute' }
Write-Host 'DR drill order: identity/keys -> database -> Kafka -> object store -> bindings -> workers'
# Production-specific restore commands are injected by the deployment pipeline.
# 生产恢复命令由部署流水线注入；仓库脚本只冻结顺序和验收契约。
