# Kubernetes 生产候选模板

新读者从[三种部署方式及 K8s 步骤](../../../docs/developer/zh/deployment.md#kubernetes-集群部署)或 [English cluster guide](../../../docs/developer/en/deployment.md#kubernetes-cluster-deployment)开始。默认 Kustomization 只包含明确引用的文件，不能直接应用整个目录。平台为模块化单体，业务 Agent 与网关等可独立部署；内部全部模块尚未拆成微服务。

当前模板包含 `platform-app`、`frontend`、`metric-runner`、`oauth2-proxy` 四个 Deployment 和 `platform-schema-migrate` Job。三个业务示例和公共 PostgreSQL + pgvector 部署仍待补齐；目前只完成结构与预检验证，没有部署到真实生产集群。[当前开发状态](../../../README.md#当前状态)。

自建镜像使用 `agentplug` 服务标签并绑定真实不可变摘要。生产配置必须替换所有占位镜像、Ingress/TLS、OIDC、数据库、模型、通知和遥测端点。`secret.example.yaml` 仅描述形状，禁止直接应用。向量知识数据库使用独立的 `KNOWLEDGE_DATABASE_DSN`，公共 Provider 尚未接入时不能把该值当作已具备检索能力。

`apply.ps1` 需要 kubectl、cosign 和带 PyYAML 的 Python。先渲染一次，再验证全部容器（包括 initContainer）的摘要、签名、签署的 SPDX SBOM、Secrets、Namespace、完整提交 SHA 和批准的发布清单。发布清单绑定完整渲染配置的 canonical SHA-256；它不能替代功能与环境验收。候选源码要求干净、已提交，本次改造不自动提交或上传 GitHub。

清单草稿可用 `kubectl kustomize <overlay> | python scripts/validate_production_release.py --namespace lexagent --draft-manifest --commit <完整提交SHA>` 生成。草稿保存到源码外，经审查后作为 `-ReleaseManifestPath`。签名中的 `source_commit` 必须匹配候选，包括外部代理的批准镜像。

只读预检通过后，发布脚本获取 `agentplug-production-release-lock`，执行迁移 Job 并等待成功，再更新工作负载。异常退出留下锁时先确认没有活动发布并检查迁移状态，不能为重试盲目删锁。Schema 版本以候选源码的 [CurrentVersion](../../../platform/internal/schemaversion/schema.go) 与迁移清单为准；历史版本必须匹配已发布摘要，未知或漂移版本拒绝。平台运行账户只提供数据库范围 DML，迁移账户独立，不进入长期服务。迁移前备份和停写，失败调查实际 DDL 状态或恢复批准备份，不删除迁移历史。

新空生产库迁移后、开放流量前，以真实 IdP issuer/subject 初始化首位管理员，见[维护流程](../../README-first-administrator.md)。关闭演示种子，配置可信代理、Secure Cookie 和再次认证。

NetworkPolicy 默认双向拒绝。业务 Agent 只能调用平台公共能力和 DNS，不能直接访问数据库或模型服务。平台及 OIDC 代理使用经批准的固定出站网关；动态域名需批准的 CNI 或固定网关，不能改成宽泛网段。[PostgreSQL覆盖层](../overlays/external-postgres-example/README.md)和[外部出站覆盖层](../overlays/external-egress-example/README.md)中的占位 CIDR 必须替换并在目标 CNI 验证允许与拒绝行为。

应用回滚先停写，保留发布清单与数据库备份。不能用旧镜像直接读取不兼容的新 Schema；数据库恢复与应用版本必须配套并验证历史归属、权限、Outbox 和运行状态。公共知识与索引恢复参考[数据生命周期](../../../docs/DATA-LIFECYCLE.md)，仍需在目标集群验证实际配置、权限、索引版本和恢复结果。
