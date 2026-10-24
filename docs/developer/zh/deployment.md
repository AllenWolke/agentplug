# 本地、Docker 与 Kubernetes 部署

[入门路线](README.md) · [English](../en/deployment.md)

部署方式改变进程的位置，不改变公司 / 部门 / Agent 的授权模型，也不免除策略发布和真实业务验收。第一次部署优先用[Compose 快速开始](quickstart.md)；本地源码适合修改平台，K8s 适合已有集群运维能力的团队。

## 本地源码与主机进程

### 准备基础设施和配置

安装 Go 1.26.10+、Node.js 20+、Python 3.12+、PostgreSQL 16 + pgvector。预置业务数据库、可执行迁移的 schema owner 和独立 `platform_runtime` DML 角色；本地开发迁移也可通过明确的 `PLATFORM_DEV_RUNTIME_PASSWORD` 预置运行角色。数据库连接必须指向你实际准备的地址和账号。

在仓库根目录创建私有目录，复制公开模板，填写真实值：

```text
python -c "from pathlib import Path; import shutil; d=Path('.local-secrets/local'); d.mkdir(parents=True,exist_ok=True); [shutil.copyfile('deploy/local/'+n+'.env.example',d/(n+'.env')) for n in ('migration','platform','frontend','runner') if not (d/(n+'.env')).exists()]"
```

| 私有文件 | 需要核对什么 |
| --- | --- |
| `migration.env` | `DB_DSN` 是迁移账号；本地预置角色时填写运行密码，生产留空且由 DBA 管理 |
| `platform.env` | `DB_DSN` 是 DML 账号；内部、网关、签名、Runner 密钥；匹配 Ed25519 公私钥；关闭演示种子 |
| `frontend.env` | `PLATFORM_URL` 指向平台 8080；`PLATFORM_GATEWAY_TOKEN` 匹配平台网关密钥；`FRONTEND_AUTH_MODE=local` |
| `runner.env` | `LEXAGENT_METRIC_SERVICE_TOKEN` 匹配平台 `PLATFORM_METRIC_RUNNER_TOKEN`，不附带其他秘密 |

公开模板中的 `replace-...` 不是有效值。主机入口按字面值读取 `.env`，不支持 shell 表达式；不能把根 Compose `.env` 整份下发给每个进程。POSIX 配置为 0600，Windows 使用私有 ACL。

本地主机可使用 `EVENT_BUS_MODE=disabled`、`PLATFORM_NOTIFICATION_ADAPTER=none` 先验证平台开发；这不提供 Kafka 投递验收。需要事件功能时自行提供 Kafka、主题和连接配置。使用知识能力还需平台知识 DSN / 索引配置，生产校验要求知识连接与遥测端点。

### 构建、迁移、建立管理员

```text
python scripts/local.py build
python scripts/local.py run migrate --env-file .local-secrets/local/migration.env
```

构建成功输出 `NATIVE BUILD PASS`，制品位于 `.local-build/bin/` 和 `frontend/dist/`。平台启动不会替你执行迁移。

将以下配置形状保存为私有 `.local-secrets/local/first-admin.json`，填写实际 **DML DSN**、你选择的 10..128 字节本地密码和明确的操作者标识。下面是模板，不是可以直接运行的凭据：

```json
{
  "version": 1,
  "db_dsn": "postgresql://platform_runtime:REPLACE_WITH_RUNTIME_PASSWORD@127.0.0.1:5432/agentplug?sslmode=disable",
  "tenant_id": "tenant-demo",
  "tenant_name": "Development Company",
  "department_id": "dept-platform",
  "department_name": "Platform Administration",
  "application_id": "app-platform-admin",
  "application_name": "Platform Administration",
  "principal_id": "platform.admin",
  "operator_id": "deployment.operator",
  "local_password": "REPLACE_WITH_YOUR_PRIVATE_PASSWORD",
  "approval_reference": "local-development-initialization"
}
```

```text
python scripts/local.py bootstrap-admin --config .local-secrets/local/first-admin.json
```

这只对空身份库有效；既有环境使用管理界面，不重新初始化。生产 JSON 用真实 OIDC issuer / subject 替换本地密码，见[维护说明](../../../deploy/README-first-administrator.md)。

### 启动和核验

分别在三个终端前台运行：

```text
python scripts/local.py run runner --env-file .local-secrets/local/runner.env
python scripts/local.py run platform --env-file .local-secrets/local/platform.env
python scripts/local.py run frontend --env-file .local-secrets/local/frontend.env
```

模板默认平台 `127.0.0.1:8080`、能力端口 `8081`、Runner `8085`、控制台 `33000`。核验平台 `/health/ready`、前端 `/healthz`，然后登录。停止开发进程使用各终端 Ctrl+C；生产由服务管理器负责。Linux 账号与资源边界见[systemd 部署](../../../deploy/local/README-linux-production.md)。

## Docker Compose 单机部署

[快速开始](quickstart.md)提供准备 → 初始化 → 创建管理员 → 启动 → 健康检查的完整命令。默认 modular 五个服务是开发 / 单机基础环境，不会自动带上业务 Agent。

| 操作 | 命令 / 说明 |
| --- | --- |
| 配置预检 | `python scripts/compose.py config --env-file .env`，不打印密钥 |
| 启动基础栈 | `python scripts/compose.py up --env-file .env` |
| 查看状态 | `python scripts/compose.py status --env-file .env` |
| 基础健康验证 | `python scripts/compose.py smoke --env-file .env` |
| 停止并保留数据 | `python scripts/compose.py down --env-file .env` |
| 数据库版本升级 | 先备份和停写，再 `python scripts/init_platform.py upgrade --env-file .env` |

三个现有示例使用 `--examples`。初始化它们的机器凭据文件后，作为后置配置传入：

```text
python scripts/bootstrap_public_examples.py --prepare-machine-env
python scripts/compose.py config --env-file .env --env-file .local-secrets/public-examples/machines.env --examples
```

离线生成凭据不创建平台主体或权限。实际启动前还要按[交付](delivery.md)配置安装、发布策略和实际端点。该脚本针对仓库三个固定示例，自定义业务 Agent 不复用它的固定 ID 作为自己的身份。

生产按[Compose 生产说明](../../../deploy/compose/README-production.md)设置 TLS / OIDC、独立数据库账号、Secret、备份及恢复；不简单把 `APP_ENV` 改成 production 而保留开发值。

## Kubernetes 集群部署

### 已有基础与需要补齐的内容

默认 [kustomization.yaml](../../../deploy/k8s/production/kustomization.yaml)选择 Namespace、ConfigMap、四个 Deployment、迁移 Job、ServiceAccount、Service、NetworkPolicy 和 Ingress。目录中的其他工作进程、存储和模型 YAML 不都会被默认引用。

目前使用外部 PostgreSQL + pgvector 和模型服务；默认配置事件总线关闭、通知 none，并未提供 Kafka 集群。业务 Agent 的独立 Deployment / Service 由你的业务部署覆盖层提供。平台默认 `replicas: 1` 和 `Recreate`，不是已验收的多实例高可用方案。

准备 Kubernetes 集群、支持 NetworkPolicy 的 CNI、Ingress / TLS、真实 IdP、数据库、镜像仓库与签名体系、遥测收集器。部署端需 kubectl、PowerShell、cosign 和安装 PyYAML 的 Python。Kustomize 的渲染逻辑见 [Kubernetes 官方说明](https://kubernetes.io/docs/tasks/manage-kubernetes-objects/kustomization/)。

### 1. 创建部署者覆盖层

从候选 base 创建自己团队维护的 Kustomize overlay。替换：

- 平台、前端、Runner、OIDC 代理等全部容器的真实不可变镜像摘要；迁移镜像与平台镜像一致。
- 真实 TLS 主机名、OIDC issuer / 登录 / 再认证回调、遥测和模型服务端点。
- 预置外部 Secret，键名匹配 [secret 形状](../../../deploy/k8s/production/secret.example.yaml)和 [OIDC 形状](../../../deploy/k8s/production/oidc-secret.example.yaml)；不得直接应用占位 Secret。
- 迁移账号、平台 DML 账号、知识 DSN，以及最小出站 CIDR / 固定网关。Agent 只访问能力网关和批准的业务目标，不直连平台数据库 / 模型供应商。
- 业务 Agent 的镜像、Service、资源限制、公钥、工作负载 Secret、探针和网络规则。

覆盖示例：[外部 PostgreSQL](../../../deploy/k8s/overlays/external-postgres-example/README.md)、[外部出站](../../../deploy/k8s/overlays/external-egress-example/README.md)。它们仍含必须替换的占位值。

### 2. 只读渲染与发布预检

先确认 kubeconfig context 指向预期集群。以下第一条可在原始模板上查看资源，第二条对**已填写的私有覆盖层**执行结构预检：

```text
kubectl kustomize deploy/k8s/production
```

```powershell
kubectl kustomize .local-secrets/k8s-overlay | python scripts/validate_production_release.py --namespace lexagent
```

候选 base 含占位镜像和端点，预检拒绝是预期行为。不要移除校验或直接 `kubectl apply -f deploy/k8s/production` 绕过发布顺序。

### 3. 准备可审查发布

源码必须已有完整 Git 提交且工作树干净。渲染批准覆盖层，用 `--draft-manifest --commit <完整提交 SHA>` 生成清单草稿，保存到源码外并审查。清单绑定整个渲染配置的 canonical SHA-256 和每个容器镜像；cosign 验证签名、`source_commit` 及 SPDX SBOM。

在真实备份、停写和变更授权准备好后执行，所有参数必须是你的实际发布值：

```powershell
./deploy/k8s/production/apply.ps1 -Namespace lexagent -KustomizePath <批准覆盖层路径> -ReleaseManifestPath <批准清单路径> -SignatureIdentity <签名身份> -SignatureIssuer <签名issuer>
```

脚本核对全部资源和 Secret 依赖，获取发布锁，先完成迁移 Job，再更新工作负载并等待 rollout。不会自动创建外部数据库、IdP 或业务授权。迁移状态以 [schemaversion](../../../platform/internal/schemaversion/schema.go)为准，不要复制旧文档的历史版本号。

### 4. 业务与权限验收

确认探针、实际安装 / Deployment 观测、管理员 OIDC 登录、网络允许 / 拒绝、遥测和备份恢复。空身份库在放开流量前初始化真实 IdP 管理员。再按[交付步骤](delivery.md)为目标公司、部门和用户绑定 Agent，并测试获准用户、未获准用户、跨公司与取消 / 恢复路径。

**这一套是服务化部署的候选基础，不是已经完成所有模块微服务拆分、真实集群运行或高可用测试的证明。** 目标团队需要保留本次集群验收证据。
