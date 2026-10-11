# Compose 部署候选说明

根目录只保留 `compose.yaml`；初始化、示例和独立工具配置集中在 `deploy/compose/`，完整场景与统一脚本见[部署入口](README.md)。平台运行提供基础配置和两个显式可选 overlay。`compose.yaml` 默认启动平台、前端、数据库、Kafka 和 Metric Runner；`deploy/compose/compose.examples.yaml` 增加 Python、Go、Java 三个 SDK 示例；`deploy/compose/compose.runtime.yaml` 增加隔离 Code Runtime，并要求同时加载示例 overlay，使平台路由目标与服务定义一致。

`scripts/compose.py` 默认使用仓库根目录 `.env`。重复传入 `--env-file` 时按命令行顺序交给 Compose，后面的文件按 Compose 规则覆盖前面的同名变量。私有文件不会自动发现或加载。仅校验三层配置：

```powershell
python scripts/compose.py config `
  --env-file .env `
  --env-file .local-secrets/public-runtime-control/compose.env `
  --examples --runtime --profile modular
```

配置通过并完成下述准备后，使用完全相同的 env、overlay 和 profile 参数启动：

```powershell
python scripts/compose.py up `
  --env-file .env `
  --env-file .local-secrets/public-runtime-control/compose.env `
  --examples --runtime --profile modular
```

后续 `status`、`smoke`、`down` 等操作也要选择相同的 overlay。只启用三个示例时传 `--examples`；`--runtime` 必须与 `--examples` 同时传入。基础栈的旧用法仍有效，例如 `python scripts/compose.py config`。`config` 只解析配置，不启动服务、不执行数据库迁移，也不发布 Catalog、Policy、Skill 或授权。

首次部署先执行 `python scripts/init_platform.py`，已有部署在维护窗口执行 `python scripts/init_platform.py upgrade`。两者使用与 `up` 相同的 env、overlay 和 profile 参数；日常 `up` 不执行 DDL。初始化任务单独位于 `deploy/compose/compose.init.yaml`，通过同版本临时容器执行并自动删除。迁移 DSN 使用独立 schema 身份，`PLATFORM_DB_DSN` 只供运行时 DML。

常驻 Kafka 随默认 `modular` 启动并自动恢复，平台在启动消费者前检查 Kafka 元数据。首次结构初始化、升级与故障处理中止说明见[独立初始化指南](README-startup.md)。

启动前需准备完整且受保护的环境文件：基础 `.env` 中应具有该环境所需的 DB、平台、身份和供应商配置；Code 私有 env 应提供经过核验的不可变 Docker CLI 镜像摘要、宿主 Docker socket GID、专用 subnet 与控制器 IP。不要将私有 env、凭据或生成密钥提交到仓库。Code Runtime 的私有 bindings、TLS、签名材料和状态密钥应由运维准备器生成并逐项核验。Compose 中 Docker socket 只挂给 Code 控制器；平台和示例 Agent 不直接访问它。

启用示例还要求三个 Agent 的 Identity client ID/secret 已签发并放入运行环境；服务定义本身不会创建身份。正式调用前，需为确切 Catalog 版本/installation/deployment 发布完整 Policy 和 Function 定义，注册并经人员分离审核发布相应 Skill，准备已批准的模型与知识资产，并分别办理当前调用人和机器主体所需的资源授权。Code 调用还需匹配的运维 Code binding/Profile 与独立人工批准。`example-release-bundle` 输出的是发布请求及可合并策略片段，不会提交审批、发布 Function/Skill 或发放 Grant。

仓库提供 Compose 扩展定义；Code Runtime 的私有运行材料和批准镜像由部署方准备。配置与构建资产存在，不代表生产服务已启动或业务端到端流程已验收。运行新增代码前，先备份并核实目标数据库版本及校验和，再使用独立迁移身份按缺失的显式迁移前滚。平台运行身份只应持有目标数据库 DML 权限，不能承担 DDL 或扩展安装。迁移服务和平台服务必须使用同一候选镜像。

生产前端还需可信 OIDC、Secure Cookie、TLS 和独立再次认证配置；禁止启用演示身份种子。平台私钥只由平台持有。检查镜像摘要、签名、SBOM、数据库/模型/通知/遥测连通性及访问边界后再部署。Compose 健康检查只能证明组件就绪；发布、权限、撤权、业务恢复和总体场景仍需单独验收。

数据库使用 PostgreSQL + pgvector 的独立卷，不得复用旧 MySQL 数据卷。PostgreSQL 部署需已安装 pgvector；独立 `PLATFORM_MIGRATION_DB_DSN` 应具备目标 Schema 的迁移权限，`PLATFORM_DB_DSN` 仅供平台运行时 DML 使用。远程 PostgreSQL 使用验证 CA 和主机名的 TLS 配置。
