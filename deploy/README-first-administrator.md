# 首次生产管理员与 OIDC 绑定引导

平台生产模式禁止 demo 主体引导。全新数据库完成平台 Schema 迁移后，使用同一候选版本的 `bootstrap-admin` 维护命令创建第一个组织、管理员和明确的 OIDC `issuer/sub` 绑定；此命令不启动 HTTP 服务，不接收浏览器头、不使用开发登录、不授予 Agent 运行 Grant。

## 前置条件与配置

先停用入口和所有写入者，确认是需要初始化的目标数据库，并完成批准版本的 `migrate`。命令只接受当前平台 Schema/checksum；组织、主体、认证绑定、运行授权等初始化事实已经存在时（包括停用或撤销状态）都拒绝执行；迁移写入的版本化角色定义和连续性锁种子不视为人员初始化。后续人员、组织、角色与 OIDC 绑定通过正常受控管理 API 创建，不通过此命令恢复或修改。

由部署维护者从 [JSON 结构示例](bootstrap-admin.example.json)创建私有文件，例如 `/secure/agentplug/first-admin.json`。示例的空值和 REPLACE 值不可直接运行。

- `version` 固定为 1，拒绝未知、重复字段及额外 JSON 文档。
- `db_dsn` 是明确指定用户、密码、主机和数据库的 PostgreSQL URL，例如 `postgresql://bootstrap_operator:PRIVATE_PASSWORD@postgres.example.internal:5432/agentplug?sslmode=verify-full`。该例子的密码和主机必须替换；CA 由部署者的 PostgreSQL 客户端信任配置提供。使用独立、非 postgres/root 的引导 DML 账户；它仅获得平台数据表的 `SELECT,INSERT,UPDATE,DELETE`、必要序列的 `USAGE/SELECT`及版本表的 `SELECT`，不含 DDL、数据库/Schema所有权、转授权、角色继承或其他Schema数据权限。密码至少 16 字节，拒绝已知占位与重复字符。连接远端库时按数据库/代理方案核验 TLS，不能把配置长度检查当作加密连接证明。
- 填入自己的 `tenant_id/name`、`department_id/name`、`application_id/name` 和 `principal_id`。ID 使用 1–128 位 ASCII 字母数字及点、下划线、连字符，名称可使用中文。固定创建一个 `user` 主体并绑定版本化超级管理员管理角色，不默认获得业务Agent运行权，不是任意角色或资源Grant配置入口。
- `oidc_issuer` 必须与可信 OAuth2 Proxy 的真实 HTTPS issuer 一致；`oidc_subject` 必须是部署方已核验的该管理员在 IdP 中的原始稳定 `sub`。用户名或邮箱不自动等同于 `sub`，代理转发的身份也不能作为未经核验的批准依据。
- `operator_id` 和 `approval_reference` 是真实维护者及本次变更引用的受控标识。审计保存操作主体、组织作用域与引用；不保存 DSN、密码或原始 issuer/sub 到审计摘要/Outbox。

POSIX 配置文件须为普通文件、仅所有者可读（0400/0600），父目录只允许维护者访问；拒绝符号链接和对其他用户开放的文件。Windows 用 ACL 限制读取者。文件仍含密码和个人身份信息，不提交 Git、不写入日志。初始化结束后按维护制度撤销引导账户或收回其写权限，并移除临时私有配置；不能删除数据库审计事实。

## Linux / Windows 本地维护

`python scripts/local.py build` 会构建原生 `bootstrap-admin`，随后执行：

```text
python scripts/local.py bootstrap-admin --config /secure/agentplug/first-admin.json
```

Windows 使用对应绝对路径。启动器只传递基本系统环境，不从 Shell 的 `DB_DSN`、内部令牌、RAG 或签名密钥推断初始化配置。也可在 `platform` 目录用批准源码直接构建：

```text
go build -trimpath -o /secure/agentplug/bootstrap-admin ./cmd/bootstrap-admin
/secure/agentplug/bootstrap-admin --config /secure/agentplug/first-admin.json
```

维护机器需要可达数据库；不是把此命令安装为长期 systemd 服务。Kubernetes 部署同样可在获批维护主机上执行，数据库与 TLS/代理路由由部署方提供，使用的源码版本必须与迁移/运行版本一致。

## Docker 维护

批准的平台镜像包含 `/app/bootstrap-admin`。单独运行此命令，使用已批准平台 digest、数据库可达的受控网络、只读私有配置挂载；不要使用带迁移/平台其他秘密的长期服务环境。

Linux 镜像 UID/GID 为 10001。维护者须把专用配置副本的读取权限交给这个 UID，并保持文件模式 0400/0600；不要为解决容器读取错误把文件改成 0644。Windows Docker Desktop 的挂载权限映射需要实际验证，不能仅凭宿主 `chmod` 宣称可读。

对应 [Docker 生产项目](compose/README-production.md)的命令形状：

```text
docker run --rm --pull never --network agentplug-production_default --read-only --cap-drop ALL --security-opt no-new-privileges:true --memory 256m --pids-limit 64 --mount type=bind,source=/secure/agentplug/first-admin.json,target=/run/secrets/first-admin.json,readonly --entrypoint /app/bootstrap-admin APPROVED_PLATFORM_IMAGE_AT_SHA256 --config /run/secrets/first-admin.json
```

`APPROVED_PLATFORM_IMAGE_AT_SHA256` 必须替换为实际获批完整 digest；网络名以实际生产项目为准。该命令只获得配置内 DML 账户，不授予 Docker socket、宿主文件访问或应用运行 Secret。首次初始化完成后再启动平台、Agent 和前端并开放 TLS 入口。

## 成功、失败和复验

成功只输出 `FIRST ADMINISTRATOR BOOTSTRAP PASS` 并退出 0。租户、部门、应用、主体、OIDC 绑定、审计和 Outbox 在同一事务中提交；审计或 Outbox 失败则回滚身份写入。PostgreSQL 会话咨询锁与串行化事务防止并发产生两个初始管理员，锁由自己的连接释放。

失败退出非零，终端输出不含底层 SQL 错误、配置值或密码。先检查私有配置、账户权限、Schema、部分 IAM 状态和已有审计事实，不重复试图“修复”停用角色，也不删表、删绑定或打开 demo 引导。成功后执行真实 OIDC 登录，核对组织及角色，验证未绑定 `sub` 拒绝，再通过管理入口配置策略、Agent 版本、端点和精确 Grant。

项目的真实 SQL 复验入口为 `python scripts/verify_public_knowledge_postgres.py --suite administration`。需要本地已存在的 `pgvector/pgvector:pg16` 镜像及Go依赖。工具运行实际完整迁移与首管理员安全场景、只读盘点CLI，使用随机数据库容器和回环临时端口，结束删除自己的容器、临时凭据和结果目录，不访问原项目或面试副本数据库。它证明事务/并发/授权边界，不等同于访问部署方真实IdP，也不替代正式集群、TLS与OIDC登录验收。CI首管理员SQL任务使用同一PostgreSQL验证入口，要求指定测试通过且禁止跳过；本地通过不代表完整CI和最终运行验收已通过。
