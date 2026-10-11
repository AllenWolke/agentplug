# 外部 PostgreSQL 出站覆盖层

把 `REPLACE_WITH_APPROVED_POSTGRES_CIDR` 替换为实际批准的固定 PostgreSQL 端点或出站网关 CIDR。本覆盖层只修改平台迁移 Job 与平台运行进程的 PostgreSQL 出站规则，业务 Agent 通过平台能力访问业务数据。

该模板不能直接发布。地址动态变化时采用批准的固定网关或具备准入验证的 FQDN-aware CNI，不能以宽泛网段替代。目标集群需要验证 DNS、PostgreSQL 成功和无关目标拒绝，并保留数据库账户 DDL/DML 分离。

公共向量数据库配置将在公共知识与部署工作包补齐；这里不隐式授权 PostgreSQL 连接。生产入口见[发布说明](../../production/README.md)。
