# PostgreSQL备份与隔离恢复

公开版只使用PostgreSQL；平台及pgvector数据由[备份工具](../../scripts/postgres_backup.py)导出。Python SDK工作流数据在独立PostgreSQL数据库中，必须单独备份；本工具不把跨数据库一致性、对象存储、应用密钥或外部副作用自动纳入同一快照。恢复后须对账备份时点之后的删除、法律保留与撤权，见[数据生命周期](../../docs/DATA-LIFECYCLE.md)。

## 凭据与依赖

需要Python3.11+与匹配源数据库的PostgreSQL客户端pg_dump/pg_restore；Docker模式使用选定数据库容器内的客户端。官方行为见[pg_dump](https://www.postgresql.org/docs/16/app-pgdump.html)和[pg_restore](https://www.postgresql.org/docs/16/app-pgrestore.html)。独立备份角色获得目标业务Schema的USAGE、全部表及序列的SELECT，不授予平台运行角色备份职责或DDL；大对象/扩展的额外授权由DBA按实际对象核验，权限不足时导出失败。

密码来自owner-private的--password-file或AGENTPLUG_BACKUP_POSTGRES_PASSWORD，不放入命令行。Native客户端通过临时0600 PGPASSFILE读取，按[PostgreSQL密码文件规则](https://www.postgresql.org/docs/16/libpq-pgpass.html)转义冒号和反斜杠；执行完删除。Docker源密码只经stdin传递给固定脚本的read，不作为Shell代码求值，也不复制到容器文件。Windows对配置/备份目录设置私有ACL，POSIX采用0700目录及0600文件。

Native模式强制PGSSLMODE=verify-full及--ssl-ca；Docker模式只允许容器内部127.0.0.1，不能用它替代远程TLS。目标数据库应按DBA认证策略验证密码，Compose新卷明确使用SCRAM host认证；初始化参数不会自动修改已有数据库的pg_hba.conf。工具不接受--password命令行参数，不打印客户端错误、DSN、原始SQL或密码。

## 导出

```text
python scripts/postgres_backup.py backup --database agentplug --host postgres.example.internal --user agentplug_backup --ssl-ca /run/secrets/postgres-ca.pem --password-file /run/secrets/postgres-backup-password --output-dir /srv/agentplug-backups --metrics-file /srv/node-exporter-textfiles/agentplug-backup-attempt.prom
```

本地Compose可由维护者显式选择源容器：

```text
python scripts/postgres_backup.py backup --database agentplug --user agentplug_backup --docker-source agentplug-postgres-1 --password-file /private/postgres-backup-password --output-dir /private/agentplug-backups
```

输出为pg_dump原生压缩custom格式.pgdump及format_version=2的.manifest.json，不沿用MySQL SQL/gzip清单。元数据记录数据库名、导出开始时间、完整归档SHA-256和带Schema的基础表清单。单次pg_dump具有数据库一致快照；迁移/跨库协同由部署维护窗口安排。当前工具要求平台/SDK默认ASCII Schema与表名，遇到其他表名明确拒绝，不能静默漏表。

导出先写临时文件，pg_dump成功后由原生pg_restore --list解析目录，再完整解码全部数据块到空设备；仅目录可读不算完整数据校验。归档及清单通过后发布，清单写入失败删除对应归档；错误或空导出不发布完成清单。每个数据库使用独立输出目录/Prometheus实例标签。历史MySQL备份保留在面试副本和私有恢复备份，不可当作本格式直接导入。

## 完整性与告警

```text
python scripts/postgres_backup.py check --output-dir /srv/agentplug-backups --max-age-seconds 86400 --metrics-file /srv/node-exporter-textfiles/agentplug-backup-check.prom
```

无主机pg_restore时可加--reader-container agentplug-postgres-1，仅使用该可信容器的归档解码工具，不连接其数据库。工具校验格式、归档SHA、全部数据块、表目录及带时区的创建时间；过期、异常未来时间、损坏或无备份均退出非零。选择最新完成清单，不在损坏时回退旧清单伪报健康；复制来的备份建议用--manifest指定已批准备份。

指标名称保持兼容：备份尝试写agentplug_backup_attempt_success，检查写agentplug_backup_status/last_success_timestamp/check_timestamp。两项使用不同.prom文件，旧备份校验成功不能覆盖最近导出失败；指标原子替换。结合[备份告警](../observability/prometheus/backup-alerts.yaml)与受保护的node_exporter textfile collector，调度停止、失败、过期、指标缺失均有规则。文件摘要是损坏检测，不是签名或加密；加密、异地副本、保留、Legal Hold由部署制度落实，本工具不自动删除历史备份。

## 隔离恢复

```text
python scripts/postgres_backup.py check --manifest /srv/agentplug-backups/agentplug-TIMESTAMP-NONCE.manifest.json --max-age-seconds 86400 --restore-image pgvector/pgvector:pg16
```

仅使用本地已有的受信PostgreSQL+pgvector镜像，不自动拉取，也没有生产恢复目标参数。创建随机归属标记、network none、无发布端口的临时数据库；原生pg_restore以--single-transaction/--exit-on-error导入全部归档，再核对数据库基础表目录。数据通过stdin送入，不写容器/主机解压SQL文件。结束校验标签并删除自己的容器、tmpfs、凭据和临时文件，Docker不可达时不能宣称清理通过；禁止全局prune。

恢复使用--no-owner/--no-acl，不复制源角色或原授权。正式恢复必须在新受控实例中按DBA批准方案重新配置迁移、运行和备份角色，并验证对象所有权及最小授权；新机器Secret不可用旧归档推断。整库导入成功仍需验证实时撤权、保留/删除事实、工作流续跑、预算/工具账本和外部副作用对账，然后再切换流量，不直接覆盖现有生产实例。

本仓库真实独立验证入口为python scripts/verify_postgres_backup_isolated.py：先运行实际完整平台迁移，创建合成数据，以SELECT角色导出；核对全部表行数/完整行摘要、JSONB/BYTEA/中文/vector/timestamptz及序列，验证快照后源变更不被恢复覆盖、错误密码不发布及指标独立。仅操作自己的数据库，不读取开发库或面试副本。该证据不替代正式业务灾备与部署方RPO/RTO验收。
