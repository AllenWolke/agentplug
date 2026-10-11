# 独立初始化、升级与日常启动


日常 `up` 只启动常驻服务，基础 Compose 不包含初始化任务，也不依赖停止的初始化容器。初始化定义单独保存在 `deploy/compose/compose.init.yaml`；脚本只在显式初始化或升级时加载，使用当前项目的同版本镜像，通过 `docker compose run --rm --no-deps -T` 执行。每步完成或失败后自动删除临时容器；任一步非零退出立即中止，不启动应用、不自动重试副作用。

初始化创建空库的表、索引、权限结构和消息主题；升级只应用缺失的版本化结构变更。它不导入其他项目数据，不重建已有账号，也不发布 Agent 或授予业务权限。`init` 和 `upgrade` 使用相同的幂等初始化流程，但分别表达首次部署与已有部署升级的用途。

脚本会先检查目标项目的实际容器状态。应用仍在运行时拒绝 DDL；升级前备份数据库和 Kafka 数据，处理在途执行并进入维护窗口，停止应用后执行。停止与升级时保留数据卷，不能通过删卷解决启动问题。初始化身份具有结构变更权限，应用运行身份只持有运行所需权限。脚本默认构建配置中声明的初始化镜像；使用已构建的同版本镜像时传 `--no-build`。

Kafka 是默认常驻消息队列，设置 `restart: unless-stopped`。Docker 恢复后自动恢复原来运行的服务；明确手动停止的服务需要重新执行 `up`。Docker 重启不执行 Compose 依赖排序，因此平台在启动 Worker 前检查 Kafka 元数据，尚未就绪时退出，由重启策略重试。日常启动不会执行 DDL。

从仓库根目录执行，PowerShell、Linux、macOS 使用相同 Python 入口。先复制并完善 `.env.example` 为受保护的 `.env`。

首次部署：

```text
python scripts/compose.py config --env-file .env
python scripts/init_platform.py --env-file .env
python scripts/compose.py up --env-file .env
python scripts/compose.py status --env-file .env
python scripts/compose.py smoke --env-file .env
```

已有部署更新版本：完成备份和维护准备，保持环境文件与 overlay 一致，然后执行：

```text
python scripts/compose.py down --env-file .env
python scripts/init_platform.py upgrade --env-file .env
python scripts/compose.py up --env-file .env
```

`down` 保留数据卷；`reset --force` 会删除数据，不属于升级流程。日常重启只运行 `up`，不运行初始化脚本。启用示例或沙箱时，按[部署说明](README-production.md)在上述命令中使用相同的 `--examples`、`--runtime`、`--profile` 及全部 `--env-file`。

| 脚本步骤 | 用途 | 容器生命周期 |
|---|---|---|
| `platform-migrate` | PostgreSQL 平台结构初始化／版本升级 | 临时执行，结束自动删除 |
| `kafka-topic-bootstrap` | 幂等创建平台消息、身份事件和死信主题 | 临时执行，结束自动删除 |

公开版没有监管 LangGraph 业务，公共 State／Checkpoint 的表由平台结构初始化统一处理，因此不需要独立 `checkpoint-bootstrap`。空库初始化后仍需按[已有用户授权指南](../../docs/开发者指南/业务Agent挂载与已有用户授权指南.md)建立首位管理员、发布和授权业务 Agent。

`status` 显示实际服务状态；旧部署遗留的一次性容器会识别为 `completed (exit 0)` 或 `FAILED`，新版脚本执行后不会留下这类容器。运行中的服务健康检查不替代业务调用验收。

初始化失败时，可传 `--diagnostic-directory .local-secrets/init-diagnostics` 将错误详情保存到受保护目录。默认终端只显示失败步骤和退出码；诊断目录可能包含连接信息，应保持私有。
