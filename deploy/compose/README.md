# Docker Compose 部署入口

所有命令均从仓库根目录执行。根目录只保留 `compose.yaml`，可选配置集中在本目录，由 `scripts/compose.py` 选择。Windows、Linux、macOS 使用相同 Python 入口。

## 文件与场景

| 配置文件 | 场景 | 选择方式 |
| --- | --- | --- |
| 根目录 `compose.yaml` | 默认平台、前端、数据库、Kafka、Metric Runner；`full` 额外提供 MinIO | 默认 `--stack platform`，`--profile modular` 或 `full` |
| `compose.init.yaml` | 数据库初始化、版本升级和 Kafka 主题初始化 | `scripts/init_platform.py` 按需加载 |
| `compose.examples.yaml` | Go、Python、Java 三个业务 Agent 示例 | `--examples` |
| `compose.runtime.yaml` | 隔离 Code Runtime 及示例运行配置 | `--examples --runtime` |
| `compose.eval.yaml` | 独立 Agent Evaluation CLI | `--stack eval` |
| `compose.eval-services.yaml` | 独立评测夹具服务或 Judge Agent | `--stack eval-services --profile fixture` 或 `judge` |
| `compose.compensation.yaml` | 可逆业务 API 参考服务及其独立迁移 | `--stack compensation`，迁移时选 `maintenance` |

可选服务具有独立凭据、网络和运行前提，因此不全部并入默认启动。Compose 支持按场景使用[多个配置文件](https://docs.docker.com/compose/how-tos/multiple-compose-files/merge/)；本项目通过一个脚本提供统一操作入口。

## 平台常用命令

先从 `.env.example` 准备私有 `.env` 并填写活动配置，随后：

```text
python scripts/compose.py config --env-file .env
python scripts/init_platform.py --env-file .env
python scripts/compose.py up --env-file .env
python scripts/compose.py status --env-file .env
python scripts/compose.py smoke --env-file .env
```

需要 SDK 示例时，为各操作使用相同的 `--examples`；启用 Code Runtime 时再加 `--runtime`。运行与迁移凭据分离，首位管理员、示例机器身份与业务授权均需单独准备。

重复 `--env-file` 按参数顺序覆盖同名配置，不会自动加载本机私有文件。首次安装和已有部署升级详见[初始化与启动](README-startup.md)；示例、Code Runtime 和上线条件详见[部署配置](README-production.md)。

`down` 保留数据卷；`reset --force` 删除所选项目数据卷，仅用于明确需要销毁的环境。

## 独立评测工具

评测 CLI 与平台分别构建和运行。以下命令只启动 CLI 并显示帮助，不运行业务评测：

```text
python scripts/compose.py build --stack eval --env-file .env
python scripts/compose.py run --stack eval --env-file .env --service agent-eval --command help
```

`--command` 必须放在最后，其后参数原样交给工具。报告目录、平台地址、会话凭据和实际评测参数见[评测工具说明](../../cli/agent-eval/README.md)。工具不会因为读取到平台环境文件而自动取得平台业务权限。

若需要评测夹具或 Judge，先分别准备其工作负载身份、私有凭据目录和外部平台网络：

```text
python scripts/compose.py config --stack eval-services --profile fixture --env-file .env
python scripts/compose.py up --stack eval-services --profile fixture --env-file .env
python scripts/compose.py status --stack eval-services --profile fixture --env-file .env
```

Judge 使用 `--profile judge`。启动前检查整个配置文件中的必填项；Compose 在选择活动服务前进行变量替换。完整条件见[独立评测开发指南](../../docs/开发者指南/独立AgentEvaluation工具使用指南.md)。

## 可逆业务 API 参考服务

先准备私有运行配置、TLS 材料、独立数据库和既有平台网络，再校验和构建：

```text
python scripts/compose.py config --stack compensation --env-file .env
python scripts/compose.py build --stack compensation --env-file .env
```

在维护窗口使用专用迁移凭据执行独立迁移，然后启动长期服务：

```text
python scripts/compose.py run --stack compensation --profile maintenance --env-file .env --service reversible-api-migrate
python scripts/compose.py up --stack compensation --env-file .env
```

参考 API 的数据库迁移不属于平台初始化。接口的补偿语义与人工处置规则见[运行恢复](../../docs/RUNTIME-RECOVERY.md)，部署定义见[参考服务配置](compose.compensation.yaml)。

## 路径与项目隔离

统一脚本始终指定仓库根目录为 `--project-directory`，因此移动配置文件后，构建上下文、Dockerfile 和相对挂载仍以仓库根目录为基准。

平台项目名为 `agentplug`；三个独立场景分别使用 `agentplug-eval`、`agentplug-eval-services`、`agentplug-compensation`。测试可使用各自的 `-test-*` 后缀，脚本拒绝使用其他场景或其他项目名称。

直接使用 Docker CLI 时也必须明确路径基准，例如：

```text
docker compose --project-directory . --env-file .env -f deploy/compose/compose.eval.yaml --profile manual config --quiet
```

只解析配置不会启动容器、迁移数据库、创建用户或调用模型。日常维护优先使用统一脚本，避免遗漏文件、Profile 或路径基准。
