# 完整实战：从空平台到用户运行自己的 Agent

[开发者路线](README.md) · [English](../en/walkthrough.md)

本实战将[部署快速开始](quickstart.md)、[业务开发](first-agent.md)和[发布与授权](delivery.md)连成一条可执行流程。最终验收是普通部门用户通过平台运行自定义排障助手，获得正确答案；未授权用户无法运行它或读取该用户的会话，普通用户伪造其他公司范围也被拒绝。

## 先运行完整流程

需要 Python 3.12+、Go 1.26.9+、Docker Engine / Docker Desktop 和 Compose v2，以及下载 Python 包、Go 模块和基础镜像的网络。Docker 引擎须处于运行状态。在平台仓库根目录执行：

```text
python -m pip install "cryptography>=50,<51"
python tests/e2e/developer_walkthrough.py --report .tmp/developer-walkthrough-report.json
```

该命令执行真实部署和管理接口调用，会创建临时公司组织、用户、独立机器身份、Agent 版本、策略及使用授权。它把公开源码复制到 `.tmp/` 下的新目录，为该副本生成独立配置、随机密码、端口、Compose 项目、数据卷和镜像标签。它不读取原部署的 `.env` 或复用其数据库。教程 Agent 不调用外部模型，无供应商付费请求。

成功后输出 `PASS` 和证据文件位置，并移除本次临时容器、数据卷、镜像标签、源码副本与虚拟环境。证据保留在 `--report` 指定位置。失败时保留原环境和私有诊断日志，不用新 run ID 重发结果未知的请求。

需要登录验收时增加 `--keep`：

```text
python tests/e2e/developer_walkthrough.py --keep --report .tmp/developer-walkthrough-report.json
```

报告中的 `retained_workspace` 是本次目录。平台地址按报告的 `origin` 访问；初始管理员配置位于该目录的 `source/.local-secrets/first-admin.json`，教程账号密码位于 `source/.local-secrets/tutorial-accounts.json`。这些是本机私有文件，不放入报告、issue、聊天或 Git。完成检查后，替换下方目录占位值：

```text
python tests/e2e/developer_walkthrough.py --cleanup .tmp/<本次目录>
```

失败后可用 `--resume .tmp/<本次目录> --report .tmp/developer-walkthrough-report.json` 继续读取和处理原状态。恢复使用该目录的源码和已完成步骤；若你已经修订平台代码，需要结束旧环境后重新运行全新用例，不能把旧镜像的结果当作新源码已通过。

## 它实际做了哪些工作

| 顺序 | 工作及操作者 | 完成标志 |
| --- | --- | --- |
| 1 | 按快速开始生成配置、初始化数据库、创建首位管理员、启动平台 | 五个基础服务健康，管理员可登录 |
| 2 | `agentctl` 生成 Python 通用工程，复制业务实现、测试与 Schema | 模板所有权验证通过，业务和 SDK 测试无跳过 |
| 3 | 平台管理员任命公司管理员；公司管理员创建与管理部门成员 | 用户属于一个公司，部门管理员身份作用域明确 |
| 4 | `agent.author` 提交 Definition 和 Version；独立平台管理员评测、发布 | 发布记录保留不同的提交人与审批人 |
| 5 | 作者创建六类策略，独立发布者发布并生成快照 | 实际版本、策略 revision / hash 对齐 |
| 6 | 构建并运行真实业务镜像，控制器核验制品与健康探针 | Deployment 记录实际状态，Installation 为 active |
| 7 | 公司管理员创建机器身份并绑定安装，配置部门成员和管理身份 | 当前独立工作负载绑定与部门成员关系有效 |
| 8 | 公司管理员先设置部门 Agent 上限，再单独授予机器执行权；部门管理员批量给业务用户开通当前使用包 | 机器与用户均在允许范围内，有预览、摘要、revision 和逐人办理结果 |
| 9 | `support.user` 登录平台，创建会话、提交任务并读取结果 | run 成功，答案和会话元数据符合业务预期 |
| 10 | 重放同一请求、测试无效输入、未授权访问与公司范围伪造 | 无重复历史，无效输入失败，越权请求被拒绝 |

脚本中可审查的接口流程见 [developer_agent_delivery.py](../../../tests/e2e/developer_agent_delivery.py)，部署、测试和清理流程见 [developer_walkthrough.py](../../../tests/e2e/developer_walkthrough.py)。报告的 `operations` 保存方法、路径和去除秘密后的请求内容，可用于逐项对照接口。`completed`、版本、策略、批次、run、业务结果和拒绝记录共同证明完成状态。

## 如何迁移到自己的业务

先修改业务所有的 `domain/`、Prompt、编排与评测材料，并重写输入 / 输出 Schema、成功答案断言和失败用例。教程的业务实现是确定性建议，不是智能问答；接入模型、知识或工具时，要配置真实平台资源、发布策略，并补测相应能力收据、引用和权限拒绝。

| 易遗漏的接线 | 本教程采用的实际约束 |
| --- | --- |
| 自定义目录提交 | `POST /api/modules/catalog/definitions` 和 Definition 的 `/versions` 均附带 `tenant_id`、`department_id`、`application_id` 查询参数；与作者当前范围一致 |
| 输入 / 输出接口 | 使用 [input.schema.json](../snippets/input.schema.json) 和 [output.schema.json](../snippets/output.schema.json) 的真实业务结构；Manifest 中的 Schema 引用不代替 Schema 内容 |
| 安装方式 | `deployment_mode` 使用 `managed`；现有枚举为 `managed` / `external` |
| 无工具、无知识需求 | 工具 `allowed_tools: []`、知识 `allowed_scopes: []` 显式禁止调用；省略或设为 null 不能发布。模型配置使用教程占位、零预算，无真实供应商端点 |
| 健康检查 | 从平台容器访问 `http://support-assistant:8080/health/ready`；判定 HTTP 成功，不要求探针一定返回正文 |
| 机器权限 | 安装绑定不自动授予 `run`。通过 `authorization-changes:preview` / `authorization-changes` 单独配置该安装的 `run`、`history.read`、`cancel`、`history.continue`，含 `source_id` 与数据范围；实际能力调用再加对应资源权限 |
| 授权顺序 | 新部门默认没有可用 Agent；公司先设置部门上限，再在该范围内授权机器和用户，不能把资源拒绝误判为应提升管理员权限 |
| 部门上限 | 公司管理员提交前读取当前 revision，预览后用该摘要执行再次认证，再携带 plan digest / expiry 提交 |
| 日常使用包 | `GET /api/modules/identity/agent-use-package` 仅传 `department_id`、`application_id`、`installation_id`；公司从登录身份推导，额外传 `tenant_id` 会被拒绝 |
| 批量授权 | 获取当前使用包和用户 revision，预览、提交、继续办理并逐人检查；不是批量直接写数据库 |
| 业务结果 | 从 `/api/modules/conversation/sessions/<session_id>/messages` 核对答案和元数据，不能只检查 run 成功或 HTTP 200 |

教程只在单机使用本地镜像内容 ID。部署到其他机器或 K8s 时，须先发布到可拉取的镜像仓库，核验实际仓库 digest，并采用目标环境的 Service DNS、Secret 与来源网络；详情见[部署指南](deployment.md)。

## 登录验收清单

| 账号 | 公司 / 部门 | 用途与边界 |
| --- | --- | --- |
| `platform.admin` | 初始开发公司 | 独立发布审批、公司管理员任命、部署控制面操作 |
| `company.admin` | 初始开发公司 / Support | 公司组织、部门成员、机器身份与部门 Agent 上限管理 |
| `department.manager` | 初始开发公司 / Support | 管理其他部门成员的日常 Agent 使用，不自动获得运行权 |
| `agent.author` | 初始开发公司 / Support | 开发、提交目录与策略；不能自己完成独立发布 |
| `support.user` | 初始开发公司 / Support | 运行排障助手并查看自己的历史；无分享、导出或管理权 |
| `unassigned.user` | 初始开发公司 / Support | 目录显示受限状态，无运行与他人历史访问权 |

本教程验证部署与交付链路，以及所实现业务的成功、无效输入、幂等与权限边界。公司由首次管理员初始化建立；当前浏览器组织操作限制在账号所属公司，不使用全局管理员跨公司创建部门来绕过这一规则。公司隔离检查覆盖普通用户伪造公司范围，未声称已验证另一公司独立账号的完整开户与运行。外部供应商、知识索引、持久恢复、多副本和 K8s 生产运行仍需按实际业务另做验收。
