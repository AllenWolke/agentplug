# 二次开发：改哪一层

[入门路线](README.md) · [English](../en/extending.md)

优先把业务变化留在独立 Agent 中。只有当多个业务需要相同能力、且现有公共端口无法表达需求时，再扩展平台。

| 变化 | 应修改的位置 | 需要同步验证 |
| --- | --- | --- |
| 新业务流程 / 领域规则 | Agent 的 `domain/`、`graph/`、`prompts/`、`eval/` | 业务 Schema、成功与失败用例、取消和恢复承诺 |
| 接入框架 | `go-eino`、`python-langgraph`、`java-spring-ai` 模板的业务层 | 保留 SDK 认证和执行生命周期，不改成框架自己的可信边界 |
| 接入新模型供应商 | 模型治理与网关的 Provider / Endpoint / Secret / Version | 批准状态、超时 / 收据、内部价格和用量、两类主体授权 |
| 新工具或 MCP 服务 | 平台工具适配器与发布策略 | 参数 Schema、允许函数、风险、确认、幂等和收据 |
| 新知识源 / 索引方法 | Knowledge 拥有的源、任务和投影边界 | 来源版本、增量 / 删除、发布 CAS、ACL 与恢复 |
| 新公共能力 | 拥有模块 + capability 端口 + SDK | 协议、三语言客户端、错误、授权、预算、事件和审计 |
| 新界面 | frontend feature 与语言目录 | 入口权限、影响说明、空状态、失败恢复、中英文、交互测试 |
| 新持久事实 | 拥有模块迁移与架构契约 | 表所有权、Schema 校验、备份兼容和迁移测试 |

## 扩展的实际步骤

1. 找到现有公开契约与拥有模块，写清业务输入、输出、错误和影响。不要先新增一套重复的 auth / model / tool / audit 服务。
2. 从当前 SDK / 模板版本开始，保留平台拥有路径。业务可注入 Hook 或实现公开 Port；升级先预览，不手改 `template.lock` 绕过冲突。
3. 涉及平台表时更新 [table-owners.json](../../../contracts/architecture/table-owners.json)和当前迁移，跨模块读取通过公开端口或已登记投影。
4. 修改契约时同步 Go、Python、Java 客户端 / 模板，以及兼容性与真实错误测试。新模块不是只加 HTTP 路由。
5. 跑与变更相符的模块测试和架构门禁，再到隔离环境验证真实业务与授权。已有生产环境遵循备份、迁移、部署观测和恢复流程。

## 测试入口

仓库根目录：

```text
python scripts/verify_modular_boundaries.py
python scripts/check_agent_code_ownership.py
python scripts/check_agent_productization_contracts.py
```

具体 Agent 测试使用其语言的测试工具，协议检查还需真实入口或正确签名的隔离测试夹具。`agentctl test` 需要 `--base-url`，其 conformance runner 路径取决于当前目录；它不自动替你准备生产机器和人类授权。

真实模型、集群和 Code Runtime 验收不能用本地 fixture 的成功替代。对不满足环境条件的检查明确报告缺失项，而不是永远跳过后宣称生产验收完成。
