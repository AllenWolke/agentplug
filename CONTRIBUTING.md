# 贡献指南

欢迎通过可复现的问题报告、文档改进、测试和代码修改参与 AgentPlug。仓库的当前能力和未完成项见 [README](README.md#当前状态)，任务操作见[用户手册](docs/用户手册/README.md)。

## 准备环境

使用 [干净环境指南](docs/开发者指南/业务Agent挂载与已有用户授权指南.md#空库首次初始化) 配置本地环境。平台需要 Go 1.25、PostgreSQL 16 和 pgvector；前端使用 Node.js 20 或更新版本。各 SDK 和模板的依赖以各自的 `go.mod`、`pyproject.toml`、依赖清单或 `pom.xml` 为准。

运行时数据库账号与迁移账号分离。把本地配置保存在 Git 忽略目录，使用自己的随机凭据；不要将密码、供应商密钥、真实业务输入、原始日志或数据库备份提交到仓库。

## 报告问题

说明版本或候选源码、操作系统、部署方式、账号角色及组织范围、复现步骤、预期结果和实际结果。用合成数据提供最小复现，保留必要的错误码及追踪编号。权限问题需说明是否为人员、机器、部门管理或资源授权，不要贴出实际令牌。

安全漏洞按 [SECURITY.md](SECURITY.md#报告问题) 私密报告。仓库尚未配置远端或私密报告入口时，不要把漏洞利用细节放到公开 Issue。

## 提交修改

- 说明具体触发条件和修改后的行为，保持职责边界；跨模块通过既有接口组合，不直接写入其他模块所属表。
- 保留版本化权限和资产的不可变定义。涉及授权继承、成员迁移、撤销或高影响操作时，提供明确差异、审计及回退说明。
- 界面修改更新中英文文案和相关手册；用户名称、输入、Agent 回答和协议标识不可被语言切换改写。
- 新行为使用能证明外部结果或不变量的测试。构建、健康检查、源码命中及被跳过的测试各自保留真实含义。
- PR 写明问题、实现、验证命令及结果，列出未验证的环境或场景。与修改无关的格式化、生成物和私有运行状态不要混入。

## 验证

根据修改范围先运行相关测试，再执行对应门禁：

```text
python scripts/check_gofmt.py
python scripts/check_contract_breaking.py
python scripts/lint_execution_contract.py
python scripts/verify_modular_boundaries.py
python scripts/verify_productization_behavior.py --compact
python scripts/check_markdown_links.py
python scripts/check_publication.py
python scripts/scan_secrets.py
```

前端在 `frontend` 下运行 `npm ci`、`npm test` 和 `npm run build`。Go 模块在相应目录运行 `go test ./...`；Python 的 SDK、示例和模板分别运行，避免同名内嵌 SDK 导入串组：

```text
python scripts/verify_python_grouped_regression.py --batch-id your-unique-batch
```

真实平台 PostgreSQL / Kafka 回归使用拥有自己临时容器的验证器：

```text
python scripts/verify_public_knowledge_postgres.py --suite platform-all-go --batch-id your-unique-batch
```

该验证器要求 Docker 及已有 Go 依赖缓存，创建独立数据库与随机凭据，结束后清理自己创建的资源。它不会把专用夹具、真实模型或 Code Runtime 用例的跳过记为通过。数据库集成和业务端到端验收的前提不同，不能用普通单元测试代替。

发布前检查 `.github/workflows` 中与该交付相关的任务。维护者需在真实 GitHub 仓库配置权限、私密安全报告和发布参数；本地文件存在不代表这些远端功能已经启用。

## 上传前的隐私检查

在首次提交前，以及每次修改部署配置、测试数据或截图后，运行 `python scripts/check_publication.py` 和 `python scripts/scan_secrets.py`。前者检查 Git 实际提交候选，包括已跟踪但后来被忽略的文件；后者检查疑似凭据。`.env.example` 和公开示例配置仍需扫描，只保留占位值或合成数据。

`.gitignore` 用于正常的 Git 提交，不会清除已有提交历史，也不会自动排除通过网页手动上传或直接压缩整个项目目录的文件。禁止使用 `git add -f` 提交私密文件。新增截图、附件和业务样例时须人工确认没有姓名、账号、聊天内容、浏览器令牌或业务数据；扫描通过不证明所有内容都已脱敏。

提交记录中的作者姓名和邮箱也会公开，与文件过滤规则无关。希望隐藏个人邮箱时，先在 GitHub 设置中开启邮箱隐私，并将 Git 提交邮箱设置为 GitHub 提供的 `noreply` 地址，参见[提交邮箱设置](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/setting-your-commit-email-address)。不要把真实邮箱或电脑路径写入公开的配置示例、Issue 和验收日志。
