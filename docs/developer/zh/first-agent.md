# 从模板开发第一个业务 Agent

[入门路线](README.md) · [English](../en/first-agent.md)

本教程创建一个确定性的排障建议助手，先验证工程与执行接线，再进入真实平台发布。它不调用付费模型，也不代表已经完成企业知识接入。准备 Go 1.26.10+、Python 3.12+；构建镜像还需要 Docker。

想一次完成部署、开发、发布和用户授权，先运行[完整实战](walkthrough.md)。本页展开其中的业务工程步骤。

## 1. 生成工程

从仓库根目录执行：

```text
cd cli/agentctl
go run ./cmd/agentctl create --template python-generic --language python --name support-assistant --output out/support-assistant
go run ./cmd/agentctl validate --path out/support-assistant
cd ../..
```

`--output` 相对 agentctl 当前工作目录，不能是绝对路径。已有目录不会覆盖。你生成的工程位于 `cli/agentctl/out/support-assistant/`，此临时开发目录被 Git 忽略；正式业务工程可放入自己的仓库，保留 SDK 和模板版本事实。

| 文件 / 目录 | 你要如何使用 |
| --- | --- |
| `manifest.json` | 标识 Agent、协议、能力和 Schema 引用；由模板管理 |
| `platform_entry/` | SDK 接入与可信验证；不在这里复制业务基础设施 |
| `domain/` | 业务自己的代码和启动接线 |
| `graph/`、`prompts/`、`eval/` | 按需增加业务编排、Prompt 和评测材料 |
| `template.lock` | 记录平台与业务代码所有权，不通过手改 hash 绕过升级检查 |

## 2. 加入业务实现

在仓库根目录复制业务代码、容器入口和构建忽略规则：

```text
python -c "import shutil; p='cli/agentctl/out/support-assistant/'; files={'business.py':'domain/business.py','server.py':'domain/server.py','test_business.py':'eval/test_business.py','input.schema.json':'eval/input.schema.json','output.schema.json':'eval/output.schema.json','requirements-dev.txt':'requirements-dev.txt','Dockerfile.business':'Dockerfile.business','dockerignore.business':'.dockerignore'}; [shutil.copyfile('docs/developer/snippets/'+s,p+d) for s,d in files.items()]"
cd cli/agentctl/out/support-assistant
python -m pip install -r requirements.txt
python -m pip install -r requirements-dev.txt
python -c "from domain.business import recommend; print(recommend({'question':'How do I investigate a timeout?'}))"
```

预期结果是含 `question`、`answer`、`source` 的 JSON 风格对象。代码通过 `invoke(trusted)`、`run(trusted, events, cancelled)` 两个 Hook 接入已有 SDK 工厂。异步运行报告进度并检查取消，业务不修改 SDK 状态机。

业务入口还注册 `validate_input(trusted)`：只检查输入结构，不做网络、存储或模型调用。SDK 先验证可信签名，再执行此校验，遇到 `ValueError` 返回明确的 `INVALID_REQUEST` 失败，避免业务启动后才抛错、无法确认副作用。实际运行中的未知异常仍保留保守的待确认处理。

`domain/server.py` 是业务所有的装配入口；容器使用 `Dockerfile.business` 启动它。默认模板 Dockerfile 仍启动原有 echo 示例，因此构建时必须明确选择新 Dockerfile。

## 3. 测试业务和协议

仍在生成工程目录，先设置 SDK 导入路径。

PowerShell：

```powershell
$env:PYTHONPATH = 'platform_entry'
python -m pytest platform_entry eval -q
```

Linux / macOS shell：

```bash
PYTHONPATH=platform_entry python -m pytest platform_entry eval -q
```

这些测试验证 SDK 接缝、生命周期、能力契约，以及业务答案、无效输入和取消。按本页在完整仓库中生成工程时，测试会向上定位 `contracts/fixtures/` 与 `sdk/python/`，共享契约检查应全部运行，不应跳过。把工程移到仓库之外后，如缺少共享夹具，对应检查会显示跳过；不能把它们记为通过，应在平台仓库根目录补测原模板完整契约：PowerShell 先设置 `$env:PYTHONPATH='templates/python-generic/platform_entry'`，再执行 `python -m pytest templates/python-generic/platform_entry -q`；Linux / macOS 使用 `PYTHONPATH=templates/python-generic/platform_entry python -m pytest templates/python-generic/platform_entry -q`。完成后切回业务工程并恢复 `PYTHONPATH=platform_entry`。

`requirements-dev.txt` 包含 pytest、异步测试插件和 SDK 内嵌测试使用的 FastAPI。它们是测试依赖，不添加到业务镜像的运行依赖。完整实战会创建专属虚拟环境安装它们。

为自己的业务另外测试无效输入、成功输出、依赖拒绝、超时和取消后的影响；用具体业务预期检查答案，不只测试 HTTP 200。

模板默认 `MemoryRunStore` 位于进程内。若业务要求重启恢复、持续异步运行或多实例，应注入作用域明确的持久 Store 并补充恢复测试，不能靠镜像构建通过宣称已满足这些要求。

## 4. 本地启动接入入口

从**本地开发平台**的 `.env` 只提取公钥，放入生成工程的公开验证文件；不要把整个 `.env` 复制进工程：

```text
python -c "from pathlib import Path; lines=Path('../../../../.env').read_text(encoding='utf-8-sig').splitlines(); value=next(x.split('=',1)[1].strip() for x in lines if x.startswith('PLATFORM_CONTEXT_PUBLIC_KEY=')); Path('platform-public-key.txt').write_text(value,encoding='utf-8')"
```

PowerShell：

```powershell
$env:PYTHONPATH = 'platform_entry'
$env:AGENT_PLATFORM_PUBLIC_KEY_FILE = (Join-Path (Get-Location) 'platform-public-key.txt')
$env:AGENT_PLATFORM_AGENT_ID = 'support-assistant'
$env:AGENT_PLATFORM_ISSUER = 'platform'
$env:AGENT_PLATFORM_AUDIENCE = 'agent-runtime'
$env:PORT = '18084'
python -m domain.server
```

Linux / macOS：

```bash
PYTHONPATH=platform_entry AGENT_PLATFORM_PUBLIC_KEY_FILE=platform-public-key.txt AGENT_PLATFORM_AGENT_ID=support-assistant AGENT_PLATFORM_ISSUER=platform AGENT_PLATFORM_AUDIENCE=agent-runtime PORT=18084 python -m domain.server
```

在另一个终端验证 `http://127.0.0.1:18084/health/ready`。这是服务就绪证明；执行端点需要平台签名的 v2 请求。不要用裸 `{"question": ...}` 直接调用执行端点并删掉鉴权来让请求成功。

## 5. 构建业务镜像

仍在生成工程目录：

```text
docker build -f Dockerfile.business -t agentplug:support-assistant-dev .
cd ../../../..
```

正式交付把真实制品摘要、业务输入输出 Schema、Manifest、评测材料和部署配置一起管理。本教程复制的 `eval/input.schema.json`、`eval/output.schema.json` 对应实际业务接口。模板提供的是 Schema 引用，**不等于已生成你业务的输入 / 输出 JSON Schema**；按自己接口修改业务所有的 Schema 并在发布材料中登记，不用修改锁文件伪装成模板原生制品。

教程的 `.dockerignore` 排除开发凭据和验证公钥文件；运行时从部署配置挂载对应平台公钥及 Agent 独立凭据。不要把私有文件重新加入镜像来解决配置缺失。

## 6. 接到平台并交给用户

下一页[发布、部署和绑定](delivery.md)逐项说明目录版本、实际服务观测、六类策略、机器身份、部门上限与用户使用包。你也可以使用[交付 skill](skill.md)串联检查和已有接口执行。

需要模型或知识时，从[公共能力](capabilities.md)选择 SDK 接口；参考 [Python 文档助手](../../../examples/python-documents/README.md)的真实能力接线，而不是把供应商 API Key、SQL 查询和工具审批重新写进 `domain/`。
