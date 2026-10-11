# 第一次部署并登录

[开发者路线](README.md) · [English](../en/quickstart.md)

本页适用于下载源码后的**新环境**。已有数据库和账号的部署从 `status`、`smoke` 开始核对，升级使用迁移流程，不重复创建首位管理员。

## 1. 检查工具

在仓库根目录执行：

```text
python --version
docker version
docker compose version
```

需要 Python 3.12+、可用的 Docker 服务和 Compose v2。首次构建需要网络下载 Go、Node、Python 依赖和基础镜像。基础平台不要求本机安装 Go、Node 或 Java；开发业务源码时才需要对应工具。

## 2. 准备私有配置

```text
python -m pip install "cryptography>=43,<46"
python scripts/prepare_local_development.py
```

根据提示设置管理员密码，确认两次。命令生成：

| 文件 | 用途 |
| --- | --- |
| `.env` | 本地 Compose 配置；必需密钥与数据库密码各自随机生成 |
| `.local-secrets/first-admin.json` | 仅用于空身份库初始化首位管理员，含你输入的密码 |

不会打印密钥，也不会启动服务。默认管理员 `platform.admin` 是平台级恢复和管理入口，不是自动拥有业务运行权的公司用户。默认公司为 `tenant-demo`，初始化管理部门为 `dept-platform`，内部容器为 `app-platform-admin`。

有占用端口时，在生成前一次选好，例如：

```text
python scripts/prepare_local_development.py --frontend-port 33000 --postgres-port 35432
```

这是另一种首次准备方式，不要在已经生成后重复执行。脚本拒绝覆盖；已有文件应由部署者核对和编辑。Windows 对私有目录设置仅当前操作者可读的 ACL；POSIX 生成的文件为 0600。两份文件均被 Git 忽略，不放入截图、Issue 或业务镜像。

## 3. 检查并初始化

```text
python scripts/compose.py config --env-file .env
python scripts/init_platform.py --env-file .env
```

`config` 只校验配置，不打印展开后的秘密。`init` 构建迁移镜像，启动 PostgreSQL / Kafka，执行 Schema 迁移、开发数据库运行角色配置和主题初始化。它不是普通业务服务启动，迁移凭据也不进入平台长期进程。

如果失败，停在此步骤，查看错误和[排障](troubleshooting.md)。不要通过删除卷、清空迁移历史或改成数据库管理员运行平台来绕过问题。

## 4. 初始化首位管理员

```text
python scripts/bootstrap_first_admin.py --env-file .env --config .local-secrets/first-admin.json
```

成功输出 `FIRST ADMINISTRATOR BOOTSTRAP PASS`。此命令检查当前 Schema 且只允许空身份库；不会覆盖既有账号。生产环境使用真实 OIDC 绑定，见[首位管理员维护流程](../../../deploy/README-first-administrator.md)，不要直接搬用本地密码方案。

首次初始化完成后，可以从安全工作区删除这份一次性管理员 JSON，保管密码与恢复方法；保留 `.env` 供后续运行。删除初始化 JSON 不会删除数据库账号。

## 5. 启动与验证

```text
python scripts/compose.py up --env-file .env
python scripts/compose.py status --env-file .env
python scripts/compose.py smoke --env-file .env
```

默认五个服务为平台、前端、PostgreSQL、Kafka、Metric Runner。打开 `http://127.0.0.1:3000`，若更改端口则使用新端口。登录 `platform.admin`，密码是步骤 2 输入的值。可以切换中英文、打开帮助、检查自己的管理范围。

## 6. 下一步

此时验收的是“基础平台可用”，没有自动创建三个业务示例、供应商账号、付费请求、知识内容或业务权限。按[第一个 Agent](first-agent.md)开发工程，再按[交付](delivery.md)完成发布与绑定。

停止基础栈：

```text
python scripts/compose.py down --env-file .env
```

此命令保留数据库与消息数据卷。`reset --force` 会删除数据，只适用于明确允许丢弃的隔离测试环境，不属于日常停止步骤。
