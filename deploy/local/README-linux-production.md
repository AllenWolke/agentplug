# Linux 本地生产部署

Linux 是本项目本地生产部署的目标系统。通用安装、平台、前端与 Runner 配置与迁移命令见[本地部署说明](README.md)；本文补充非 root 服务管理、实际资源边界和服务器验收步骤。

当前公开版尚待干净环境和 Linux 运行边界验收，历史业务验收不能代表本版本已通过。三个独立示例的服务配置将随部署工作包补齐。

## 构建和配置

主机需要 Go 1.26.9+、Python 3.12、Node 20/22、PostgreSQL 16 + pgvector，以及支持 memory/pids 控制器和 seccomp 的 Linux 内核。systemd 必须能实际施加资源上限。AMD64 与其他架构均需对当前候选重新运行同样测试，不能只因为 Go 能交叉编译就算验收通过。

从候选源码目录执行：

```bash
python3.12 -m venv .venv
. .venv/bin/activate
python -m pip install -e './sdk/python[grpc,telemetry]'
python -m pip check
python scripts/local.py build
```

必须把 SDK extras 与 Agent 版本约束放在同一次安装中；先装最新 SDK extras 再单独降级 Agent 依赖，会留下不兼容的遥测依赖。`pip check` 必须成功。系统软件由部署者安装，本项目不替换系统 Python 或修改全局 PATH。

将构建后的源码/venv/二进制及前端 dist 安装到 `/opt/agentplug`。目录由发布管理账户所有，服务账户只读；不要授予运行账户修改应用、SDK、插件制品或签名公钥的权限。venv 必须在最终路径建立，不能直接搬迁含旧绝对路径的 venv。若采用不同目录，修改模板中的完整路径并执行 `systemd-analyze verify`。

把现有示例中的值替换为实际私有配置。生产设为 `APP_ENV=production`，关闭演示身份、demo 登录，配置真实 OIDC、Secure Cookie、已发布策略/Prompt、模型和平台公共知识、通知与遥测。平台数据库账户使用最小 DML 权限；业务 Agent 不持有平台数据库账户；迁移账户不进入长期服务配置。生产不能配置 `PLATFORM_DEV_RUNTIME_PASSWORD`。

开发配置使用回环 PostgreSQL。生产远端数据库需要部署者验证加密连接/代理；不能认为在 PostgreSQL URL 后附加任意 TLS 参数就已经启用 TLS。对外只暴露 TLS 入口，平台内部、Agent、Runner 和数据库端口保持回环或明确受控的网络边界。

## 分账户 systemd 服务

提供 [agentplug@.service](systemd/agentplug@.service)，实例为 `runner`、`platform`、`frontend`。每个实例使用独立 `agentplug-实例名` 系统账户/组。由管理员创建账户；已有账户应检查 UID、组和目录，不覆盖无关账户。

新机器的创建示例：

```bash
for service in runner platform frontend; do
  sudo useradd --system --user-group --home-dir "/var/lib/agentplug-$service" --no-create-home --shell /usr/sbin/nologin "agentplug-$service"
done
sudo install -d -m 0755 /etc/agentplug
```

为各账户安装对应配置，文件仅其拥有者可读。例如平台配置：

```bash
sudo install -o agentplug-platform -g agentplug-platform -m 0400 .local-secrets/local/platform.env /etc/agentplug/platform.env
sudo install -m 0644 deploy/local/systemd/agentplug@.service /etc/systemd/system/agentplug@.service
sudo install -d -m 0755 /etc/systemd/system/agentplug@runner.service.d
sudo install -m 0644 deploy/local/systemd/runner-limits.conf /etc/systemd/system/agentplug@runner.service.d/limits.conf
sudo systemd-analyze verify /etc/systemd/system/agentplug@.service
sudo systemctl daemon-reload
```

其他长期服务配置采用对应账户和路径；迁移、Checkpoint 初始化配置仍由维护者私有保存，执行初始化后不交给 Agent。平台私钥仅平台账户可读，Agent 只有公钥；Runner 不持有平台数据库密码或签名私钥。

模板设置非 root、清空 capabilities、NoNewPrivileges、只读系统/应用、保护控制组、独立临时目录和状态目录、资源上限及整组停止。业务需写本机状态时配置到 `/var/lib/agentplug-实例名`，不能为了写日志把源码目录改成运行账户可写。模板不授予 Docker socket 权限；开发集成测试访问 Docker 仅用于创建一次性数据库。

## 沙箱与资源验收

Runner 示例覆盖为 MemoryMax=128M、TasksMax=64。**这是整个 Runner 及所有子进程共享的上限，不是每个插件独立额度。** 其实际上限必须不大于每个签名插件所登记的资源预算；更小预算、并发或更大模型需调整描述符/服务配置并复验。不要把上限改为 infinity 来绕过拒绝。

插件运行时设置 `LEXAGENT_METRIC_NETWORK_MODE=none`、`LEXAGENT_METRIC_REQUIRE_NONROOT=true`，并配置只读插件注册表及签名公钥。原生生产不能借用 `container` 网络模式替代实际隔离。没有注册表/签名或可强制的资源上限时，应明确拒绝插件；内置指标可独立使用。

在服务器上运行：

```bash
bash scripts/test_native_linux_sandbox.sh
```

该脚本需要管理员权限创建自己的临时 systemd 单元；普通用户需可用的 `sudo -n`。它验证非 root 注册插件、篡改/外来签名拒绝、fork/PID 限制、文件读取/超量写入、环境密钥隔离、输出洪泛、超时终止和 seccomp 出网拦截；另启独立 root 负例。必须看见 `NATIVE LINUX BOUNDED SANDBOX PASS`，缺必要断言或静默跳过按失败处理。脚本停止自己的单元并删除自己的测试缓存，不改生产服务配置。

Runner 根据 `/proc/self/cgroup` 和 mountinfo 找当前进程的控制组，兼容主机 systemd 路径及容器命名空间、v1/v2，并取可见层级最严格的有限上限。缺少上限时拒绝；仅配置了 systemd 字段而没有对应内核约束，也不能算通过。

## 启动、停止与上线

先按通用说明用私有维护配置完成平台迁移及 Checkpoint 初始化，两个命令退出 0。然后依次启动并检查就绪：

```bash
sudo systemctl start agentplug@runner
sudo systemctl start agentplug@platform
sudo systemctl start agentplug@validation agentplug@qa
sudo systemctl start agentplug@frontend
```

`Type=simple` 的 active 只表示进程尚未退出；每一步还要检查说明中的 HTTP readiness。不要把 systemctl active 当作数据库、Grant 或模型可用的证明。就绪后在控制面发布 Agent 版本/部署端点、策略和精确安装 Grant，执行真实业务冒烟。确认通过后才 `systemctl enable` 相应实例。

检查日志和资源边界：

```bash
sudo journalctl -u agentplug@platform -u agentplug@runner --since '10 minutes ago'
sudo systemctl show agentplug@runner -p User -p Group -p NoNewPrivileges -p MemoryMax -p TasksMax -p ControlGroup
```

上线验收还需验证 TLS/OIDC、隔离/撤权、配置读取者、实际模型和平台公共知识、通知与监控、[备份恢复](../backup/README.md)及目标硬件负载。项目已提供可重跑脚本，但不能替部署者声明未知服务器已验收。

停止按前端 → Agent → 平台 → Runner：

```bash
sudo systemctl stop agentplug@frontend agentplug@validation agentplug@qa
sudo systemctl stop agentplug@platform agentplug@runner
```

升级前备份，维护窗口停写，再执行候选迁移、替换应用、依次重启并做业务验证。失败时保留数据库账本/审计事实，按 Schema 兼容性回退应用；不能删库回滚。PID/cgroup、私有状态目录和回退版本均需由部署者保存与核查。

回退前执行上面的停止命令，并确认写入服务已经停止。保留上一个已批准的完整源码/构建目录、Python venv、前端静态资源、systemd 单元和私有配置；只恢复一个二进制不足以恢复整个候选版本。旧平台必须接受当前 Schema checksum，旧 Checkpoint SDK 必须接受当前迁移版本。满足兼容条件时，把实例的 WorkingDirectory/ExecStart 恢复到保留的旧目录，审查单元和私有配置后执行 `sudo systemctl daemon-reload`，用旧候选执行通用说明的迁移与 Checkpoint 检查，再按上述顺序启动并检查 HTTP 就绪、真实授权业务及撤权。业务检查失败时继续保持入口关闭。

若旧版本拒绝新 Schema，不修改版本标记或删除迁移历史。先将升级前已验收备份恢复到新的受控数据库，创建旧版本的最小权限账户，核对 Run/Checkpoint 与外部副作用，并对账备份点后的撤权、删除和 Legal Hold。批准新的私有 DSN 后再执行旧候选初始化/启动/业务检查；原数据库保留调查。实际恢复窗口和外部资产由部署方按[备份说明](../backup/README.md)演练。
