# 独立公共Code执行控制器

Code Runtime 由独立控制器创建一次性代码容器，并提供签名许可与加密回执接口。控制器和平台通过私有专用网络通信，部署时须为两者分配同一子网内互不冲突的固定地址，并让证书 SAN、监听地址、平台 endpoint 和 binding 一致；[独立控制器部署资产](#独立控制器部署资产)列出准备和启动步骤。

控制器是受信任部署组件，具有宿主容器引擎操作权限。平台及业务Agent不挂载Docker Socket；代码容器没有该Socket、宿主挂载、数据库或模型凭据。服务入口验证平台Ed25519操作绑定许可、控制器受众、短期有效期和固定执行Profile，使用加密持久claim/receipt防止重复执行。平台须在目标安装上发布Code策略与Profile，为用户和机器配置独立授权，并按平台运行状态和回执处理取消；内部容器引擎接口不暴露给业务用户。

服务入口为`cmd/code-runtime`，通过`CODE_RUNTIME_CONFIG_FILE`指定绝对配置路径。配置包含明确的本地/私网监听地址、控制器ID、独立公钥与状态加密密钥文件、预先创建的状态目录和Docker配置目录、固定镜像ID、Profile及并发上限。密钥文件使用base64；控制器只持有验签公钥，不持有平台签名私钥。配置严格拒绝未知字段，服务不打印源码、许可或密钥。私网监听仍须部署防火墙/内部网络保护。

`POST /v1/execute`和`POST /v1/receipt`只接收`{"permit":"平台签发许可"}`。Agent不能在请求中覆写镜像、资源、语言或端点。回执查询不执行代码；中断、清理未确认或记录损坏保持未知/拒绝，不凭猜测重复运行。源码和许可不写入持久回执，结果正文加密保存且不作为审计日志输出。服务关闭会取消活动请求并等待受控清理。

运维固定Python、Node、Shell镜像的不可变image ID。请求不能选择镜像、挂载、解释器、环境变量、网络或Docker参数。每次执行独立PID/网络/文件环境，非root、全部Capabilities移除、no-new-privileges及仓库固定seccomp；Docker默认unconfined也不回退无过滤执行。

只读镜像提供公开运行库，临时写入仅限有总额度的`/workspace`、`/tmp`、`/dev/shm`。不挂载宿主资料；容器可读取自身镜像公开文件，但不提供逐文件读取白名单或受控宿主输入通道，因此不要把秘密放入镜像或容器。网络socket及高风险系统调用被seccomp拒绝。cgroup内存/CPU/PID、CPU秒数和文件大小rlimit、FD、临时磁盘、墙钟及stdout/stderr有界；日志驱动关闭，避免原始输出占满宿主日志磁盘。

stdout/stderr分别限制64KiB～1MiB，墙钟10～60秒。取消、超时、超额和执行结束均核验owner并删除本次容器，结束其全部子进程。清理未确认时返回错误。受信任控制器通过 Docker Engine 有界采样记录 CPU 时间与已观察内存峰值；引擎未提供的峰值保持 null，`measurement_complete=false`，不把采样视为完整执行测量。另以固定无shell `/bin/stat` 读取 `/workspace`、`/tmp` 与 `/dev/shm` 的已分配tmpfs块并汇总有限样本中的最大值，来源和样本数单独记录；其值不是全程峰值或累计写入量，命令、格式、超时或固定镜像不支持时保持null。资源字段反映有限采样能力，不代表完整峰值或全部运行期间用量。详见 `internal/sandbox/resource_usage.go` 与 `internal/sandbox/disk_usage.go`。

执行错误依据实际停止状态分类：仅匹配本次容器且完整的 Engine `OOMKilled=true` 证明内存超限。单独退出码 `137` 可能来自主动退出或其他 SIGKILL，返回 `CODE_EXITED`，不伪造 OOM/CPU 超限原因。CPU 秒数硬限制仍生效，实际 CPU 限制场景另外核验执行时间、停止和清理。

在目标 Linux Docker Engine 主机运行 `python scripts/verify_public_code_runtime.py`，以验证可用执行镜像、控制器和宿主内核组合下的实际隔离。脚本不构建或拉取镜像，不访问业务数据库或供应商，只清理本次 owner 的容器和临时目录。普通 `go test ./internal/sandbox` 未提供 Docker 夹具时会跳过实际执行用例，不能替代此验证。

## 独立控制器部署资产

`Dockerfile`和`deploy/compose/compose.runtime.yaml`提供独立控制器部署入口。Compose overlay 未并入默认`compose.yaml`；只在显式叠加后启用。构建上下文必须是仓库根目录，因为 worker 通过`go.mod`的本地 replace 引用`contracts/code-runtime`。构建固定使用`golang:1.26.9-bookworm`；最终阶段的`CODE_RUNTIME_DOCKER_CLI_IMAGE`是必填参数，必须使用含`docker` CLI的不可变`image@sha256:…`引用，不能留空或使用浮动标签。控制器仅需要 Docker CLI 的执行、检查和清理命令；最终镜像移除上游附带的 Buildx 和 Compose 发布插件，缩小运行时攻击面。CLI镜像必须支持目标Docker Engine架构；Linux/amd64 与 Linux/arm64 可使用已核验的多架构 Docker CLI 索引，例如 `docker.io/library/docker:29-cli@sha256:1a4c7cb63513f349bdad01fcc6e0f3f2f67d37b9da86f14dc0d4a0942eecda00`，并在部署时从实际可信来源核验摘要与架构。

运维先把父目录`.local-secrets`设为仅部署用户可读写，并确认目标子目录不存在。准备器只创建一个新的私有目录，生成十个逐文件材料：`bindings.json`、平台许可签名私钥、工具批准私钥、控制器CA证书、许可公钥、回执加密密钥、控制器证书和私钥、控制器JSON配置、Compose环境文件。CA私钥只在生成时使用且不落盘；该生成器不会创建 IAM Grant、发布策略或启动服务。它预置三个示例语言绑定到命令所给 tenant/application 和三个示例Agent，并将并发设为2；每次执行限制为128 MiB内存、500 milli CPU、5 CPU秒、16个PID、8 MiB临时盘、15秒墙钟和64 KiB输出。准备器根据 controller IP 和专用子网自动选择不与 controller、网络地址、默认网关或广播地址冲突的`CODE_RUNTIME_PLATFORM_PRIVATE_IP`，与`CODE_RUNTIME_PRIVATE_IP`、`CODE_RUNTIME_SUBNET`一并写入`compose.env`。`--docker-cli-image`和`--socket-gid`是可选但必须成对提供；提供时生成的`compose.env`还包含这两个部署变量，省略时则需在部署前从已核验来源补齐。不要把示例绑定直接扩展为未审查的生产Agent授权。

在目标 Linux 宿主运行 `stat -c '%g' /var/run/docker.sock` 检查 socket 的数值 GID 与权限，将该宿主返回的 GID 设为 PowerShell 环境变量 `$env:CODE_RUNTIME_DOCKER_SOCKET_GID`，再传给准备器的 `--socket-gid`。该值随 Docker Engine 安装和宿主配置变化，不能从示例或另一台机器照抄；仅向受信任控制器授予必要的 socket 访问权限。

从仓库根目录在 PowerShell 设置真实的私网 IP、专用子网、tenant/application 和三种已存在执行镜像的实际 `sha256:` ID，然后运行：

```powershell
Push-Location platform
go run ./cmd/prepare-code-runtime `
  --output ..\.local-secrets\public-runtime-control `
  --private-ip $env:CODE_RUNTIME_PRIVATE_IP `
  --subnet $env:CODE_RUNTIME_SUBNET `
  --tenant $env:CODE_RUNTIME_TENANT `
  --application $env:CODE_RUNTIME_APPLICATION `
  --python-image-id $env:CODE_RUNTIME_PYTHON_IMAGE_ID `
  --javascript-image-id $env:CODE_RUNTIME_JAVASCRIPT_IMAGE_ID `
  --shell-image-id $env:CODE_RUNTIME_SHELL_IMAGE_ID `
  --docker-cli-image docker.io/library/docker@sha256:cd58b396e427d1ee8cddcc3f3b7e8d8c2ba45755c5dd5b821b6e615e1ccf4586 `
  --socket-gid $env:CODE_RUNTIME_DOCKER_SOCKET_GID
Pop-Location
```

准备器拒绝已有目标目录；失败后保留其输出供运维检查，不要覆盖当前运行控制器的密钥或状态。正式执行镜像必须从本仓库 `workers/code-runtime/images/Dockerfile` 构建三个目标 `python`、`javascript`、`shell`，仓库标签分别为 `agentplug:code-python`、`agentplug:code-javascript`、`agentplug:code-shell`；控制器镜像为 `agentplug:code-runtime`。例如 `docker build --target python -t agentplug:code-python -f workers/code-runtime/images/Dockerfile .`，其他两种替换为对应 target 和标签。第三方语言镜像只作为基础层；原始镜像缺少固定文件守卫，控制器拒绝直接使用。准备器的`--python-image-id`、`--javascript-image-id`、`--shell-image-id`必须传入这些仓库自建执行镜像在目标 Docker daemon 中的实际 image ID（`sha256:`加64位小写十六进制），不能传标签或第三方基础镜像 ID。执行时 runner 使用`--pull never`；应确保实际构建镜像已存在于同一 Docker daemon 中。

执行前固定守卫要求 Linux amd64/arm64、Landlock ABI 至少为3、非root身份，并限制系统库的只读路径及本任务临时读写路径；关闭额外继承描述符后才进入解释器。不支持内核守卫时拒绝执行。Code 无网络，外部请求走平台注册的域名/路径白名单 API Tool。按前述步骤构建三种执行镜像、将实际 image ID 写入控制器配置，并在目标主机运行 Code Runtime 验证脚本。守卫实现见 [Linux隔离启动源码](cmd/code-sandbox-guard/launch_linux.go)，业务接入见[三语言SDK开发指南](../../docs/开发者指南/三语言SDK业务Agent开发指南.md)。

`public-runtime-control`下文件要按容器 UID/GID `10001:10001`逐文件授予必要读取权限，并保持宿主侧私有权限。Compose 将 `bindings.json`、平台许可私钥、工具批准私钥和 CA 证书分别只读挂到平台；控制器只读挂自己的 JSON 配置、许可公钥、状态密钥、TLS 证书和 TLS 私钥。不能把整个私有目录挂进任一服务。许可私钥和工具批准私钥相互独立，只在平台；控制器的 AES 状态密钥和 TLS 私钥只在控制器。不要把密钥内容写进环境变量、日志或镜像。准备器为新目录和文件设置严格权限；部署前须确保容器 UID 10001 对各自挂载文件可读，但平台和控制器不应因此互相获得对方的私钥。

控制器配置、平台 binding 和证书必须一致使用控制器的固定私网 IPv4：控制器监听`<CODE_RUNTIME_PRIVATE_IP>:8443`，平台 endpoint 为`https://<CODE_RUNTIME_PRIVATE_IP>:8443`，证书包含该 IP 的 SAN，平台通过只读挂载的控制器 CA 验证它。平台容器在同一专用网络上使用另一个固定地址`CODE_RUNTIME_PLATFORM_PRIVATE_IP`；准备器从子网可用主机地址中选择，跳过默认网关和控制器地址。Compose 中`platform-app`在`default`、`metric-control`网络保留普通映射，只在`code-runtime-control`使用该固定地址；这样不会让自动分配地址与 controller 静态地址重合。例如子网`172.30.76.0/24`、controller 地址`172.30.76.2`时，平台使用`172.30.76.3`；二者均不能使用网络地址、默认网关或广播地址，也不能与宿主/其他 Compose 网络冲突。监听不可改成`0.0.0.0`，endpoint 不使用 Compose DNS 名。overlay 创建只供平台和控制器加入的`internal`网络，不发布控制器 host port；Agent 服务不加入该网络。只有受信任的`code-runtime`服务挂载`/var/run/docker.sock`，平台和Agent没有 Docker Socket。控制器以非root UID运行，仅通过可配置补充组访问宿主 Docker socket。

控制器回执卷`code-runtime-state`独立持久化；其中 claim/receipt 用`controller-state.key`做 AES-GCM 加密。备份和恢复时必须一起保留这把状态密钥，丢失或更换会使旧回执无法解密，不能清空旧状态来绕过不确定执行。Docker CLI 配置路径`/var/lib/agentplug-code/docker`预建在镜像并在容器中以小型 tmpfs 可写；runner 启动时把嵌入的`internal/sandbox/seccomp.json`以`agentplug-code-seccomp.json`写入该目录，若已存在则要求它是非符号链接普通文件且内容完全匹配。Docker CLI 在控制器容器内读取该路径并把 profile 内容发送给 Docker daemon；因此该 profile 目录必须对 UID 10001 可写。代码执行容器仍由 runner 固定为`--network none`、只读根目录、无挂载、非root、无 capabilities 和显式 seccomp；它们不继承控制器网络或 socket。

准备器生成的示例绑定只针对指定的 tenant/application 和三个示例Agent；它不自动授予应用权限，也不会开启其他预算、MCP 或 Grant。Compose 的示例控制器资源限制和并发值仍需按目标宿主容量审查。控制器IP、平台IP、子网、证书SAN和endpoint必须使用同一组非冲突配置；准备器会为平台选择不同于控制器、网关和保留地址的静态地址，但运维仍须检查该子网未与宿主或其他Compose网络重叠。Docker Compose 支持多个`--env-file`并按顺序读取，后面的文件覆盖前面的文件；使用时将仓库`.env`放在准备器生成的`compose.env`之前，并清除shell中同名变量，避免shell优先级覆盖准备器生成值：

```text
docker compose --env-file .env --env-file .local-secrets/public-runtime-control/compose.env \
  -f compose.yaml -f deploy/compose/compose.examples.yaml -f deploy/compose/compose.runtime.yaml --profile modular up --build
```

该命令只启用`modular`示例部署和代码控制器；它不选择`full` profile。准备器输出的三条示例Agent绑定只有在包含`deploy/compose/compose.examples.yaml`时才对应到示例服务。多份 Compose `--env-file`按从左到右读取，后面的文件覆盖先前文件；shell已导出的同名变量仍会优先覆盖env-file。准备器把控制器 IP、单独生成的平台私网 IP、子网、指定的`CODE_RUNTIME_DOCKER_CLI_IMAGE`不可变摘要及目标宿主实际`CODE_RUNTIME_DOCKER_SOCKET_GID`写入`compose.env`。启动前清除这些同名shell变量，让绑定、证书、监听地址和静态网络地址使用同一组准备值。该overlay针对Linux Docker Engine的`/var/run/docker.sock`。
