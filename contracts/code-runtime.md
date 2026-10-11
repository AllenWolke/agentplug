# 公共 Code Runtime 协议

当前实现处于开发整合阶段，未部署或完成总体验收。平台统一执行授权与审计，Go/Python/Java使用既有公共Tool接口；SDK不持有控制器私钥、Docker权限或状态加密密钥。

## 公共调用

工具名由运维注册，例如`code.python`、`code.javascript`、`code.shell`。输入仅包含`{"code":"源码"}`，最多64KiB。调用须有明确且稳定的`call_id`，通过已发布工具策略、当前调用人与Agent双身份资源权限及操作绑定人工批准。代码内容改变时必须使用新的操作ID和批准。

平台固定执行类型`code`、风险`high`，使用公共执行租约及取消监督。执行许可`code-permit/v1`绑定完整可信作用域、身份/版本/安装、权限世代、策略及批准、代码指纹、call_id、LeaseFence、Profile、资源上限、控制器受众和最长60秒有效期；有效期进一步受当前批准、租约与请求截止时间限制。许可使用独立Ed25519私钥和专用签名域，不能与平台上下文或人工批准密钥复用。

## 平台启动装配

可选环境变量：`PLATFORM_CODE_BINDINGS_FILE`、`PLATFORM_CODE_PERMIT_PRIVATE_KEY_FILE`。同时设置才启用；缺少持久IAM/审批配置时启动拒绝。Binding文件是严格JSON数组，每项固定tool_name、endpoint、controller_id、profile_id、language、limits、tenant_id、application_id、agent_ids。签名密钥文件为base64编码Ed25519私钥，仅挂载给平台。

Endpoint仅允许运维配置的控制器origin，无路径参数、查询、凭据或跳转。当前客户端复用受控DNS/IP及TLS策略，不继承宿主代理；开发模式可使用本机loopback。控制器响应等待上限适配Code的长超时，不复用普通API的短响应截止时间。

## 控制器与结果

执行镜像从 `workers/code-runtime/images/Dockerfile` 的三个目标构建为 `agentplug:code-python`、`agentplug:code-javascript`、`agentplug:code-shell`，配置绑定实际 immutable image ID。控制器拒绝缺少固定文件守卫标记/入口的原始语言镜像；每次启动前核验容器 ID、实际镜像、入口、语言、用户及原有隔离限额。镜像标记只是配置检查，可信来源仍须由仓库构建与摘要核对证明。

固定 `code-sandbox-guard` 要求 Linux amd64/arm64、Landlock ABI至少为3及UID/GID65532，在同一锁定OS线程设置路径规则后exec解释器。仅允许镜像系统库目录读取/执行、少数运行必需文件，以及本任务workspace/tmp/shm读写；proc/sys和其他目录不放行正文读取/目录枚举/写入。临时目录禁止执行。关闭除三条标准流外的继承描述符，解释器环境固定；子进程继承规则，路径穿越、链接和目录描述符不能扩大访问层次。ABI不足或规则设置失败不执行用户源码。内核仍可允许部分文件元数据查询，这不是读取敏感正文的授权。见[官方Landlock文档](https://docs.kernel.org/6.6/userspace-api/landlock.html)。

控制器持有验签公钥和独立AES-256状态密钥；使用运维固定Profile及镜像ID，Agent不可覆写。`POST /v1/execute`与`POST /v1/receipt`只接收签名permit。租户/应用/Agent与具体源码的许可绑定由平台生成，控制器验证签名、有效期、受众与Profile。

排他持久claim先于实际执行；完成后追加加密receipt。相同作用域/call_id的不同指纹拒绝，未知或中断执行不重新运行。回执查询只读，不执行、不修复。结果使用`code-execution/v1`，平台检验回执绑定、资源配置、输出大小与清理证明，并经公共Observation脱敏、截断和非可信上下文封装。标准审计不包含源码、许可、完整密钥、环境变量或原始结果正文。

## 资源测量和审计

Linux 控制器通过固定本机 Docker socket 读取自己创建的容器统计，先协商受支持的 Engine API 版本（1.41～1.48），再调用只读 stats 接口。业务不能指定 socket、地址、容器 ID 或采样参数；请求不继承代理、不接受跳转，超时及响应大小有界。协议依据见 [Docker Engine API v1.48](https://docs.docker.com/reference/api/engine/version/v1.48/)，包含stats及固定Exec创建/启动/检查接口。

`resource_usage` 只允许 CPU/内存元数据及磁盘采样元数据：`cpu_time_ms`、`peak_memory_bytes`、`disk_bytes`、`sampled_peak_memory_bytes`、`sample_count`、`measurement_source`、`measurement_complete`、`disk_sample_count`、`disk_measurement_source`。CPU时间与采样内存最大值来自 Engine 实际数字；重复时刻不计新样本。`peak_memory_bytes` 仅在 Engine 提供 max_usage 时记录，不能用采样最大值替代。`measurement_complete` 固定 false，采样不能证明全程峰值或最终累计 CPU。

磁盘采样通过受信任控制器在固定容器中执行无 shell 的固定 argv：`/bin/stat -f -c %b:%f:%S /workspace /tmp /dev/shm`；每次最多500ms、stdout/stderr合计最多512字节、整个执行最多128个尝试。Exec 请求明确设为非特权、用户 `65532:65532`、工作目录 `/workspace`；返回的容器 ID、实际 `ProcessConfig` 用户/argv和退出状态必须与请求完全一致。仅解析恰好三行 `blocks:free:block_size`，计算三个隔离tmpfs的 `(blocks-free)*block_size` 之和；`disk_bytes` 是有效样本中的最大观测值，`disk_sample_count` 与 `disk_measurement_source=docker_exec_tmpfs_stat/v1`记录采样来源。它是有限采样最大值，不是全程峰值或累计写入量；不读取tmpfs配额或block I/O当作使用量，不记录路径输出、环境或原始命令结果。镜像文档指向Alpine BusyBox `/bin/stat` 与Debian合并`/usr`路径，但尚未对实际固定镜像进行容器验证；命令、格式、超时或采样不可用时保留`disk_bytes:null`、来源`unavailable`。

短任务、统计不可用或当前宿主不支持采集时，相应数值保持 null、来源为 unavailable、对应样本数为0；Engine 或 `stat` 明确测得的0与缺失字段分别处理。平台拒绝负数、小数、越界值、不匹配的来源/计数、非白名单字段及虚构完整测量；兼容旧七字段回执（磁盘为null）与旧三项null回执，均不会推定未记录的磁盘用量为0。规范化后的元数据才进入 Observation 和审计。

## 待完成边界

平台已将成功、已知代码退出失败、超时、取消、资源及输出超限包装为真实状态的标准Observation，并通过幂等账本保存；三语言Harness复用受限错误上下文。平台已有running/unknown记录时，回执接口可在当前鉴权与批准下查询控制器完成结果，不执行代码或修复账本。后台恢复没有当前人工批准时拒绝签发许可，不会凭旧账本恢复权限。固定文件路径守卫已补源码，输入仍只接受经批准绑定的源码，不提供宿主路径、挂载或外部文件注入参数。Code网络始终关闭；平台的域名/路径白名单网络访问由注册的API Tool承担，服务凭证不传入Code。资源采集、文件守卫和三业务可选 sandbox_check 已完成源码及必要编译/静态检查，实际执行镜像构建、正式部署和三语言总体场景仍待完成。服务端验签不等于已证明实时撤权与取消，需开发完成后集中进行实际链路验收。

