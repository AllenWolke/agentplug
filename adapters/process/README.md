# Process Adapter

Process Adapter 仅用于 L1 存量命令行 Agent。它由 PluginHost 的 `sandbox` Launcher 启动，命令、参数、工作目录、只读文件和 Secret 引用必须来自已签名 Plugin Descriptor；禁止请求方提交任意命令。

## 强隔离（强资源与网络边界）

Adapter **不提供无隔离的执行模式**。启动时必须登记完整隔离信封，任一上限缺失即 `log.Fatal`，请求路径也永远无法放宽它：

| 边界 | 变量 | 实施方式 |
|---|---|---|
| 内存 | `PROCESS_SANDBOX_MEMORY_BYTES` | 由外层容器 cgroup 强制；`PROCESS_SANDBOX_REQUIRE_CGROUP_MEMORY=true` 时 Adapter 在启动阶段核对 cgroup 限额（未设置或大于登记值即失败闭合） |
| CPU | `PROCESS_SANDBOX_CPU_SECONDS` | 目标命令继承 `RLIMIT_CPU`，超支后内核先发 `SIGXCPU` 再 `SIGKILL` |
| 进程/线程 | `PROCESS_SANDBOX_MAX_PROCESSES` | 目标命令继承 `RLIMIT_NPROC` |
| 输出 | `PROCESS_SANDBOX_MAX_OUTPUT_BYTES` | 捕获缓冲有界，越界按 `PROCESS_EXECUTION_FAILED` 拒绝且不缓冲更多字节 |
| 墙钟 | `PROCESS_SANDBOX_TIMEOUT_SECONDS` | 单次调用的 `context` 截止时间 |
| 网络 | `PROCESS_SANDBOX_NETWORK` | `none`：Adapter 为目标创建空网络命名空间（需 `CAP_SYS_ADMIN`，失败即闭合）；`container`：由外层容器运行时及其 NetworkPolicy 负责 |
| 文件系统 | 部署模板 | Distroless `nonroot` + 只读根文件系统与只读挂载 |
| 环境变量 | `PROCESS_ENV_JSON` | 目标进程只接收登记白名单，默认**不继承** Adapter 自身环境（平台凭证不会外泄） |

实现要点：Go 无法在 `fork` 与 `exec` 之间设置 rlimit，因此 Runner 会以 `__lexagent_sandbox_exec` 重启 Adapter 二进制作为「沙箱跳板」，在跳板里施加 `RLIMIT_CPU`/`RLIMIT_NPROC`（以及可选的网络命名空间），随后 `execve` 预注册目标。跳板信封只经环境变量传递，命令与参数不出现在进程列表，也不能由请求提供。

非 Linux 平台没有可移植的 rlimit/`execve` 通道，Adapter 直接失败闭合，不会退化成无隔离执行；生产部署在 Linux 容器内运行。

健康状况 `/health/ready` 会回显已登记的沙箱上限，运维可据此核对实际生效的边界。
