# GitHub Actions 上传前验证（2026-10-23）

后续托管运行发现的两项故障及完整阶段补验，见 [2026-10-24 修复记录](github-actions-fixes-20261024.md)。本页保留当日上传前验证事实，不代表后续 GitHub 托管运行已全部通过。

本轮仅修改 AgentPlug 的 CI、构建依赖及配套说明，未推送 GitHub、未部署镜像。现有账号、授权、历史数据和运行服务保持原状；对照项目未做代码或运行环境操作。

验收针对 Git 发布候选集合，包含尚未跟踪的新增源码与测试。上传时需一并纳入这些新增文件；只提交已跟踪文件会遗漏本轮及前期实现所需源码。`.env`、`.local-secrets`、缓存、备份与本地验收副本不在发布集合中。

## 工作流与修复

| 文件 | 职责与本轮调整 |
| --- | --- |
| [three-project-quality.yml](../../../.github/workflows/three-project-quality.yml) | 保留 PR 与 `main` 推送门禁，增加手动运行。Go 竞态矩阵由 12 个模块补齐到全部 17 个发布模块；增加 `sync_public_sdks.py --check`。显式上传 `.tmp` 中的三组指定报告文件，SQL job 总时限调整到 45 分钟。 |
| [agent-eval.yml](../../../.github/workflows/agent-eval.yml) | 保留 Linux、macOS、Windows 原生矩阵与变更路径过滤，增加手动运行；统一 Go 补丁版本。 |
| [supply-chain.yml](../../../.github/workflows/supply-chain.yml) | 保留安全扫描、完整历史扫描，以及同仓库 `main` 成功质量门禁后的精确提交发布约束。更新 Go 和 Code Runtime 基础镜像，继续要求两个发布架构均扫描后再签名。 |

- CI、活动镜像构建和验证脚本统一使用 Go **1.26.10**；它包含 `crypto/x509` 安全修复，见 [Go 官方发布记录](https://go.dev/doc/devel/release#go1.26.10)。语言最低版本及已发布 SDK 协议未改变。
- 实际 Trivy 扫描发现 `platform/go.mod` 中的间接依赖 `github.com/klauspost/compress v1.15.9` 命中 **CVE-2026-63209**；已升级到 `v1.18.7`，见 [维护者公告](https://github.com/klauspost/compress/security/advisories/GHSA-259r-337f-4rfw)。没有增加漏洞忽略项或放宽退出码。
- Code Runtime 原基础镜像的 Docker CLI 29.9.0 仍由 Go 1.26.9 构建。现固定为多架构索引 `docker.io/library/docker:29-cli@sha256:5e6baf67325a79f64ed3bed6863954d5e05d0f3d4e57cbdb14809346814bbfdb`，实际核验客户端为 **29.9.2 / Go 1.26.10**，索引包含 Linux AMD64、ARM64。
- 隔离 Kafka 回归复现了首次竞态编译超过原 210 秒外层等待限制的问题。普通验证命令的外层限制调整为 600 秒，Go 测试本身的 **180 秒限制不变**；真实模型、进程恢复和全平台测试各自的原有独立限制继续保留。
- 新增 [workflow 回归测试](../../../tests/release-validation/test_workflow_checkout_contract.py)，防止发布模块漏测、CI/镜像 Go 版本漂移、SDK/模板同步门禁遗漏，以及隐藏目录报告上传配置退化。隐藏上传仅指定报告文件，不能上传整个临时目录；参见 [upload-artifact 说明](https://github.com/actions/upload-artifact/tree/v6#uploading-hidden-files)。

## 本轮执行结果

验证使用独立 Git 副本及可发布文件集合，不复制 `.env`、私有目录和既有构建产物。Linux 检出按 Git 索引与 `.gitattributes` 使用 LF。依赖安装、Maven 和 npm 安装均实际执行。

| 验证 | 结果 |
| --- | --- |
| 三份 workflow 的 actionlint 1.7.12 检查 | 通过；最终 Go 1.26.10 环境执行 |
| 16 个外部 Action 版本与输入参数 | 均按官方标签的 `action.yml` 或 `action.yaml` 实际核对通过 |
| 发布文件、文档链接、格式、模块边界、契约及 SDK/模板同步 | 通过；共享副本 270 个文件零漂移 |
| Go 竞态矩阵 | 17 个模块命令通过；metric-runner 在非 root、512 MB、128 进程限制下执行完整竞态与恶意插件沙箱测试。该通道按设计跳过的“缺少限制”用例，另在保持内存限制、缺少 PID 配额的断网环境单独通过 |
| Python SDK 普通单元测试 | 560 通过、3 个数据库条件用例跳过；不将跳过计为通过 |
| Python SDK 独立 PostgreSQL 完整回归 | **575 通过、零跳过**；包含上述数据库用例，以及检查点升级、角色隔离和持久退出恢复 |
| Python 示例与两种 Python 模板 | 13、52、43 项通过 |
| Java SDK 与示例 reactor | 69 项通过；从空 Maven 依赖目录构建成功 |
| 两种 Java 模板 | 6、10 项通过 |
| 前端 | 全新 `npm ci`、164 项测试及生产构建通过 |
| 六种模板真实 HTTP Conformance | **78 项通过**，每种模板启动两个实际进程 |
| 发布验证测试 | Linux 301 项通过、2 项因缺少 kubectl 跳过；补入官方校验过的 Linux kubectl 后，两项均在断网容器中通过，因此 303 个用例均有实际通过证据 |
| E2E/性能门禁合约测试 | 83 项通过；包含恢复代理测试 |
| Proto 生成、PowerShell 发布模拟、Prometheus 规则 | 通过；仅执行模拟或独立工具容器 |
| 源码与两种受影响镜像的漏洞扫描 | 按原 `HIGH,CRITICAL`、已有修复版本、退出码 1 门槛，三份最终报告均为零发现；镜像为本轮独立构建的 AMD64 临时镜像 |
| 完整可达 Git 历史密钥扫描 | 8 个提交、约 20.89 MB，零泄露；5 组真实扫描器正反控制符合预期 |
| PostgreSQL + Kafka 授权传输 | 第三次隔离回归通过，必需测试执行且零跳过；首次镜像未预拉取、第二次冷编译超时均保留失败记录 |
| 全平台 PostgreSQL 回归 | **3,478 通过、零失败、83 个条件用例跳过**；完整迁移及运行账号 DML 边界先执行，检查点 SQL companion 1/1 通过。83 个专用夹具、跨进程或真实供应商条件分支不计作通过，逐项原因保留在结构化回执中 |

本轮原始日志和结构化回执保存在被 Git 忽略的 `.tmp/github-workflow-check-20261023/`，汇总见 [机器可读记录](github-actions-verification-20261023.json)。本地复制流程最初保留 Windows CRLF 导致的 4 项失败，在规范化为实际 Linux 检出内容后已重跑通过；宿主首次启动 kubectl 超时的一项也通过断网 Linux 客户端重新验证。失败记录保留，没有通过修改业务断言消除失败。

回归后已删除本轮 4 个临时验证镜像及约 7.4 GB 编译、下载和构建产物，保留独立源码快照、原始回执和私有 Go JSONL。112 项证据哈希复核通过；共享基础镜像与构建缓存没有全局清理。原 9 个服务的容器、镜像、配置和启动时间核对一致，平台、前端及三个示例就绪复查通过。

## GitHub 首次运行的条件与边界

83 项条件跳过已另行逐项核验：本轮 82 项实际执行通过，1 项辅助入口由父测试实际驱动验证，未解决项为 0。新增 CI job 强制执行免费的专用公共契约检查；付费供应商和公共 DNS 探测保留显式启用。完整原因、启用条件、对 workflow 及三个示例的影响见[83 项补验验收](conditional-tests-acceptance-20261023.md)和[逐项机器回执](conditional-tests-verification-20261023.json)。原始全量回归的 83 项跳过记录保留，不改写为该次全量运行已通过。

1. 仓库启用 Actions，允许当前工作流引用的 Action 与 hosted runner。自动发布分支为 `main`；手动 `agentplug-quality` 验证不会触发镜像签名发布。
2. CodeQL 使用本仓库提供的 **advanced setup**。已有 default setup 的仓库需切换；仓库须为公开仓库，或已启用相应 GitHub Code Security 能力，参见 [GitHub 配置说明](https://docs.github.com/en/code-security/how-tos/find-and-fix-code-vulnerabilities/configure-code-scanning/configuring-advanced-setup-for-code-scanning)。
3. GHCR 发布使用 job 已声明的 `packages: write`，签名使用 `id-token: write`。若同名 `agentplug` package 已存在，需要向当前仓库授予 Actions 访问权限，参见 [GitHub Container registry 说明](https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-container-registry)。
4. 本轮没有触发 GitHub hosted runner，未将 CodeQL 实际远端分析/SARIF 上传、GitHub artifact 实际上传、GHCR 推送、OIDC 签名、全部 18 种镜像的双架构发布，以及 macOS/Windows 原生 job 记为通过。Linux 容器回归不替代真实 hosted runner 的完整环境验收。
5. 漏洞库、镜像仓库和托管运行环境会继续更新；新发现仍须阻断，不能把本次通过理解为未来扫描永久零错误。
