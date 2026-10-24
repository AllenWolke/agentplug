# Local Embedding 供应链修复与工作流复核（2026-10-24）

本轮针对 [supply-chain 运行 40063979538](https://github.com/AllenWolke/agentplug/actions/runs/40063979538) 的 `local-embedding` 镜像扫描失败，修复传递依赖漏洞，并检查供应链和质量工作流的后续门禁。本地结果与尚未触发的新提交托管结果分别记录，不把本地复验描述为 GitHub 已完成发布。

## 故障与修复

基线提交为 `c7a07e028b39d90eae02b552dd474e1d30b72467`。公开 API 确认供应链有 **23 个 job 成功、1 个失败**；失败 job 中 AMD64、ARM64 两次扫描都退出 1，SBOM 和签名后续步骤因此没有执行。

对日志中的不可变镜像 `ghcr.io/allenwolke/agentplug@sha256:3bb7ec2519371fb2dc8966291ef8c35fffb2d8fbcfc2035b373b683ebd453ad7`，用与工作流相同的 Trivy **0.70.0** 实际复扫，两种架构均发现：

| 依赖 | 原版本 | 漏洞 | 等级 | 修复版本 |
| --- | --- | --- | --- | --- |
| filelock | 3.32.3 | CVE-2026-112940 / GHSA-v4x8-3wr5-3wq8 | HIGH | 4.2.1 |

[维护者公告](https://github.com/tox-dev/filelock/security/advisories/GHSA-v4x8-3wr5-3wq8)确认 4.2.1 修复该缺陷。日志中的新版 Trivy 提示、第三方 SBOM 提示和许可证提示是通知或警告；这次退出码 1 对应实际命中的可修复高危漏洞。

原构建先从 Torch CPU 索引安装依赖，再安装 Provider requirements。Torch 和 Hugging Face 对 `filelock` 的约束允许已经安装的旧版本；requirements 未显式要求修复版本，因此后一次安装不会自动将其升级到安全基线。

本轮修改：

- [Provider requirements](../../../providers/local-embedding/requirements.txt)固定 `filelock==4.2.1`，保留现有 Torch、Transformers、Tokenizers、Hugging Face 和 NumPy 版本。
- [Dockerfile](../../../providers/local-embedding/Dockerfile)在移除安装器前实际执行 `python -m pip check`，构建时确认完整依赖集合一致。
- [供应链工作流](../../../.github/workflows/supply-chain.yml)明确命名两种架构扫描，使用 Python 3.12 执行[扫描摘要](../../../scripts/summarize_trivy.py)，在日志与 GitHub Step Summary 中显示漏洞编号、依赖、安装版本和修复版本。源码扫描也增加同样的诊断。
- 两种架构的扫描仍使用 `CRITICAL,HIGH`、`ignore-unfixed: true`、`exit-code: '1'`；没有增加 CVE 忽略项或 `continue-on-error`。镜像 SBOM 步骤明确要求两次扫描均成功，签名和证明步骤继续受全链路成功条件约束。
- [新增回归](../../../tests/release-validation/test_trivy_summary.py)覆盖漏洞输出、日志/Markdown 转义、架构不符、报告缺失或损坏、Step Summary 追加，以及两种架构均为发布前置条件。

## 两份工作流的实际复核

[同提交的质量工作流 40063402814](https://github.com/AllenWolke/agentplug/actions/runs/40063402814)经公开 API 核对为 **30/30 job 成功，零跳过**。因此本轮保留 [three-project-quality.yml](../../../.github/workflows/three-project-quality.yml) 的现有执行逻辑；新增测试会被其完整发布检查自动纳入。

| 检查 | 本轮结果 |
| --- | --- |
| 工作流语法与表达式 | actionlint 1.7.12 检查全部三份 workflow，通过 |
| 源码漏洞扫描 | 相同 Trivy 版本与高危门禁，通过 |
| 修复后的 Local Embedding | 实际构建 AMD64、ARM64 OCI 镜像，两种架构扫描均通过，无命中当前门禁的漏洞 |
| 其余发布矩阵 | 对同提交其余 17 种已发布镜像逐一解析不可变摘要，实际复扫双架构，**34/34 通过**；新增摘要兼容所有报告 |
| 镜像合计 | **18 种镜像、36 项架构检查通过**；Local Embedding 本轮重建，其余镜像沿用同提交的不可变制品进行复扫 |
| SBOM 与来源证明 | 本地双架构 SPDX SBOM 与 `mode=max` 来源证明均生成并核验；两个 SBOM 中 `filelock` 均为 4.2.1 |
| Provider 实际运行补验 | AMD64 通过；ARM64 本地 QEMU 推理失败，原始镜像同样复现，未计为通过，原生 ARM64 硬件待验 |
| 发布检查 | Linux Python 3.12 / Go 1.26.10 下 **320 通过、零跳过**，含新增 10 项回归 |
| E2E/性能契约 | **83 通过、零跳过** |
| 格式、模块、契约、源码归属、SDK/模板及扫描自检 | 通过；格式检查已在临时副本按 Linux 换行规则补验 |

Provider 运行补验使用在 AMD64 一次生成并冻结的小型测试权重，两种架构只读消费同一夹具。AMD64 实际启动正式服务代码，健康、未授权拒绝、文档和查询向量、1024 维有限归一化结果、非法用途和超长输入拒绝均通过。它验证依赖兼容与服务功能，不代表正式锁定模型的语义质量验收，也不会调用付费模型。

ARM64 的附加推理补验没有通过：本机默认 QEMU 模式出现段错误；显式选择 Cortex-A72 后 Torch/Transformers 导入通过，但生成随机夹具及服务加载冻结模型仍出现段错误。对同一提交原始 ARM64 镜像、同一冻结夹具和同一仿真设置进行对照，也复现相同失败。该现象在本次依赖修复前已经存在；没有修改镜像、服务代码或主机配置来隐藏它。当前工作流执行安装、构建、SBOM、漏洞扫描和签名，不执行这项推理探针，所以它不阻塞本轮 CI 修复，但原生 ARM64 推理部署仍需硬件验证。三个示例当前运行环境及模型配置保持原状。

本轮未重跑无改动的全部 Go/Java/前端与 SQL 托管 job；这些部分沿用同提交质量工作流已经成功的 30 个 job 作为基线。当前代码的工作流契约、完整发布测试、源码安全扫描及所有镜像架构检查均另行实际执行。

## 隔离环境与证据边界

双架构构建使用专属 BuildKit 容器及其独立状态卷，限制 3 GiB 内存和 2 CPU，不挂载 Docker socket，不推送注册表。ARM64 安装在本机 QEMU 仿真下耗时较长，完整构建实际成功，未跳过构建或依赖一致性检查。

本地 OCI 扫描使用按平台选择的 layout 视图，保留原始 manifest、blob 和配置摘要，并核对扫描报告的实际架构。Trivy 0.70 的本地输入读取器不按平台遍历嵌套索引，见[对应版本源码](https://github.com/aquasecurity/trivy/blob/v0.70.0/pkg/fanal/image/oci.go)；单平台视图解决该本地输入限制，GitHub 的远端不可变摘要扫描方式保持原样。

初次本地尝试中遇到的 Windows 子进程编码、Git 归档 CRLF、构建器上下文及 OCI 输入格式问题均保留失败证据；通过 Linux Python 3.12 复验、临时副本换行还原及正确 OCI 输入解决，没有修改真实 Go 源码格式、弱化扫描规则或把失败计为通过。

本轮外部模型请求 **0 次**，没有向既有数据库执行测试或迁移，没有变更账号、授权或历史未知记录。原有 9 个容器的 ID、镜像、配置、挂载和启动时间保持不变，平台、前端及三个示例健康检查通过。对照项目未做代码或运行环境操作。

逐架构摘要、扫描回执、SBOM/来源证明摘要、运行结果、源码 SHA-256 及清理结果见[机器可读记录](local-embedding-supply-chain-fix-20261024.json)。详细报告保留于忽略的 `.tmp/supply-chain-fix-20261024`，不得将整个临时目录、缓存或本地配置上传 GitHub。

本轮临时 BuildKit、专属状态卷、三张临时镜像、新下载的基线镜像引用、OCI 归档与视图、工具和缓存均已按所有权清理。共享默认构建缓存和既有服务资源未执行全局清理；清理后再次核对原有 9 个容器和健康检查，结果保持正常。

本轮未推送源码或镜像，未请求 GitHub OIDC 身份，也未在线签名或部署。上传时应包含新增摘要脚本、回归用例及文档；在包含修复的新提交上运行完整质量与供应链工作流，才可确认托管发布和无密钥签名的最终结果。此前两项 SQL/缓存故障的记录保留在[上一轮说明](github-actions-fixes-20261024.md)。
