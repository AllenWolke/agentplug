# CodeQL 精确误报处理

[安全边界与报告入口](../../SECURITY.md) · [供应链工作流](../../.github/workflows/supply-chain.yml) · [机器可读审查清单](../../.github/codeql/reviewed-false-positives.json)

审查日期：2026-10-12。范围是已完成 Go 全量源码审查后剩余的 **5 条具体告警**；本策略没有关闭任何 CodeQL 规则，也不把所有历史告警当作允许基线。

## 对 workflow 的影响

CodeQL 的 **Analyze 任务**与 GitHub 的 **Code scanning results 检查**不同。分析任务通常因构建、查询或上传失败而失败；发现源码告警并不等同于该任务执行失败。PR 中的扫描结果检查默认会因达到 `error`、`high` 或 `critical` 等级的发现失败，仓库设置及合并规则可改变具体门槛。这 5 条中包含 3 条安全严重性 7.5 的路径 / 解压告警，因此不能断言它们永远不影响 PR。依据：[GitHub 的 PR 告警说明](https://docs.github.com/en/code-security/how-tos/manage-security-alerts/manage-code-scanning-alerts/triage-alerts-in-pull-requests)。

本次处理只消除这 5 条经审查且源码未变的结果对上传报告的干扰，不保证其他扫描发现、外部服务故障或仓库配置问题也消失。历史 GitHub 告警的最终状态由同类别的新分析决定；本地没有调用告警关闭 API，也不宣称已在 GitHub 中标记为 `false positive`。

## 五条处理依据

编号沿用原始审查记录，位置为本次审查的源码位置；完整数据流与源码 SHA-256 在审查清单中固定。

| 编号 | 规则与位置 | 为什么是误报 | 支撑验证 |
| --- | --- | --- | --- |
| CQ-003 | `go/path-injection`，[protocol.go](../../workers/metric-runner/internal/protocol/protocol.go):116 | 请求仅提供插件 ID。`ResolveRegistered` 拒绝路径分隔符、父目录跳转等非法 ID，再在运维持有的注册目录内拼接固定 `plugin.json`。请求不能指定任意文件路径。 | `TestResolveRegisteredRejectsTraversal`、`TestDescriptorValidateRejectsUnsafeRegistration`，见[协议测试](../../workers/metric-runner/internal/protocol/protocol_test.go)。 |
| CQ-004 | `go/path-injection`，[protocol.go](../../workers/metric-runner/internal/protocol/protocol.go):249 | 制品路径由合法注册 ID 和经过校验的 entrypoint 推导。[PluginRunner](../../workers/metric-runner/internal/sandbox/plugin.go) 在校验制品前验证固定 Ed25519 公钥的描述符签名；业务调用者无权改变注册目录及制品。 | `TestDescriptorSignatureAndDigest`、`TestResolveRegisteredRejectsTraversal`，见[协议测试](../../workers/metric-runner/internal/protocol/protocol_test.go)。 |
| CQ-005 | `go/zipslip`，[remote.go](../../cli/agentctl/internal/template/remote.go):281 | 下载包只解压至新建私有暂存目录。`safeArchivePath` / [safeRelative](../../cli/agentctl/internal/template/upgrade.go) 拒绝绝对路径、目录穿越和设备路径；拒绝符号 / 硬链接、重复项，并限制文件数及解压量。查询未识别这套组合校验。 | `TestRemoteMaliciousMatrix`、`TestExtractTarGzLimits`，见[恶意归档矩阵](../../cli/agentctl/internal/template/remote_test.go)。 |
| CQ-027 | `go/log-injection`，[runtime_observation.go](../../platform/internal/capability/runtime_observation.go):347 | `raw` 是标准 `encoding/json.Marshal` 对平台构造的观测字段生成的紧凑 JSON。字段含字符串、数值、时间、权限结构及资源 map；字符串内 CR / LF 和控制字符被转义，写入的是 JSON 序列化结果，不能插入新的物理日志行。 | `TestRuntimeObservationJSONKeepsUntrustedMetadataOnOneLine` 验证换行不能伪造记录，并校验 JSON 反解后仍保留原元数据，见[日志边界测试](../../platform/internal/capability/log_boundary_test.go)。 |
| CQ-029 | `go/useless-assignment-to-field`，[main.go](../../platform/cmd/platform/main.go):832 | `ancestry.evaluation` 随后由 `ancestry.Check` 的值接收者方法读取。方法值在赋值后捕获，并交给执行守卫；[Check](../../platform/cmd/platform/coordinated_ancestry_guard.go) 在评测子执行分支调用 `VerifyPersisted`。删除赋值会拒绝合法评测执行，不是无效写入。 | [评测执行授权测试](../../platform/cmd/platform/evaluation_execution_authority_test.go)覆盖父级、用例、用户绑定与伪造请求拒绝；[授权实现](../../platform/cmd/platform/evaluation_execution_authority.go)保留持久化校验。 |

前两项的信任前提是注册目录、固定公钥和 Runner 配置由运维控制，业务用户和插件不可写。这不意味着底层 `LoadDescriptor` / `VerifyArtifact` 可以安全地接受任意不可信路径，也不豁免部署配置、文件权限或其他新调用者的审查。

## 如何做到精确并保留安全检查

1. 仍构建并提取全部 17 个 Go 模块；运行默认查询，并追加 `security-and-quality`。其他三种语言的扫描方式保持原有设置。
2. Go `analyze@v4` 使用官方为结果后处理提供的 `upload: failure-only`；分析失败仍然失败，并保留失败调试上传。成功分析生成的原始 `go.sarif` 保持不变。
3. [处理脚本](../../scripts/filter_codeql_false_positives.py)只在**规则、文件、精确行列范围、完整结果 / 数据流指纹、全部已审查防护源码 SHA-256**同时吻合时，从上传副本排除对应结果。关联位置、每条数据流的源和中间节点也参与指纹；所有流经源码都必须在校验清单内。仅忽略无语义的 SARIF 表索引与 taxonomy 展示编号，保留 source / sink 等语义属性；源码 LF / CRLF 和 UTF-8 BOM 统一后计算哈希。
4. 任一相关文件被修改、删除或改为符号链接，数据流改变、缺失或增加，路径解析不确定，或发现重复匹配时，都**保留告警**。清单不接受规则通配符、路径通配符或目录排除。清单 / 输入格式错误导致任务失败，禁止上传半成品。
5. 使用 `upload-sarif@v4` 上传副本，沿用 `/language:go` 类别，并明确绑定本次实际检出的 commit / ref。非 Go 分析仍直接上传。原始结果、副本、逐项处理原因与输入 / 输出哈希作为 `codeql-go-reviewed-results` Artifact 保留 90 天。

官方接口依据：[analyze@v4 的 upload 说明](https://github.com/github/codeql-action/blob/v4/analyze/action.yml)、[upload-sarif@v4](https://github.com/github/codeql-action/blob/v4/upload-sarif/action.yml)。没有通过 `continue-on-error` 放过失败，没有排除路径 / 日志 / 解压规则，也没有更改 Trivy、Gitleaks、其他语言、SBOM、镜像双架构漏洞扫描或签名门槛。

## 验证与日常维护

处理策略测试只依赖 Python 标准库，CI 使用 Python 3.12：

```sh
python scripts/test_codeql_false_positives.py
python -m pytest -q tests/release-validation
```

[公开测试夹具](../../tests/fixtures/codeql/reviewed-go.sarif)来自本次真实 CodeQL 2.27.1 / go-queries 1.6.11 全套查询的 5 条结果，保留实际位置、消息和数据流，移除不需要的传输表编号。它用于验证策略行为；不冒充新执行的源码扫描。反向测试证明：相同规则的新位置、相同位置的新来源、改动防护代码、其他规则 / 语言、含诊断的扫描均不会被静默丢弃。

可对一次真实扫描进行本地复核，输入与输出必须不同：

```sh
python scripts/filter_codeql_false_positives.py \
  --input /path/to/original/go.sarif \
  --output .tmp/codeql-reviewed/go.sarif \
  --summary .tmp/codeql-reviewed/review.json
```

审查清单状态含义：`excluded_reviewed_false_positive` 精确排除；`invalidated` 防护源码发生变化；`not_observed` 本次没有相同结果；`ambiguous_retained` 出现重复匹配，全部保留。后两者不会强行要求每次扫描必须产生 5 条告警。

相关源码或 CodeQL 数据流模型变化后，误报可能重新出现，这是复核机制的预期行为。维护者必须检查新的原始 SARIF、全部调用者与防护代码，运行对应安全测试及策略反向测试，再以可审查变更更新该条指纹、源码哈希、原因和证据。**禁止仅为了 workflow 变绿而批量刷新哈希，或自动接受新增告警。**

工作流、处理脚本和审查清单属于安全敏感变更，应由维护者审查，不能让 PR 提交者免审新增例外。原始 SARIF 始终作为完整发现记录保留；上传副本的零告警只表示本次发现均命中了已审查例外，不表示源码没有被扫描到的问题。

源码审查和精确处理不能证明平台没有其他安全问题。发布仍需执行完整供应链检查和目标环境验收。
