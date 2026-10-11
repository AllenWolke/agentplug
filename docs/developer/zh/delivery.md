# 从业务工程到平台可用 Agent

[开发者路线](README.md) · [English](../en/delivery.md)

交付目标是：**指定公司与部门中的指定用户，可以通过平台成功运行某个确定版本的业务 Agent。** 源码测试通过、镜像启动和前端看见名称都不是这一步的完整验收。

首次交付先走[完整实战](walkthrough.md)，用可运行的自定义 Agent 流程理解下文各环节。脚本保留实际接口请求和验收证据，不用三个固定示例替代你的业务。

## 一次准备交付信息

记录目标平台地址、部署方式、公司 / 部门 / 内部 Application、Agent ID 与版本、制品摘要、实际端点、工作负载身份、允许的能力、需启用的用户及有效期。缺少的目标范围先从平台实际记录读取，不猜 ID，也不把三个公开示例的固定 ID 套到你的业务。

先写好可审查计划和配置，再执行已授权的部署与赋权。代码助手可以使用[交付 skill](skill.md)完成这条路径；平台发布、部门上限和用户使用包仍走现有治理接口。

## 1. 检查业务和公共能力复用

按[第一个 Agent](first-agent.md)生成工程、写业务 Hook 并测试。准备真实业务输入 / 输出 Schema、Manifest、版本和评测用例。按[公共能力](capabilities.md)列出本 Agent 需要的模型、知识、工具、记忆、Skill、检查点与协作；不用的能力说明不需要，不为通过检查而强加。

除了成功场景，测试无效输入、权限拒绝、依赖失败、超时、取消和业务声明的恢复能力。进程内 Store 不等于持久恢复。确定性测试与真实供应商测试分开记录，付费调用明确使用的供应商与数据范围。

## 2. 生成和登记真实制品

按业务工程的 Dockerfile 构建镜像，记录实际内容摘要，发布到目标部署环境能访问的仓库；本地标签与可拉取的仓库 digest 含义不同。随版本保留 Manifest、Schema、测试 / 评测证据和 SDK / 模板版本。

平台目录管理 **Definition → Version → Installation → Deployment**。版本先经过评测和受控发布，随后安装到目标内部 Application；安装的发布策略和实际部署状态独立维护。`agentctl package` 不自动发布版本，`agentctl publish` 也不等于完成审批和部署。

三个正式例子的发布请求可以离线生成：在 `platform/` 执行 `go run ./cmd/example-release-bundle`，用 `--example`、`--artifact-digest`、`--publisher`、`--endpoint` 提供实际信息。该工具生成计划，不自行批准或观测健康；自定义 Agent 用其真实 Schema / Manifest 和目录接口准备相应请求。

目录接口的当前参数以[前端 API 接线](../../../frontend/src/api.js)中的 `catalogCreateVersion`、`catalogTransitionVersion` 及安装 / 部署接口和 [Catalog 实现](../../../platform/internal/catalog/)为准。发布者和独立审批 / 评测人的职责不合并为“万能管理员”。

作者在指定范围内创建 Definition 和 Version 时，POST 路径须附带 `tenant_id`、`department_id`、`application_id` 查询参数，且与当前身份范围一致。安装方式使用 `managed` 或 `external`，不使用未定义的 `service`。

## 3. 配置并发布公共能力策略

对应安装需要 **模型、Prompt、工具、记忆、知识、Runtime** 六类策略资产和匹配的发布快照。已批准模型版本与内部价格、端点引用和 Secret 要真实存在；知识绑定有实际源 / 索引；工具和 Skill 在允许范围内。即使不用某类能力，也明确保持对应策略的最小允许范围。

模型供应商 Secret 只在平台端挂载。业务 Agent 不持厂商 Key。生产通过 PolicyAsset 发布维护 Prompt，不使用启动 JSON 直接注入来绕过发布。

不用工具或知识时，显式填写 `allowed_tools: []`、`allowed_scopes: []`，表示禁止调用；省略或 null 不能发布。确定性教程使用零预算且无真实端点的模型配置占位，不能据此宣称模型已接入。

三个例子可使用 [publish_public_policy_release.py](../../../scripts/publish_public_policy_release.py) 的 `prepare`、`create-drafts`、`publish`；其作者和发布者必须不同。工具的默认作用域针对公开例子，自己的目标需要明确指定，并核对工具支持的数据形状。[详细操作参考](../../开发者指南/业务Agent挂载与已有用户授权指南.md)。

## 4. 部署服务并核实安装状态

在选定的[部署方式](deployment.md)下运行 Agent。配置 SDK 公钥、Agent ID、issuer / audience、能力网关地址和工作负载认证；Agent ID 与 Manifest、安装一致，端点从**平台所在网络**可达。

`127.0.0.1` 从容器或 Pod 内访问指它本身。Compose 服务之间使用服务名，K8s 使用 Service DNS；不要把浏览器能访问的宿主机地址直接当成所有环境的能力地址。

真实部署控制器核对实际镜像和 `/health/ready`，使用 [deployment-observe](../../../platform/cmd/deployment-observe/) 的预览 / 输入 hash / revision 约束记录观测，安装才成为 `active`。不能为了演示在数据库手写 ready、也不让业务用户 API 伪造部署观测。

## 5. 创建并绑定机器身份

为每个 Agent 使用独立工作负载凭据，创建机器主体，绑定目标 Installation 与版本 / 策略，限制平台实际观察到的来源网络和能力资源。不把浏览器网关 Token 当机器认证使用。

机器绑定、资源授权和安装可用性分别核验。具有机器管理权的操作者在“机器身份凭证”中办理；受控维护入口 [configure-workloads](../../../platform/cmd/configure-workloads/)支持预览与输入摘要约束，但平台数据库凭据不能交给业务 Agent 或普通用户。

**绑定 Installation 不自动授予执行权。** 通过授权变更预览 / 提交，为机器主体单独授予该安装所需的执行动作；教程配置 `run`、`history.read`、`cancel`、`history.continue`，每条记录有 `source_id` 与明确数据范围。模型、知识等调用还需独立授予相应机器资源权限，不能只给调用用户开通。

新部门默认未批准任何 Agent。创建并绑定身份后，先由公司管理员完成下一节的部门 Agent 上限，再办理受该上限约束的机器和用户资源授权。

## 6. 公司、部门和用户绑定

| 层级 | 操作者与界面 | 实际影响 |
| --- | --- | --- |
| 公司工作空间 | 平台管理员任命对应公司管理员；公司管理员管理公司组织 | 一个用户属于一个公司，不跨公司套用成员关系 |
| 部门成员 | 公司管理员的“用户主体管理 / 部门管理” | 把用户加入部门，任命部门管理员或部门用户；不自动开通 Agent |
| 部门 Agent 上限 | 公司管理员在“部门管理 → 可用 Agent” | 限定该部门哪些安装可被授予哪些操作及期限 |
| 用户使用权 | 公司管理员或获准部门管理员在用户列表选人 → “开通 Agent 使用” | 读取当前使用包，批量赋予个人会话操作和已发布配置所需资源 |
| 特殊操作 | 单独预览授权 | 分享、导出、内容修改、管理和高风险操作不默认包含在日常使用包中 |

日常批量使用包包括个人会话和安装策略涉及的模型、知识、工具、记忆资源，避免逐条勾选基础资源。每批最多 50 用户，跨页选择后先预览；确认、再次认证、提交，查看逐人结果。已有权限和拒绝规则保留，deny 仍优先。

部门管理员只能在公司设定的 Agent 上限和自己的管理范围内给**其他成员**开通使用；管理员不能给自己新增业务权限。自己的业务使用必须由其他有权操作者独立授权。

API 自动化应复用[现有前端请求与命令构造](../../../frontend/src/features/identity/permission-batch.js)：`department-agent-changes:preview` → `department-agent-changes`，`agent-use-package` → `permission-batches:preview` → `permission-batches`，保留当前 revision、package digest、再次认证和原 idempotency key。不是直接插入 Grant 表。

查询 `agent-use-package` 时只传 `department_id`、`application_id`、`installation_id`；公司由当前登录身份推导，不额外传 `tenant_id`。部门上限变更则按自身接口填写公司和部门，并用预览摘要取得相应再次认证证明。

## 7. 完成真实验收

| 验收项 | 需要保存的证据 |
| --- | --- |
| 获准用户运行 | 对应用户、范围、安装 / 版本、run ID、业务输入、终态与正确结果 |
| 公共能力调用 | 实际模型 / 知识 / 工具等结果、引用或收据；不只网络 200 |
| 未获准用户 / 跨公司 | 可见性及运行 / 资源拒绝；不能以全局管理员替代普通用户测试 |
| 取消、超时与恢复 | 终态、收据、检查点及真实副作用状态，覆盖业务声称支持的能力 |
| 审计与费用 | 目录 / 策略 / 绑定 / 授权的 receipt，模型内部用量记录 |
| 部署可维护 | 健康探针、秘密归属、版本 / 回滚条件和持久化边界 |

输出一份用户登录验收清单：账号、公司、部门、Agent、日常操作、特殊操作和管理范围；不写密码。存在未配置、跳过或没有证据的条目，明确标为待完成，不能写“已上线可用”。

若批量提交或工具调用响应未知，读取原 receipt / batch 状态再恢复，不重新生成 key 重发。撤销和回滚以具体授权、安装、版本和数据库兼容性为准，不通过删除所有数据来恢复。
