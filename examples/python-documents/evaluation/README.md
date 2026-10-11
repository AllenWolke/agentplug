# 文档助手的公共RAG Evaluation

业务输出提供 `retrieved_ids`（按平台最终Top-K/重排顺序）、`citation_ids`、完整答案声明；指标实现、数据集/套件冻结、调度、输出产物、评分、恢复与发布闸门都属于平台 `evaluation-product`，Agent不自评。

`metrics.json` 是六项指标的管理提交配置：Recall@3、Precision@3、MRR、NDCG@3、引用准确率和引用接地。分别提交到 `POST /api/modules/evaluation-product/metrics`；指标发布、人工数据集审查与套件冻结仍需当前管理权限及合法状态转换，不能从业务Agent直写SQL。

先完成知识源及索引发布，再由有权限的评测维护者确认规范chunk ID、版本和正文，形成带 `case_id`、`input`、`expected` 的数据集用例。`input` 只放业务问题/top_k/cache_mode；`expected` 放 `relevant_ids`、`citation_ids` 和 `citations`。每条金标citation格式为 `{"id":"实际chunk ID","revision":"实际版本","source":"人工核对的源","content":"核对后的规范正文"}`。正文从经人工批准的源快照取得，不能把Agent生成的引用正文直接当作金标。

公共Runner冻结数据集和指标公式后只将 `input` 交给Agent。Grounding公式的 `input_citations_field: expected.citations` 让评分进程仅使用冻结金标正文，忽略Agent返回的 `evaluation_citations`，拒绝缺失金标；声明仍以完整答案为评分对象。不要同时设置 `output_citations_field`，这会被判为歧义配置。

冻结的指标、数据集、套件和实际安装版本由平台工作空间绑定；启动评测后查询 `/api/modules/evaluation-product/runs/{id}` 与 `/api/modules/evaluation-product/evidence/{id}`，按平台产物ID/哈希核对输出。源或索引换版应重新核对金标并发布新的数据集/套件，不修改已冻结版本。Cache对照用相同问题分别设置use/cold/bypass，比较平台实际调用/预算/用量账本，而不是仅看Agent的saved_usage。

当前grounding是独立metric-service中的确定性词面基线，检查内容词、否定与条件；不是LLM裁判或完整语义NLI，改写可能被保守拒绝。引用接地通过不等于领域正确，未配置独立领域指标时DomainGrounding保持unknown，不能宣称通过完整发布闸门。正式开发数据库中的实际Python、公共Runner、独立评分与资产发布已于下文阶段验证，完整示例准出和最终集成仍待完成。

2026-10-04实际阶段：六指标已经通过正式Python、公共Runner及独立metric-service执行，引用接地配置版本为1.1.0。该版本支持完整声明句子与完整参考句子的格式归一匹配，保留限定、条件和否定，避免其他段落的否定数量导致误拒；不接受删掉条件的子串。旧已发布指标/套件/证据不可修改，升级时创建新指标版本及新套件。示例规范源问题六指标实际完成，Precision@3为1/3；状态passed不表示其值达到1。独立领域正确性仍unknown，质量发布闸门仍应阻断。完整示例准出和干净环境复现继续验收。
