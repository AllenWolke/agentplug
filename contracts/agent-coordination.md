# 公共Agent路由与协作协议（开发中）

Runtime.delegation须明确发布allowed_agent_ids/task_types/max_depth/max_children，省略时关闭；最多4层、16个累计子任务。业务路由不同于传输选择。当前仅领域Router和SQL账本已开发编译，实际HTTP/SDK和执行未装配，不能用于真实子Agent派发。

Route输入operation_key/task_type/count，Scope及父链/策略来自已验证当前执行。agent-route/v1结果固定父Run、策略Hash、任务/深度、已授权已发布就绪Target及EvidenceDigest。只选择同租户/部门/应用安装；拒绝自身和祖先Agent/安装循环。相同键指纹变更冲突，回放复查当前目标，不自动切换版本。Plan不携带厂商Token或客户端指定Endpoint。

SQL父键使用稳定完整执行身份，不以新epoch/Trace创建额外配额。Plan、逐目标子任务预留和安全元数据Audit/Outbox事务提交；提交前必须通过实际Authority取得当前父执行/IAM连续性和选定Catalog目标绑定。只有明确控制器结果才能推进子任务状态；未知网络结果保持预留，不能重发或释放预算。真实子任务状态机、取消/恢复和父子Token/Cost归集尚待开发。

显式迁移2026100404创建两张协调自有表，保留0403 Skill原校验；不在业务启动执行DDL。全量场景验收将在开发整合后运行。

Catalog内部事实Port从精确工作空间和允许Agent ID读取最多128候选，冻结安装Revision、Deployment ID/Desired/Observed Revision、Version、sha256: Manifest/Artifact及Manifest metadata.route_task_types。Catalog结果不是授权；组合根须重复当前调用人/父机器权限和真实父执行世代。滚动发布未就绪不回退，权限或绑定未知则拒绝。三示例源码已声明任务类型但没有发布、授权或派发。

POST /internal/agent/route输入operation_key/task_type/count，返回{route:agent-route/v1}。仅供已验签且具当前父执行租约的Agent；双方须agent.delegate本安装权限与Runtime明确delegation，用户及父机器分别须目标安装run权限。新增agent_delegate/v1不改旧角色、不自动授权。SQL提交前实际IAM/Run lease/Catalog复查已装配源码。路由计划不派发子Run、不是执行许可；正式部署、真实子边/能力收敛、调度取消恢复和SDK仍待完成。

三语言调用：Go RouteAgents(ctx,operationKey,taskType,count)，Python await route_agents(operation_key,task_type,count=1)，Java routeAgents(operationKey,taskType,count)。结果为路由计划，SDK校验当前父Run/操作/任务/数量与目标ID，不能据此派发或绕过授权。后代路由来源须协调账本accepted/running精确子Run边；ParentRunID不是来源证明，未知或仅预留边不授权。实际子运行创建/派发和三语言执行查询尚未完成。


### Child preparation (development, not dispatch)

`POST /internal/agent/prepare` accepts `operation_key`, `ordinal`, `expected_revision` (initial value 1), `input_schema`, and an object `input`. It requires the same signed execution context, published delegation policy and current dual-identity `agent.delegate` access as route planning. The selected ordinal and schema must match the saved plan and current target authorization. Input is bounded to 64 KiB; caller-supplied `policy_snapshot` is rejected.

Response key `preparation` contains `agent-child-preparation/v1`, parent_run_id, operation_key, ordinal, stable child_key, status `preparing`, revision 2, input_schema and input_fingerprint. Replay requires identical frozen input and performs current authorization checks. Neither a Run nor budget reservation nor Agent RPC is created by this endpoint. Actual child admission must atomically bind this preparation, current permissions, immutable target policy, shared budget and execution metadata before dispatch. The execution module's `CreateCoordinatedRunTx` Port is not directly exposed over HTTP and is not yet wired to admission.


### Shared root budget (development)

UsageCost owns a durable root Run token/cost budget and immutable per-actor request receipts. Counters admit on used + held, serialize under a root row lock, retain uncertain holds, preserve known actual charges above estimates/limits, and release only with independently verified terminal unbilled evidence. Request replay never implies permission to resend a provider request. Root lineage, immutable policy limits and admission-time IAM/fence continuity must come from the composition Authority; accounting of known charges retains original ownership after revocation.

`SQLRunTreeBudgetStore.ApplyTx` and existing `SQLStore.ReserveTx` are caller-owned transaction Ports for atomic root and Agent/price-window admission, using the common lock order root then window. On error the caller rolls back the entire transaction. Neither Port dispatches a child nor invokes a provider. Explicit migration source 2026100405 installs the root budget tables; this source has not been migrated or deployed. Actual Authority/model/coordination integration and full scenario acceptance remain pending.


The immutable Runtime policy may declare `run_budget: {limit_tokens, limit_micros}` for the root and all coordinated descendants. Both are nonnegative; zero grants zero allowance. Omission preserves older snapshot JSON and does not authorize coordinated admission without an explicit root budget.

`SQLRunTreeModelBudgetStore` implements model budget reserve, settle, retained unknown hold, release and manual terminal unbilled resolution with one root-then-price-window transaction. Existing price-window Tx Ports preserve standalone interfaces. Any composed error, including price-window expiry, rolls back both ledgers. Unknown/terminal root receipts cannot re-admit a provider send. A real authority must bind signed execution estimates and persisted original actors to requests, verify root provenance/current admission permissions, and verify actual provider receipts for accounting. That authority and production wiring are still pending; the source adapter is not enabled in the running platform.


The model gateway now supplies a private, verified execution/request/token-estimate binding only for stores implementing `ModelBudgetExecutionBindingStore`. Client JSON cannot mint that authority. UsageCost atomically persists original Scope and admission parameters with the held root request before reserving its price window. Stored timestamps use UTC microseconds, matching the existing SQL reservation envelope. A narrow binding read Port independently validates saved metadata against the root request.

The model module's `BudgetEvidenceTx` reads its original recovery envelope under the owning transaction, binds the full reservation/price/fingerprint, validates usage ownership and accepted/applied unbilled decisions, and returns billing metadata plus a stable evidence digest. It returns no model response or attempt secret and sends no provider request. Real root/coordination/IAM composition and the pre-send failure proof chain are still pending; none of these source additions have been deployed or scenario-accepted.


Development startup wiring now supports `PLATFORM_RUN_TREE_BUDGET_ENABLED=true` (strict true/false, default disabled). Enabled composition requires persistent execution/IAM/coordination/audit/model receipts and uses real signed estimates, verified root lineage/policy, current admission permissions and terminal billing evidence. Roots without explicit approved `run_budget` fail admission. Original price reservation IDs/envelopes are stored atomically with root requests; outcome checks reread original model evidence. Known pre-send capacity failures persist no-send proof before resolving both holds; failed accounting retains recovery rather than overwriting it as preparation failure. Production settings, policy rollout, pre-existing unknown-ledger compatibility and full scenario acceptance remain pending; the running service has not enabled this source.


### Coordinated child admission (development)

`POST /internal/agent/admit` accepts only `operation_key`, `ordinal` and `expected_revision: 2`, using the same verified parent lease, published delegation policy and dual-identity `agent.delegate` authority. It reads the saved target and frozen preparation; callers cannot replace input, endpoint, version, policy or machine identity. A stable child Run ID and idempotency key derive from the child key.

The coordinator locks its reservation and delegates to a trusted `ChildExecutionAdmitter` in the same transaction. That implementation must verify caller/parent-machine/target-machine authority, immutable target policy, parent fence and shared-root budget before `Execution.CreateCoordinatedRunTx`. The coordinator then validates the exact returned child Scope and fingerprint, CAS-transitions to accepted, records Audit/Outbox and repeats current authority before commit. Replay of accepted/in-flight/terminal/uncertain records never calls creation again. Only the normal fenced dispatcher may send the child RPC.

The actual execution/budget composition adapter is still pending; without it admission returns unavailable. This source endpoint has not created a real child, migrated, deployed or passed scenario acceptance. Cancellation, recovery, aggregation and three-language SDK admission remain pending.


The development composition now supplies `childExecutionAdmitter` when shared root budgeting is explicitly enabled. It rechecks the parent fence/policy and fixed Catalog target, verifies caller/parent-machine and target-machine run permissions, creates the child's IAM epoch within the owning transaction, materializes the approved child policy, checks locked root headroom, and calls the Execution creation Port. The normal dispatcher alone fences/signs/dispatches the accepted Run. Child admission does not duplicate a whole-child provider hold: every actual model/embedding send must separately reserve its exact root-plus-price-window allowance. Disabling shared budgeting leaves admission unavailable. This source has not created or scenario-tested a real child or been deployed; lifecycle, ongoing ancestor boundary enforcement, cancellation/recovery/aggregation and SDK/business integration remain pending.

### Immediate-child results and SDK binding (development)

POST /internal/agent/child accepts operation_key and ordinal only. It reads the recorded immediate child under the verified parent lease, current delegation/target authority and exact coordination lineage. Targets pin both input_schema and output_schema. Execution returns only same-owner/workspace/session output whose outcome revision and task_completed event match the completed Run. Output above 16 KiB is omitted explicitly; missing completion proof is uncertain. Every returned result is untrusted_data. Reads never dispatch, acknowledge, recover or cancel.

Go AdmitAgentChild/ReadAgentChild, Python admit_agent_child/read_agent_child and Java admitAgentChild/readAgentChild bind responses to the preparation child_key/input_fingerprint, parent Run, operation/ordinal and stable derived child Run ID. Reads additionally verify fixed output_schema, revision, status, size/omission and trust metadata. Null is distinct from an empty object. Unknown admission/read responses do not trigger automatic retries. The output digest describes the server's original bytes; SDKs validate its format and envelope without claiming identical reserialized JSON bytes.

Admission locks ancestor Runs root-first before the current actor fence to remove an identified parent-read/child-admission lock-order inversion. These source changes have only compiled; deployment, lifecycle/cancellation/recovery/aggregation, ongoing ancestry and final target disclosure enforcement, business integration and overall scenario acceptance remain pending.

### Final result disclosure and stop intent (development)

The child-read gateway rechecks current parent and fixed target authority, recorded child lineage, owner/session/workspace, outcome revision/status/digest and size/omission in a separate transaction immediately before returning. Changed authority or result denies stale disclosure. This is neither receipt repair nor a second dispatch; complete ongoing ancestor enforcement remains pending.

POST /internal/agent/cancel accepts operation_key, ordinal and expected_execution_revision (positive signed BIGINT). It locates the existing reservation rather than accepting a caller-supplied Run. The composition verifies parent/fixed-target authority and recorded lineage. Execution locks its own child, validates immutable stable scope/command/depth, and CAS-persists cancelling plus cancel_requested; coordinator Audit/Outbox commits in the same transaction. Already stopping or terminal executions replay actual status, never create a Run or overwrite outcome. Revision conflicts return 409.

Remote stop confirmation remains owned by the existing execution reconciler. Intent never releases a lease, acknowledges a projection or releases uncertain budget holds. Current parent delegation/target authority can stop an existing child without restoring a revoked child-machine execution grant. Go CancelAgentChild, Python cancel_agent_child and Java cancelAgentChild validate fixed child bindings and explicitly preserve cancelling/recovering as pending. Full parent cancellation propagation, recovery/aggregation and business integration remain pending. Source compilation is not deployed scenario acceptance.

### Orphan-child stop reconciliation (development)

ChildLifecycleCandidates enumerates coordination-owned admitted bindings through bounded child-ID seek pages. A composition reconciler independently verifies actual execution ownership and the recorded edge, locks ancestors root-first and the child directly FOR UPDATE, then asks Execution to CAS-persist a stop intent if the real immediate parent is no longer running or its lease has expired. Stop event and metadata-only system Audit/Outbox commit atomically. The cursor gives failed records another sweep without starving later children.

The Dispatcher hook runs before cancellation confirmation and accepted-run discovery, only when shared Run budgeting is enabled. No RPC, lease release, output overwrite, credential creation or uncertain cost release occurs in the control transaction. Existing signed-stop confirmation remains necessary. Complete immediate dispatch/capability ancestry enforcement, live IAM/dependency revocation, terminal synchronization/scan optimization, recovery/aggregation and business integration are still pending; source compilation is not overall acceptance.

### Continuous business ancestry guard (development)

One composition guard now serves dispatch admission, heartbeat, live capability authorization and renewal. Earlier provider/authority interface copies retain a shared startup-configured closure. Business depth 1–4 requires exact stored scope/command/policy, real coordination metadata and original execution request fingerprint, active parent Run/session fences, current v2 caller/machine run and delegation rights, allowed tasks/agents/depth and an explicit root budget. Existing depth-zero evaluation provenance retains its separate authority and does not grant business delegation.

ChildRoutingFactsTx returns the original fixed target plus verified plan policy/task/request metadata. Current Catalog must match that saved deployment/install/version/manifest and schemas; a replacement latest-ready deployment cannot silently become the original evidence. Budget admission consumes the same fixed evidence. Known historic charges remain attributable after revocation.

The actor is re-read through a non-locking, non-secret control projection because nested live-authority callbacks can occur inside a transaction already holding its UPDATE fence. The existing actor execution boundary still verifies its fence; ancestors are locked root-first and checked against actual session leases without exposing tokens. Full actual concurrent/nested-transaction and revocation/deployment/expiry scenarios are pending overall acceptance. Terminal synchronization, recovery/aggregation, old unknown-budget compatibility and SDK/business integration remain unfinished; this source has only compiled and is not deployed.

### Verified lifecycle synchronization (development)

Execution.ChildLifecycleTx supplies metadata-only original scope/request fingerprint and Run status/revision. Terminal state is verified only against the matching execution-owned task_completed/task_failed/task_cancelled Outcome revision. Missing proof is not fabricated; output/error bodies and lease tokens are excluded.

Coordinator SyncChildLifecycleTx verifies original plan/reservation and the trusted observer result, CAS-updates real running or verified completed/failed/cancelled, and records system Audit/Outbox in the same transaction. Unknown coordination never automatically becomes running; terminal state never moves backward. Terminal records leave the bounded active seek scan. Billing holds and original known costs remain untouched.

Explicit forward migration 2026100406 adds the failed terminal state, admitted child binding constraint and active-scan index. Original 2026100405 checksum remains an accepted predecessor, and startup performs no DDL. SDK admission replay supports failed and never creates another child. Historic budget accounting also locks ancestors root-first before its actor. These changes compiled but have not migrated, deployed or passed overall scenarios; recovery/aggregation and SDK/business integration remain pending.

### Whole-plan result gathering (development)

POST /internal/agent/gather accepts only operation_key and reads all 1–16 already-admitted slots of the original plan in one parent-fenced transaction. It reuses bounded single-child reads and verifies current authority, fixed output schemas, real execution request fingerprints and terminal Outcome proof. Missing/uncertain admission must be reconciled through individual reads; gathering never creates a child.

Group counts cover every child. Terminal is true only when all children ended; outputs_complete additionally requires every child completed with available non-omitted output. In-flight siblings keep a failed group nonterminal; uncertain children produce uncertain. Child output is limited to 16 KiB and the entire group to 512 KiB, with explicit omission and untrusted_data tagging. No result becomes a system instruction automatically.

Final disclosure re-reads the whole group and target authority. A changed snapshot returns 409 AGENT_GROUP_RESULT_CHANGED for read-only re-query; revoked authority denies output. Go GatherAgentChildren, Python gather_agent_children and Java gatherAgentChildren bind ordinal-ordered saved keys/schemas, validate all children and recompute group summaries. They never poll, re-dispatch or repair outcomes automatically. Durable orchestration/recovery and starvation-free parent/descendant worker capacity remain pending, alongside business integration and overall acceptance. These source changes only compiled and are not deployed.

### Reserved depth workers and pending discovery (development)

When shared run-tree budgeting is explicitly enabled, dispatch has separate bounded root and depth 1–4 worker pools. PLATFORM_CHILD_RUN_WORKERS is 1–32 per depth; root plus four child pools must not exceed 128. Queue hints grant no authority: stored command depth is rechecked, and normal policy, lease and session FIFO checks remain required. Pending discovery uses bounded run-ID keyset pages with wraparound to avoid repeatedly scanning only busy roots. Explicit schema 2026100407 adds its index; runtime startup performs no DDL. Compose defaults budgeting to false. These source changes compile only; cross-tree session contention, expiry scans and overall concurrency remain unaccepted.

### Durable fixed-plan SDK orchestration (development)

Go RunAgentGroup, Python run_agent_group and Java AgentGroupRunner persist a bounded run-scoped coordination checkpoint under schema://agentplug/agent-group/v1. It binds the input digest, original route schemas and child preparation keys/fingerprints, ordinal and phase. Up to 16 children; no waiting poll loop, no saved outputs and no completed checkpoint bypass of current disclosure authority.

POST /internal/agent/admission-state accepts operation_key/ordinal only and discloses metadata from the original prepared/admitted slot. Preparing requires revision 2 with no child Run; admitted state requires the real original execution and its request fingerprint. The parent, target and original plan are reauthorized, with a final independent snapshot check (changed: 409; denied: 403). Recovery queries first: verified preparing can complete the same original CAS admission, while an existing child advances state without another admit or dispatch. Unknown reads stop. This is not a dispatch permit, outcome repair or budget release. Cross-language fingerprints, actual crash/concurrency and business lifecycle integration remain unaccepted. Source compiles only; not migrated or deployed.
