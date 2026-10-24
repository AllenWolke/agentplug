"""Run real public knowledge SQL against an owned, disposable pgvector database.

Uses the existing Go cache. Never mounts project databases or uses their networks.
Runtime credentials are ephemeral and do not appear in command arguments or logs.
"""
import json
import sys
import argparse
import os
import re
import hashlib
from pathlib import Path
import secrets
import shutil
import stat
import subprocess
import threading
import time
import uuid
from types import SimpleNamespace

# Knowledge includes both the repository and its signed platform composition.
# Use domain prefixes, not every TestPostgres function in cmd/platform: some
# require the separate compensation fixture and are gated by another CI job.
KNOWLEDGE_GO_TEST_PATTERN = (
    r"^(TestBM25.*|TestDenied.*|TestChinese.*|TestHybrid.*|"
    r"TestPostgres(Source.*|Index.*|Corpus.*|FinalAuthority.*|Generation.*|Governed.*|"
    r"Metadata.*|RuntimeCannotRunDDL|Retrieval.*|Knowledge.*|SignedModelBudget.*|ToolApprovalHTTP.*)|"
    r"TestVectorLiteral.*|TestCurrentKnowledgeSource.*|TestStageCache.*|TestCachedQueryModels.*|"
    r"TestIndexEmbeddings.*|TestIndexEmbeddingWorker.*)$"
)

parser = argparse.ArgumentParser()
parser.add_argument('--suite', choices=['index', 'source', 'knowledge', 'foundation', 'identity', 'identity-full', 'scale', 'usage', 'tree-budget', 'execution', 'execution-recovery', 'models', 'policy', 'conversation', 'erasure-audit', 'platform-ports', 'process', 'maintenance', 'kafka', 'evaluation', 'capability', 'capability-recovery', 'capability-billing', 'schema', 'administration', 'checkpoint', 'platform-all-go'], default='knowledge')
parser.add_argument('--sdk-full', action='store_true')
parser.add_argument('--administrator-scopes', action='store_true', help='identity suite only; current management scopes, self-grant denial and workspace/session boundaries')
parser.add_argument('--company-administration', action='store_true', help='identity suite only; protected company administrator appointment, explicit global-role replacement and company-only department authority')
parser.add_argument('--department-agent-access', action='store_true', help='identity suite only; persisted department Agent ceilings, fresh proof, atomic rollback, source generations and runtime revocation')
parser.add_argument('--permission-batches', action='store_true', help='identity suite only; persisted multi-user authorization and request decision batches, per-item transactions and interruption recovery')
parser.add_argument('--batch-id', help='safe independent evidence suffix; refuses to overwrite existing batch')
parser.add_argument('--live-models', action='store_true', help='process suite only; use operator-provided local model mounts')
parser.add_argument('--rag-evaluation', action='store_true', help='evaluation suite only; include independent RAG grounding evidence')
parser.add_argument('--real-rag-metrics', action='store_true', help='evaluation suite only; actual repository metric-service and frozen gold reference SQL evidence')
parser.add_argument('--local-admin-bootstrap', action='store_true', help='administration suite only; real local-password first administrator without fabricated OIDC')
parser.add_argument('--containerized-go', action='store_true', help='scale/administration only; run Linux Go next to the owned PostgreSQL, using the existing offline module cache')
parser.add_argument('--coverage', action='store_true', help='identity-full only; require critical-package coverage with the same owned PostgreSQL credentials')
parser.add_argument('--retrieval-cache', action='store_true', help='knowledge suite only; focused SQL retrieval-cache and live IAM backend checks')
parser.add_argument('--answer-cache', action='store_true', help='knowledge suite only; focused governed RAG answer-cache checks')
parser.add_argument('--answer-cache-process', action='store_true', help='process suite only; actual signed HTTP answer-cache and SQL billing with controlled upstream')
parser.add_argument('--java-example-process', action='store_true', help='process suite only; run formal Java Agent image against the actual platform and owned PG')
parser.add_argument('--example-tool-loop', action='store_true', help='controlled process suite only; supplier requests one actual runtime.inspect call before the final answer')
parser.add_argument('--python-example-process', action='store_true', help='process suite only; run formal Python Agent image against the actual platform and owned PG')
parser.add_argument('--function-calling', action='store_true', help='capability suite only; native function usage, replay and unknown tool receipt SQL checks')
parser.add_argument('--business-state', action='store_true', help='capability suite only; business checkpoints, execution lease fences and explicit migration')
parser.add_argument('--checkpoint-agent-process', action='store_true', help='process suite only; actual platform crash and owned Go SDK Agent stop/restart recovery')
parser.add_argument('--evaluation-restart', action='store_true', help='process suite only; execute the original restart seed while the real platform is down, then verify actual lifecycle recovery')
parser.add_argument('--runtime-observation', action='store_true', help='capability suite only; signed Observation bounds/replay/revocation and actual SQL precision/isolation')
parser.add_argument('--tool-approval', action='store_true', help='capability suite only; durable tool approval revoke/audit-Outbox rollback and explicit migration')
parser.add_argument('--skill-transactions', action='store_true', help='capability suite only; actual PostgreSQL skill caller-transaction and lock-order regression fixture')
parser.add_argument('--go-test-pattern', help='platform-all-go only; fixed affected-regression selection, never an arbitrary Go expression')
GO_WORKER_DIAGNOSTIC_PATTERN = r'^TestSQLRealPlatformProcessStartsWithDMLAndRejectsBadSchema$/^knowledge-index-worker$'
GO_WORKER_DIAGNOSTIC_REQUIRED_TESTS = (
    'TestSQLRealPlatformProcessStartsWithDMLAndRejectsBadSchema',
    'TestSQLRealPlatformProcessStartsWithDMLAndRejectsBadSchema/knowledge-index-worker',
)
args = parser.parse_args()
if args.python_example_process and args.java_example_process:
    raise SystemExit('one formal example per isolated fixture')
external_example_process = args.python_example_process or args.java_example_process
example_language = 'java' if args.java_example_process else 'python'
example_title = example_language.title()
if args.example_tool_loop and (args.suite != 'process' or args.live_models or args.evaluation_restart or args.checkpoint_agent_process or args.answer_cache_process):
    raise SystemExit('tool loop requires its own controlled example process suite')
if args.evaluation_restart and (args.suite != 'process' or args.checkpoint_agent_process or args.live_models or external_example_process or args.answer_cache_process):
    raise SystemExit('evaluation restart requires its own controlled process suite')
ADMINISTRATOR_SCOPE_REQUIRED_TESTS = {
	'TestSQLManagementWorkspaceBrowserSessionWithoutBusinessMembership',
	'TestSQLDelegatedManagementWorkspaceWithNoDepartmentBusinessMembership',
    'TestSQLAdministratorWorkspacesFollowLiveAuthority',
    'TestSQLAdministratorsCannotAddOwnBusinessAuthority',
    'TestSQLDepartmentAdministratorMembershipAndAgentBoundary',
    'TestSQLWorkspaceSwitchAndRefresh',
    'TestSQLPermissionRequestsSubsetAndAtomicAudit',
    'TestSQLAdministratorAuthenticationAndContinuity',
}
if args.administrator_scopes and args.suite != 'identity':
    raise SystemExit('administrator scopes require the identity suite')
if args.company_administration and (args.suite != 'identity' or args.administrator_scopes):
    raise SystemExit('company administration requires its own identity suite')
DEPARTMENT_AGENT_REQUIRED_TESTS = {
    'TestSQLInstallationTargetPagesBeyondOneHundred',
    'TestSQLDepartmentAgentPolicyFreshProofAtomicRetryAndRevocation',
    'TestSQLDepartmentAgentManagedDelegationSourceAndRestoration',
    'TestSQLDepartmentAgentScopeAndConcurrentChange',
    'TestSQLDepartmentAgentMembershipLegacyAndCorruptPolicy',
    'TestSQLDepartmentAdministratorMembershipAndAgentBoundary',
    'TestSQLCompanyAdministratorAppointmentAndBoundaries',
    'TestDepartmentAgentActionRestorePreservesIndependentSourcesAndDenials',
    'TestDepartmentAgentGrantInheritsApprovedWindowAndRejectsExpansion',
    'TestDepartmentAgentPolicyPeriodChangeDoesNotReviveSubordinateGrant',
    'TestDepartmentAgentObsoleteSourceCannotRemoveDataDenial',
    'TestManagedLegacyCancellationRecoveryRespectsOriginalAuthority',
}
if args.department_agent_access and (args.suite != 'identity' or args.administrator_scopes or args.company_administration):
    raise SystemExit('department Agent access requires its own identity suite')
PERMISSION_BATCH_REQUIRED_TESTS = {
    'TestAgentUsePackageCanonicalDigestAndRestrictedActions',
    'TestAgentUseScopedRoleKeepsExistingSensitiveGrantDormant',
    'TestSQLAgentUsePackageBatchActualDependenciesAndCeiling',
    'TestSQLAgentUsePackageCatalogUpgradePreservesPublishedV1AndFacts',
    'TestSQLAgentUsePackagePinsReviewAndRollsBackUnknownAuditResult',
    'TestSQLAgentUsePackageRejectsUnauthorizedMixedAndIncompleteCeiling',
    'TestSQLPermissionBatchDepartmentRolesAndAutomaticRevocationImpact',
    'TestSQLPermissionBatchPartialConflictRecoveryAndConcurrentProgress',
    'TestSQLPermissionBatchAuditFaultCancellationAndLostAuthority',
    'TestSQLPermissionBatchApprovalsAreAtomicAndRespectWithdrawal',
    'TestSQLPermissionBatchPendingCeilingExpiryAndCorruption',
    'TestSQLPermissionRequestsSubsetAndAtomicAudit',
    'TestSQLPermissionRequestWithdrawalAndDecisionRace',
    'TestSQLPermissionRequestsBoundaryAndRejection',
    'TestSQLPermissionRequestTwoAdministratorsOnlyOneSubsetCommits',
    'TestPermissionBatchNormalizationOwnsCommandsAndPinsOriginalItems',
    'TestPermissionBatchScopeIncludesAutomaticRevocations',
}
if args.permission_batches and (args.suite != 'identity' or args.administrator_scopes or args.company_administration or args.department_agent_access):
    raise SystemExit('permission batches require their own identity suite')
GO_TERMINAL_OUTCOME_FENCE_TESTS = (
    'TestSQLTerminalOutcomeFenceIsAtomicAndRunLocked',
    'TestSQLTerminalOutcomeFenceIsAtomicAndRunLocked/succeeded',
    'TestSQLTerminalOutcomeFenceIsAtomicAndRunLocked/failed',
)
GO_MIGRATION_UPGRADE_REQUIRED_TESTS = (
    'TestPostgresDelegationAuthorityMarkerUpgradesFromPermissionCatalogV2',
)
GO_GOVERNED_BILLING_REQUIRED_TESTS = (
    'TestGovernedModelBillingPostgresIntegration',
    'TestGovernedEmbeddingBillingPostgresIntegration',
    'TestGovernedKnowledgeEmbeddingBillingPostgresIntegration',
    'TestGovernedFunctionBillingPostgresIntegration',
    'TestInvalidFunctionBillingPostgresIntegration',
)
GO_PERMISSION_AUTHENTICATION_REQUIRED_TESTS = (
    'TestAutomaticRecoveryHoldManifestBindsReviewedBytes',
    'TestSQLAutomaticToolRecoveryHoldsPreserveUnknownAndAdmitNewScope',
    'TestKafkaHistoricalBoundarySkipsBeforeDecodeAndSurvivesLostGroupOffsets',
    'TestKafkaHistoricalBoundaryCommitFailureDoesNotFetchOrQuarantineNext',
    'TestKafkaHistoricalBoundaryRejectsInvalidAndForeignOffsets',
    'TestEventReadResolvesDurableOriginWithoutReplacingReadAuthority',
    'TestEventReadResolvesDurableOriginWithoutReplacingReadAuthority/independent_read_epoch_and_trace',
    'TestEventReadResolvesDurableOriginWithoutReplacingReadAuthority/revoked_run',
    'TestEventReadResolvesDurableOriginWithoutReplacingReadAuthority/revoked_history',
    'TestEventReadResolvesDurableOriginWithoutReplacingReadAuthority/stale_run',
    'TestEventReadResolvesDurableOriginWithoutReplacingReadAuthority/invalid_proof',
    'TestEventReadResolvesDurableOriginWithoutReplacingReadAuthority/foreign_reader',
    'TestEventReadResolvesDurableOriginWithoutReplacingReadAuthority/foreign_parent',
    'TestEventReadResolvesDurableOriginWithoutReplacingReadAuthority/foreign_policy',
    'TestSynchronousReviewResumeQueuedBeforeOwnerReleaseRechecksRevocation',
    'TestPublishedPermissionResourcesRequireCurrentInstallationAndPolicy/complete_use_package_pins_material_without_disclosing_it',
    'TestBrowserCancellationRevisionRaceIsBoundedAndRechecksAuthority',
    'TestBrowserCancellationRevisionRaceIsBoundedAndRechecksAuthority/claim_race',
    'TestBrowserCancellationRevisionRaceIsBoundedAndRechecksAuthority/revoked_between_reads',
    'TestBrowserCancellationRevisionRaceIsBoundedAndRechecksAuthority/bounded_conflict',
    'TestBrowserCancellationRevisionRaceIsBoundedAndRechecksAuthority/storage_failure_is_not_retried',
    'TestSQLAuthorizationChangeInvalidatesStepUpAtomically',
    'TestSQLAuthorizationChangeInvalidatesStepUpAtomically/local',
    'TestSQLAuthorizationChangeInvalidatesStepUpAtomically/oidc',
    'TestSQLOIDCStepUpAppointmentAndOneUse',
    'TestSQLOIDCStepUpAuditRollbackAndExpirationCleanup',
    'TestSQLOIDCStepUpRevocationAndQualification',
    'TestSQLOIDCToolStepUpExactSessionAndOperation',
    'TestSQLOIDCToolStepUpExactSessionAndOperation/tool.approval.approve',
    'TestSQLOIDCToolStepUpExactSessionAndOperation/tool.approval.revoke',
    'TestSQLOIDCToolStepUpMembershipRevocation',
    'TestPostgresToolApprovalHTTPOIDCOnly',
    'TestPostgresToolApprovalHTTPOIDCOnly/same-user-other-login-cannot-consume-proof',
    'TestPostgresToolApprovalHTTPOIDCOnly/proof-does-not-grant-tool-permission',
    'TestPostgresToolApprovalHTTPOIDCOnly/changed-claims-cannot-use-proof',
    'TestPostgresToolApprovalHTTPOIDCOnly/audit-failure-rolls-back-approve-and-proof-consumption',
    'TestPostgresToolApprovalHTTPOIDCOnly/audit-failure-rolls-back-revoke-and-proof-consumption',
)
GO_AFFECTED_TEST_PATTERN = r'^(TestFirstAdministratorLocalPasswordPostgres|TestFirstAdministratorPostgres|TestInvalidFunctionBillingPostgresIntegration|TestPersistentSessionLeaseSQLRestartAndHeartbeatRollback|TestPostgresMigrationCommandCompleteBundleAndReplay|TestSQLAtomicCreationAndOutcomeFaultRecovery|TestSQLProjectionOutageRecoversWithoutAgentExecution|TestSQLRealPlatformProcessStartsWithDMLAndRejectsBadSchema|TestSQLTerminalOutcomeFenceIsAtomicAndRunLocked|TestPostgresDelegationAuthorityMarkerUpgradesFromPermissionCatalogV2)$/^(read-only_inventory_CLI|development_runtime_role|knowledge-index-worker|succeeded|failed)$'
GO_AFFECTED_REQUIRED_TESTS = (
    'TestFirstAdministratorLocalPasswordPostgres',
    'TestFirstAdministratorPostgres',
    'TestInvalidFunctionBillingPostgresIntegration',
    'TestPersistentSessionLeaseSQLRestartAndHeartbeatRollback',
    'TestPostgresMigrationCommandCompleteBundleAndReplay',
    'TestSQLAtomicCreationAndOutcomeFaultRecovery',
    'TestSQLProjectionOutageRecoversWithoutAgentExecution',
    'TestSQLRealPlatformProcessStartsWithDMLAndRejectsBadSchema',
    'TestFirstAdministratorPostgres/read-only_inventory_CLI',
    'TestPostgresMigrationCommandCompleteBundleAndReplay/development_runtime_role',
    'TestSQLRealPlatformProcessStartsWithDMLAndRejectsBadSchema/knowledge-index-worker',
) + GO_TERMINAL_OUTCOME_FENCE_TESTS + GO_MIGRATION_UPGRADE_REQUIRED_TESTS
if args.batch_id and not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,63}', args.batch_id):
    raise SystemExit('invalid independent verification batch ID')
if args.suite == 'platform-all-go' and not args.batch_id:
    raise SystemExit('platform-all-go requires a unique --batch-id')
if args.go_test_pattern and (args.suite != 'platform-all-go' or args.go_test_pattern not in {GO_AFFECTED_TEST_PATTERN, GO_WORKER_DIAGNOSTIC_PATTERN}):
    raise SystemExit('platform-all-go accepts only the fixed affected-regression test pattern')
if args.tool_approval and (args.suite != 'capability' or args.function_calling or args.business_state or args.runtime_observation):
    raise SystemExit('tool approval requires its own focused capability suite')
if args.skill_transactions and (args.suite != 'capability' or args.function_calling or args.business_state or args.runtime_observation or args.tool_approval):
    raise SystemExit('skill transactions require their own focused capability suite')
if args.runtime_observation and (args.suite != 'capability' or args.function_calling or args.business_state):
    raise SystemExit('runtime observation requires its own focused capability suite')
if args.checkpoint_agent_process and (args.suite != 'process' or args.live_models or external_example_process or args.answer_cache_process):
    raise SystemExit('checkpoint recovery requires a separate controlled process suite')
if args.function_calling and args.suite != 'capability':
    raise SystemExit('function calling requires the focused capability suite')
if args.business_state and (args.suite != 'capability' or args.function_calling):
    raise SystemExit('business state requires its own focused capability suite')
if args.local_admin_bootstrap and args.suite != 'administration':
    raise SystemExit('local administrator bootstrap requires administration suite')
if args.containerized_go and args.suite not in {'scale', 'administration'}:
    raise SystemExit('containerized Go is supported only for scale/administration')
if args.coverage and args.suite != 'identity-full':
    raise SystemExit('SQL coverage requires the identity-full fixture')
if args.real_rag_metrics and (args.suite != 'evaluation' or args.rag_evaluation):
    raise SystemExit('real RAG metrics require the focused evaluation suite')
if external_example_process and (args.suite != 'process' or args.answer_cache_process):
    raise SystemExit('formal example process requires the controlled process suite without other process variants')
if args.live_models and args.suite != 'process':
    raise SystemExit('live models require the actual process suite')
if args.rag_evaluation and args.suite != 'evaluation':
    raise SystemExit('RAG evaluation requires the evaluation suite')
if args.retrieval_cache and args.suite != 'knowledge':
    raise SystemExit('retrieval cache requires the knowledge suite')
if args.answer_cache and args.suite != 'knowledge':
    raise SystemExit('answer cache requires the knowledge suite')
if args.answer_cache and args.retrieval_cache:
    raise SystemExit('select one focused knowledge cache suite')
if args.answer_cache_process and (args.suite != 'process' or args.live_models):
    raise SystemExit('answer cache process requires process suite with controlled upstream')
focused_knowledge_cache = args.retrieval_cache or args.answer_cache
ROOT = Path(__file__).resolve().parents[1]
OWNER = "knowledge-pg-" + uuid.uuid4().hex
NAME = "agentplug-test-" + OWNER
GO_NAME = NAME + "-go"
EXAMPLE_NAME = NAME + "-" + example_language
KAFKA_NAME = NAME + "-kafka"
TEMP = ROOT / ".tmp" / OWNER
EVIDENCE = ROOT / "docs/新增需求/github作品改造"
SCALE_EVIDENCE = EVIDENCE / ("T3-04A-PostgreSQL权限规模测量" + ("-" + (args.batch_id or OWNER)) + ".json")
IMAGE = os.environ.get("KNOWLEDGE_TEST_POSTGRES_IMAGE", "pgvector/pgvector:pg16")
if IMAGE not in {"pgvector/pgvector:pg16", "ankane/pgvector:latest"}:
    raise SystemExit("unsupported fixture image")
receipt = {"complete": False, "scope": "real PostgreSQL " + args.suite + " stage only, not complete platform/RAG",
           "owner": OWNER, "image": IMAGE, "temporary_images_built": [], "cleanup_errors": []}
docker_access_confirmed = False
basenames = {'index': 'T3-04-PostgreSQL完整影子与增量索引实际验证', 'source': 'T3-04-PostgreSQL知识源版本与Outbox实际验证', 'scale': 'T3-04A-PostgreSQL权限规模实际验证', 'kafka': 'T3-04A-PostgreSQL与Kafka授权事件实际验证', 'maintenance': 'T3-04A-PostgreSQL维护CLI只读映射实际验证', 'process': 'T3-04A-PostgreSQL真实平台进程实际验证', 'identity-full': 'T3-04A-PostgreSQL身份全量SQL实际验证', 'platform-ports': 'T3-04A-PostgreSQL平台发布与通知实际验证', 'erasure-audit': 'T3-04A-PostgreSQL擦除与审计实际验证', 'execution-recovery': 'T3-04A-PostgreSQL执行恢复与会话租约实际验证', 'capability-billing': 'T3-04A-PostgreSQL计费故障补偿实际验证', 'capability-recovery': 'T3-04A-PostgreSQL模型与工具恢复实际验证', 'checkpoint': 'T3-04A-PostgreSQL-SDK检查点实际验证', 'administration': 'T3-04A-PostgreSQL首管理员实际验证', 'knowledge': 'T3-04-PostgreSQL公共检索实际验证', 'foundation': 'T3-04A-PostgreSQL首批仓储实际验证', 'identity': 'T3-04A-PostgreSQL身份与会话实际验证', 'usage': 'T3-04A-PostgreSQL预算与用量实际验证', 'execution': 'T3-04A-PostgreSQL运行事务实际验证', 'models': 'T3-04A-PostgreSQL模型治理与容量实际验证', 'policy': 'T3-04A-PostgreSQL策略与知识绑定实际验证', 'conversation': 'T3-04A-PostgreSQL会话与历史实际验证', 'evaluation': 'T3-04A-PostgreSQL评测执行实际验证', 'capability': 'T3-04A-PostgreSQL公共能力账本实际验证', 'schema': 'T3-04A-PostgreSQL事务版本迁移实际验证', 'platform-all-go': 'T3-11-平台全量Go隔离PostgreSQL测试实际验证'}
if args.suite == 'tree-budget':
    basenames['tree-budget'] = 'T3-17-RunTree预算真实SQL集中验证'
    receipt['scope'] = 'actual isolated PostgreSQL root-child aggregate reservation, idempotent receipts, uncertain hold, overestimate charge and audit rollback; authority/provider proof are explicit fixtures, not real IAM/Execution or formal Agent acceptance'
if args.evaluation_restart:
    basenames['process'] = 'T3-21-原始评测种子与真实平台进程重启验证'
    receipt['scope'] = 'original TestSeedPlatformProcessRestartRun executes with the real owned Linux platform down; actual restarted platform lifecycle worker reclaims its expired lease and safely terminates the intentionally incomplete suite as SNAPSHOT_INVALID; not successful business evaluation'
if args.function_calling:
    basenames['capability'] = 'T3-13-PostgreSQL原生函数计费与工具回执实际验证'
    receipt['scope'] = 'actual PostgreSQL native function usage settlement/replay, read-only model receipt with runtime DML account and tool unknown-result fencing; not complete formal IAM/example delivery'
if args.business_state:
    basenames['capability'] = 'T3-14-PostgreSQL公共检查点与执行栅栏实际验证'
    receipt['scope'] = 'actual PostgreSQL checkpoint CAS/history/audit-Outbox rollback, hashed execution lease fencing, payload retention and SQL principal disable rejection; complete dual-identity resource approval and three-example process recovery are not accepted'
if args.runtime_observation:
    basenames['capability'] = 'T3-18-Observation公共工具与实际SQL阶段验证'
    receipt['scope'] = 'tool Observation, frozen runtime registration/risk/timeout and explicit write approval with signed fixtures, read-only receipt query without execution, actual DML-only PostgreSQL reopen/precision/isolation and unchanged ledger timestamp; not complete Runtime, formal IAM approval, sandbox or three-example acceptance'
if args.tool_approval:
    basenames['capability'] = 'T3-18-批准记录撤销与事务SQL阶段验证'
    receipt['scope'] = 'actual DML-only PostgreSQL approval/reopen/revoke, audit-Outbox rollback and migration; real SQL browser session/Run/policy/caller-workload IAM/local-password and OIDC-only action-bound authentication, cross-login proof rejection, membership/resource revocation with seeded identities; verified OIDC assertions are explicit fixtures, not an external IdP; formal cookie UI and business examples not accepted'
if args.skill_transactions:
    basenames['capability'] = 'T3-13-Skill调用者事务与锁顺序真实SQL验证'
    receipt['scope'] = 'actual PostgreSQL skill caller-owned transaction, model-validation lock order, scope/database fencing and rollback using persisted skill fixtures; permission authorizer is a controlled fixture, not live IAM, and production Harness orchestration is not exercised'
if args.suite == 'platform-all-go':
    receipt['scope'] = 'one full `go test ./...` pass across platform packages against this owner-labelled disposable PostgreSQL instance after the complete schema migration; optional Kafka integration runs only when its image is already present; no project database or business API'
    if args.go_test_pattern:
        receipt['go_test_pattern'] = args.go_test_pattern
        if args.go_test_pattern == GO_WORKER_DIAGNOSTIC_PATTERN:
            receipt['scope'] = 'one scoped knowledge-index-worker PostgreSQL process regression and its required parent; diagnostic selection only, not the prior affected batch or full platform Go suite'
            receipt['required_postgres_test_cases'] = list(GO_WORKER_DIAGNOSTIC_REQUIRED_TESTS)
            receipt['required_postgres_test_case_groups'] = {'knowledge_index_worker_parent_and_subtest': list(GO_WORKER_DIAGNOSTIC_REQUIRED_TESTS)}
        else:
            receipt['scope'] = 'fixed affected PostgreSQL regressions only, across the platform Go package tree; not a full Go-suite rerun or complete platform acceptance'
            receipt['required_postgres_test_cases'] = list(GO_AFFECTED_REQUIRED_TESTS)
            receipt['required_postgres_test_case_groups'] = {
                'prior_affected_roots_and_children_preserved': list(GO_AFFECTED_REQUIRED_TESTS[:-4]),
                'terminal_outcome_fence_run_lease_clear': list(GO_TERMINAL_OUTCOME_FENCE_TESTS),
                'permission_catalog_v2_migration_upgrade_and_replay': list(GO_MIGRATION_UPGRADE_REQUIRED_TESTS),
            }
if args.checkpoint_agent_process:
    basenames['process'] = 'T3-14-SDK实际进程停止与平台恢复验证'
    receipt['scope'] = 'actual Linux platform crash, SQL IAM caller/workload checks, OS-confirmed owned SDK Agent exit, controller-signed stop evidence, platform redispatch and checkpoint recovery; declared integration Agent, not three-example acceptance'
if args.live_models:
    basenames['process'] = 'T3-04-真实双模型平台RAG与Cache实际验证'
    receipt['scope'] = 'actual platform/Go SDK/PostgreSQL pgvector RAG and same-run cache with live suppliers; not complete task 3'
if args.rag_evaluation:
    basenames['evaluation'] = 'T3-04-RAGEvaluation独立评分实际PG验证'
    receipt['scope'] = 'independent frozen RAG metric verdicts, durable evidence and recovery on actual PostgreSQL; controlled metric service, not model quality acceptance'
if args.real_rag_metrics:
    basenames['evaluation'] = 'T3-04-真实MetricService冻结参考与PG评测证据验证'
    receipt['scope'] = 'actual repository metric-service process/lexical entailment and frozen gold references with PostgreSQL DML-only durable artifacts; controlled Agent outputs, not actual Python invocation or external semantic judge'
if args.local_admin_bootstrap:
    basenames['administration'] = 'T3-08-本地密码首管理员实际PG验证'
    receipt['scope'] = 'actual local password first administrator CLI/PG DML-only IAM/password verification/atomic audit and Outbox; no development database rebuild or five-user acceptance yet'
if args.retrieval_cache:
    basenames['knowledge'] = 'T3-04-检索Cache与正文版本边界实际PG验证'
    receipt['scope'] = 'SQL ranking cache with fresh scoped bodies, current IAM and generation fences; no answer cache or external model quality acceptance'
if args.answer_cache:
    basenames['knowledge'] = 'T3-04-公共答案Cache与权限用量实际PG验证'
    receipt['scope'] = 'governed cited-answer cache, current SQL IAM/source/generation checks, signed HTTP response boundary; controlled model callback, not real supplier billing or full RAG Evaluation'
if args.answer_cache_process:
    basenames['process'] = 'T3-04-公共答案Cache真实平台与计费实际验证'
    receipt['scope'] = 'actual Linux platform/Go SDK live execution scope, signed answer HTTP, guarded loopback model gateway, approved SQL invocation/budget/usage ledgers; answer request sent by owned test proxy, not Python or external supplier acceptance'
if external_example_process:
    basenames['process'] = 'T3-06-'+example_title+'真实双模型平台RAG实际验证' if args.live_models else 'T3-06-'+example_title+'正式镜像真实平台与PG完整链路验证'
    receipt['scope'] = 'actual formal '+example_title+' example image and repository SDK/Linux platform/owned PostgreSQL pgvector/common capabilities/invocation-budget-usage ledgers; '+('operator-authorized external model teaching query' if args.live_models else 'controlled supplier')+', not independent semantic quality or final task acceptance'


if args.batch_id:
    basenames[args.suite] += '-' + args.batch_id
    for extension in ('.log', '.json'):
        if (EVIDENCE / (basenames[args.suite] + extension)).exists():
            raise SystemExit('refusing to overwrite existing verification evidence')


def run(args, **kwargs):
    try:
        return subprocess.run(args, check=True, capture_output=True, **kwargs)
    except subprocess.CalledProcessError as error:
        # A failing setup command used to hide its entire diagnostic, making
        # migration/container failures impossible to distinguish in CI. Never
        # include argv or the environment; redact the owned fixture credentials.
        private_values = [globals().get('password', ''), globals().get('runtime_password', '')]
        for key, value in kwargs.get('env', {}).items():
            if re.search(r'(?i)password|secret|token|key|dsn|credential', key):
                private_values.append(value)
        output = (error.stdout or b'') + (error.stderr or b'')
        if isinstance(output, bytes):
            output = output.decode('utf-8', errors='replace')
        diagnostic = safe_event_value(output, private_values)[-4000:]
        receipt['fixture_exit_code'] = error.returncode
        receipt['fixture_program'] = Path(args[0]).name
        receipt['fixture_error_summary'] = diagnostic
        print('Fixture setup failed (exit ' + str(error.returncode) + '):\n' + diagnostic, flush=True)
        raise


def sanitized_test_tail(path, secrets_to_redact):
    """Read a bounded failure diagnostic without exposing fixture credentials."""
    with path.open('rb') as source:
        source.seek(0, os.SEEK_END)
        source.seek(max(0, source.tell() - 16384))
        raw = source.read(16384).decode('utf-8', errors='replace')
    return safe_event_value(raw, secrets_to_redact)[-8000:]


GO_JSON_LIMIT = 64 * 1024 * 1024


def run_bounded_capture(command, output_path, timeout, max_bytes, **kwargs):
    """Capture one child process without unbounded output or console leakage."""
    child = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, **kwargs)
    state = {'bytes': 0, 'overflow': False, 'reader_error': None}

    def drain():
        try:
            with output_path.open('wb') as output:
                while True:
                    chunk = child.stdout.read(65536)
                    if not chunk:
                        break
                    remaining = max_bytes - state['bytes']
                    if len(chunk) > remaining:
                        if remaining > 0:
                            output.write(chunk[:remaining])
                            state['bytes'] += remaining
                        state['overflow'] = True
                        child.terminate()
                        break
                    output.write(chunk)
                    state['bytes'] += len(chunk)
        except Exception as error:
            state['reader_error'] = type(error).__name__
            try:
                child.terminate()
            except OSError:
                pass

    reader = threading.Thread(target=drain, daemon=True)
    reader.start()
    deadline = time.monotonic() + timeout
    timed_out = False
    while reader.is_alive():
        if time.monotonic() >= deadline:
            timed_out = True
            try:
                child.terminate()
            except OSError:
                pass
            break
        reader.join(0.1)
    if reader.is_alive():
        try:
            child.wait(timeout=5)
        except subprocess.TimeoutExpired:
            child.kill()
        reader.join(10)
    if child.poll() is None:
        child.kill()
    return_code = child.wait()
    if reader.is_alive():
        raise RuntimeError('bounded test output reader did not stop')
    if timed_out:
        raise RuntimeError('full platform Go test exceeded its 20 minute deadline')
    if state['overflow']:
        raise RuntimeError('full platform Go test exceeded the 64 MiB JSONL capture bound')
    if state['reader_error']:
        raise RuntimeError('full platform Go test output capture failed')
    return SimpleNamespace(returncode=return_code)


def verify_postgres_runtime_password_auth(container_prefix, go_cache):
    """Probe correct and incorrect DML credentials over TCP without argv secrets."""
    probe_source = r'''package main
import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/stdlib"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	raw := os.Getenv("PUBLIC_TEST_POSTGRES_RUNTIME_DSN")
	config, err := pgx.ParseConfig(raw)
	if err != nil { fmt.Println("invalid_runtime_dsn"); os.Exit(1) }
	good := stdlib.OpenDB(*config)
	defer good.Close()
	if err := good.PingContext(ctx); err != nil { fmt.Println("correct_runtime_password_rejected"); os.Exit(1) }
	wrongConfig, err := pgx.ParseConfig(raw)
	if err != nil { fmt.Println("invalid_runtime_dsn"); os.Exit(1) }
	wrongConfig.Password = "synthetic-wrong-password-never-the-fixture-secret" // secret-scan: allow -- deliberately wrong isolated-test credential, never a usable password
	wrong := stdlib.OpenDB(*wrongConfig)
	defer wrong.Close()
	err = wrong.PingContext(ctx)
	var pgError *pgconn.PgError
	if err == nil || !errors.As(err, &pgError) || pgError.Code != "28P01" {
		fmt.Println("incorrect_runtime_password_not_proven_rejected")
		os.Exit(1)
	}
	fmt.Println("correct_runtime_tcp_auth=PASS")
	fmt.Println("wrong_runtime_tcp_auth=REJECTED")
}
'''
    probe_path = go_cache / 'postgres-auth-probe.go'
    probe_path.write_text(probe_source, encoding='utf-8')
    probe_path.chmod(0o600)
    result = subprocess.run([*container_prefix, 'go', 'run', '/test-cache/postgres-auth-probe.go'],
                            capture_output=True, timeout=60)
    expected = ['correct_runtime_tcp_auth=PASS', 'wrong_runtime_tcp_auth=REJECTED']
    actual = result.stdout.decode('utf-8', errors='replace').splitlines()
    if result.returncode != 0 or actual != expected:
        raise RuntimeError('disposable PostgreSQL runtime TCP password-auth preflight failed')
    return {'correct_runtime_tcp_password_accepted': True, 'incorrect_tcp_password_rejected': True,
            'wrong_password_sqlstate': '28P01'}


def safe_event_value(value, secrets_to_redact):
    if isinstance(value, dict):
        return {key: safe_event_value(item, secrets_to_redact) for key, item in value.items()}
    if isinstance(value, list):
        return [safe_event_value(item, secrets_to_redact) for item in value]
    if not isinstance(value, str):
        return value
    for secret in secrets_to_redact:
        if secret:
            value = value.replace(secret, '[redacted]')
    value = re.sub(r'(?i)postgres(?:ql)?://[^\s"<>]+', '[redacted-postgres-dsn]', value)
    value = re.sub(r'(?i)(password|secret|token|api[_-]?key|dsn)(\s*[:=]\s*)[^\s,;"<>]+', r'\1\2[redacted]', value)
    value = re.sub(r'(?i)bearer\s+[A-Za-z0-9._~+/=-]+', 'Bearer [redacted]', value)
    return value


def parse_platform_go_jsonl(path):
    states = {}
    skip_output = {}
    package_states = {}
    non_json_lines = 0
    with path.open('r', encoding='utf-8', errors='replace') as source:
        for raw in source:
            try:
                event = json.loads(raw)
            except json.JSONDecodeError:
                non_json_lines += 1
                continue
            package, test, action = event.get('Package', ''), event.get('Test', ''), event.get('Action', '')
            if action == 'output' and package and test:
                output = event.get('Output', '')
                for line in output.splitlines():
                    match = re.match(r'^\s*.+?\.go:\d+:\s*(.+?)\s*$', line)
                    if match:
                        skip_output[(package, test)] = match.group(1)
            if action in {'pass', 'fail', 'skip'}:
                if test:
                    states[(package, test)] = action
                elif package:
                    package_states[package] = action

    passed = sorted((package, test) for (package, test), action in states.items() if action == 'pass')
    failed = sorted(test for (package, test), action in states.items() if action == 'fail')
    skipped = []
    for (package, test), action in sorted(states.items()):
        if action != 'skip':
            continue
        reason = skip_output.get((package, test), 'test called Skip without a captured reason')
        reason = safe_event_value(reason, ())
        skipped.append({'package': package, 'test': test, 'reason': ' '.join(reason.split())[:240]})
    return {
        'counts': {
            'passed': len(passed),
            'failed': len(failed),
            'skipped': len(skipped),
            'package_passed': sum(1 for action in package_states.values() if action == 'pass'),
            'package_failed': sum(1 for action in package_states.values() if action == 'fail'),
            'packages_without_test_files': sum(1 for action in package_states.values() if action == 'skip'),
        },
        'failed_tests': failed,
        'skipped_tests': skipped,
        'non_json_lines': non_json_lines,
    }


def required_platform_go_test_states(path, required):
    """Return only named test outcomes so filtered evidence cannot imply full-suite coverage."""
    wanted = set(required)
    states = {}
    with path.open('r', encoding='utf-8', errors='replace') as source:
        for raw in source:
            try:
                event = json.loads(raw)
            except json.JSONDecodeError:
                continue
            name, action = event.get('Test'), event.get('Action')
            if name in wanted and action in {'pass', 'fail', 'skip'}:
                states[name] = action
    return {name: states.get(name, 'missing') for name in required}


def persist_private_go_jsonl(source_path, batch_id, owner, secrets_to_redact):
    private_dir = ROOT / '.local-secrets' / 'public-development'
    private_dir.mkdir(parents=True, exist_ok=True)
    target = private_dir / ('platform-all-go-' + batch_id + '-' + owner + '-events.jsonl')
    temporary = target.with_suffix(target.suffix + '.pending')
    if target.exists() or temporary.exists():
        raise RuntimeError('refusing to overwrite private Go JSONL evidence')
    digest = hashlib.sha256()
    bytes_written = 0
    try:
        with source_path.open('r', encoding='utf-8', errors='replace') as source, temporary.open('x', encoding='utf-8', newline='\n') as output:
            for line in source:
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue
                safe = safe_event_value(event, secrets_to_redact)
                encoded = (json.dumps(safe, ensure_ascii=False, separators=(',', ':')) + '\n').encode('utf-8')
                if bytes_written + len(encoded) > GO_JSON_LIMIT:
                    raise RuntimeError('sanitized Go JSONL evidence exceeded its size bound')
                output.write(encoded.decode('utf-8'))
                digest.update(encoded)
                bytes_written += len(encoded)
        if bytes_written > GO_JSON_LIMIT:
            raise RuntimeError('sanitized Go JSONL evidence exceeded its size bound')
        os.chmod(temporary, stat.S_IREAD | stat.S_IWRITE)
        raw = temporary.read_bytes()
        if any(secret.encode('utf-8') in raw for secret in secrets_to_redact if secret):
            raise RuntimeError('private Go JSONL secret redaction verification failed')
        if re.search(rb'(?i)postgres(?:ql)?://[^\s"<>]+', raw):
            raise RuntimeError('private Go JSONL retains a PostgreSQL DSN after redaction')
        temporary.replace(target)
    except Exception:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass
        raise
    return {'path': str(target.relative_to(ROOT)), 'bytes': bytes_written, 'sha256': digest.hexdigest()}


try:
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    run(['docker','info','--format','{{.ServerVersion}}'])
    docker_access_confirmed = True
    TEMP.mkdir(parents=True, exist_ok=False)
    password = secrets.token_hex(32)
    runtime_password = secrets.token_hex(32)
    environment_file = TEMP / "postgres.env"
    postgres_environment = "POSTGRES_PASSWORD=" + password + "\nPOSTGRES_DB=knowledge_test\n"
    if args.suite == 'platform-all-go':
        # The Go migration and tests reach the owner-labelled container through
        # 127.0.0.1. Require password authentication there so wrong-password
        # account checks cannot silently pass under initdb's trust default.
        postgres_environment += "POSTGRES_INITDB_ARGS=--auth-host=scram-sha-256 --auth-local=trust\n"
    environment_file.write_text(postgres_environment, encoding="utf-8")
    inspection = json.loads(run(["docker", "image", "inspect", IMAGE]).stdout)[0]
    receipt["image_id"] = inspection["Id"]
    receipt["repo_digests"] = inspection.get("RepoDigests", [])
    run(["docker", "run", "--detach", "--name", NAME, "--label", "agentplug.test.owner=" + OWNER,
         "--env-file", str(environment_file), "--publish", "127.0.0.1::5432", "--read-only",
         "--user", "postgres", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
         "--tmpfs", "/var/lib/postgresql/data:rw,noexec,nosuid,size="+("1g" if args.suite in {"scale", "platform-all-go"} else "256m")+",uid=999,gid=999,mode=0700",
         "--tmpfs", "/var/run/postgresql:rw,nosuid,uid=999,gid=999,mode=0700",
         "--tmpfs", "/tmp:rw,noexec,nosuid,size=32m", IMAGE])
    for attempt in range(60):
        # The image starts a socket-only temporary server during initdb. Only
        # TCP readiness proves that the final server (used by Go) is running.
        ready = subprocess.run(["docker", "exec", NAME, "pg_isready", "-h", "127.0.0.1", "-U", "postgres", "-d", "knowledge_test"], capture_output=True)
        if ready.returncode == 0:
            break
        time.sleep(0.5)
    else:
        raise RuntimeError("owned PostgreSQL readiness timed out")
    receipt['database_ready_over_tcp'] = True
    # The local socket admin applies explicit DDL, then creates a DML-only role.
    schema = (ROOT / "platform/internal/knowledge/schema.sql").read_text(encoding="utf-8")
    schema += "\n" + (ROOT / "platform/internal/knowledge/source_schema.sql").read_text(encoding="utf-8")
    schema += "\nCREATE ROLE knowledge_test_runtime LOGIN PASSWORD '" + runtime_password + "';\n"
    schema += "GRANT USAGE ON SCHEMA knowledge TO knowledge_test_runtime;\n"
    schema += "GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA knowledge TO knowledge_test_runtime;\n"
    schema += "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO knowledge_test_runtime;\n"
    schema += "REVOKE CREATE ON SCHEMA public FROM PUBLIC;\n"
    schema += "REVOKE CREATE, TEMPORARY ON DATABASE knowledge_test FROM PUBLIC;\n"
    schema += "ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO knowledge_test_runtime;\n"
    run(["docker", "exec", "--interactive", NAME, "psql", "-X", "-v", "ON_ERROR_STOP=1", "-U", "postgres", "-d", "knowledge_test"], input=schema.encode("utf-8"))
    if args.suite == 'platform-all-go':
        auth_rules = run(["docker", "exec", NAME, "psql", "-X", "-t", "-A", "-F", ",", "-U", "postgres", "-d", "knowledge_test", "-c",
                          "SELECT COUNT(*) FILTER (WHERE type IN ('host','hostssl','hostnossl') AND auth_method='trust'), COUNT(*) FILTER (WHERE type IN ('host','hostssl','hostnossl') AND auth_method='scram-sha-256') FROM pg_hba_file_rules WHERE error IS NULL"]).stdout.decode("utf-8").strip()
        try:
            trust_rules, scram_rules = (int(part) for part in auth_rules.split(','))
        except (TypeError, ValueError):
            raise RuntimeError('could not verify disposable PostgreSQL host authentication rules')
        if trust_rules != 0 or scram_rules < 1:
            raise RuntimeError('disposable PostgreSQL host rules must use SCRAM and contain no trust authentication')
        receipt['postgres_host_auth'] = {
            'initdb_host_method': 'scram-sha-256',
            'initdb_local_method': 'trust',
            'host_trust_rule_count': trust_rules,
            'host_scram_rule_count': scram_rules,
            'host_rules_verified': True,
        }
    receipt["database_versions"] = run(["docker", "exec", NAME, "psql", "-X", "-t", "-A", "-U", "postgres", "-d", "knowledge_test", "-c", "SELECT current_setting('server_version'),extversion FROM pg_extension WHERE extname='vector'"]).stdout.decode("utf-8").strip()
    metadata = json.loads(run(["docker", "inspect", NAME]).stdout)[0]
    binding = metadata["NetworkSettings"]["Ports"]["5432/tcp"][0]
    if binding["HostIp"] != "127.0.0.1":
        raise RuntimeError("fixture port is not loopback-only")
    env = os.environ.copy()
    if args.suite == 'platform-all-go':
        for name in list(env):
            if name == 'DB_DSN' or name == 'DATABASE_URL' or 'DSN' in name.upper() or name.upper().startswith('PG'):
                env.pop(name, None)
        for name in ('AUTHORIZATION_ISOLATED_KAFKA_BROKER', 'PLATFORM_TEST_CHECKPOINT_RECOVERY',
                     'PLATFORM_TEST_LIVE_EVIDENCE', 'PLATFORM_TEST_LIVE_MODELS',
                     'PLATFORM_TEST_PUBLIC_ANSWER_CACHE', 'PLATFORM_TEST_PUBLIC_ANSWER_EVIDENCE',
                     'PLATFORM_TEST_PYTHON_ARTIFACT', 'PLATFORM_TEST_PYTHON_EVIDENCE',
                     'PLATFORM_TEST_PYTHON_RUNTIME_CONFIG', 'PERMISSION_SCALE_TEST',
                     'PERMISSION_SCALE_EVIDENCE_PATH'):
            env.pop(name, None)
        for name in list(env):
            if name.startswith('LEXAGENT_LIVE_'):
                env.pop(name, None)
    runtime_dsn = "postgres://knowledge_test_runtime:" + runtime_password + "@127.0.0.1:" + binding["HostPort"] + "/knowledge_test?sslmode=disable"
    env["KNOWLEDGE_TEST_POSTGRES_DSN"] = runtime_dsn
    env["PUBLIC_TEST_POSTGRES_RUNTIME_DSN"] = runtime_dsn
    env["PUBLIC_TEST_POSTGRES_MIGRATION_DSN"] = "postgres://postgres:" + password + "@127.0.0.1:" + binding["HostPort"] + "/knowledge_test?sslmode=disable"
    kafka_fixture_available = args.suite == 'kafka'
    kafka_image = 'apache/kafka:3.9.1'
    kafka_meta = None
    if args.suite == 'kafka':
        kafka_meta=json.loads(run(['docker','image','inspect',kafka_image]).stdout)[0]
    elif args.suite == 'platform-all-go' and not args.go_test_pattern:
        kafka_inspection = subprocess.run(['docker','image','inspect',kafka_image], capture_output=True)
        if kafka_inspection.returncode == 0:
            kafka_meta = json.loads(kafka_inspection.stdout)[0]
            kafka_fixture_available = True
        else:
            receipt['optional_kafka_fixture'] = 'not run: apache/kafka:3.9.1 was not already present locally; no image pull attempted'
    elif args.suite == 'platform-all-go':
        receipt['optional_kafka_fixture'] = 'not selected in the fixed affected-regression batch; no Kafka container started'
    if kafka_fixture_available:
        receipt['kafka_image_id']=kafka_meta['Id']
        kafka_settings={'KAFKA_HEAP_OPTS':'-Xms256m -Xmx256m','KAFKA_NODE_ID':'1','KAFKA_PROCESS_ROLES':'broker,controller',
            'KAFKA_LISTENERS':'PLAINTEXT://127.0.0.1:9092,CONTROLLER://127.0.0.1:9093',
            'KAFKA_ADVERTISED_LISTENERS':'PLAINTEXT://127.0.0.1:9092','KAFKA_CONTROLLER_LISTENER_NAMES':'CONTROLLER',
            'KAFKA_LISTENER_SECURITY_PROTOCOL_MAP':'CONTROLLER:PLAINTEXT,PLAINTEXT:PLAINTEXT',
            'KAFKA_CONTROLLER_QUORUM_VOTERS':'1@127.0.0.1:9093','KAFKA_OFFSETS_TOPIC_REPLICATION_FACTOR':'1',
            'KAFKA_TRANSACTION_STATE_LOG_REPLICATION_FACTOR':'1','KAFKA_TRANSACTION_STATE_LOG_MIN_ISR':'1',
            'KAFKA_AUTO_CREATE_TOPICS_ENABLE':'false','KAFKA_GROUP_INITIAL_REBALANCE_DELAY_MS':'0'}
        kafka_env=TEMP/'kafka.env'
        kafka_env.write_text(''.join(k+'='+v+'\n' for k,v in kafka_settings.items()),encoding='utf-8')
        run(['docker','run','--detach','--name',KAFKA_NAME,'--label','agentplug.test.owner='+OWNER,
            '--network','container:'+NAME,'--memory','768m','--env-file',str(kafka_env),kafka_image])
        topic_command=['docker','exec',KAFKA_NAME,'/opt/kafka/bin/kafka-topics.sh','--bootstrap-server','127.0.0.1:9092']
        for attempt in range(30):
            try:
                ready=subprocess.run([*topic_command,'--list'],capture_output=True,timeout=15)
                if ready.returncode==0: break
            except subprocess.TimeoutExpired:
                pass
            time.sleep(1)
        else:
            raise RuntimeError('owned Kafka broker readiness timed out')
        for topic in ['platform.audit','agent-platform.identity.v1','platform.notification-dlq.v1']:
            run([*topic_command,'--create','--topic',topic,'--partitions','1','--replication-factor','1'],timeout=30)
        receipt['kafka_topics_created_explicitly']=True
        receipt['kafka_listeners_loopback_only_no_host_port']=True
        if args.suite == 'platform-all-go':
            receipt['optional_kafka_fixture'] = 'started from the pre-existing local image on the owned PostgreSQL network namespace'
    basename = basenames[args.suite]
    log = TEMP / 'platform-all-go.raw.jsonl' if args.suite == 'platform-all-go' else EVIDENCE / (basename + '.log')
    packages = ['./...'] if args.suite == 'platform-all-go' else (['./internal/knowledge'] if args.suite == 'knowledge' else ['./internal/sqlutil', './internal/postgresintegration', './internal/catalog'])
    selection = [] if args.suite == 'knowledge' else ['-run', 'TestPostgres|TestBind|TestSQLCatalogReleaseAtomicityProvenanceAndRetry']
    if args.suite == 'platform-all-go':
        selection = []
    if args.suite == 'knowledge':
        packages = ['./internal/knowledge', './cmd/platform']
        selection = ['-run', KNOWLEDGE_GO_TEST_PATTERN]
    if args.suite == 'identity':
        packages = ['./internal/identity']
        selection = ['-run', 'TestSQLRefreshSessionLifecycle|TestSQLPermissionChangeAtomicRetryAndStalePlan|TestSQLAdministratorAuthenticationAndContinuity|TestSQLOIDCBindingFollowsCurrentIAMState|TestSQLAuthorizationEpochTracksIAMAndRejectsRevocation']
        if args.administrator_scopes:
            selection = ['-run', '^(' + '|'.join(sorted(ADMINISTRATOR_SCOPE_REQUIRED_TESTS)) + ')$']
            receipt['scope'] = 'actual PostgreSQL live administrative workspaces, non-inherited business access, administrative self-request/self-grant denial, workspace switching and atomic permission request decisions'
        if args.company_administration:
            selection = ['-run', '^(TestSQLCompanyAdministratorAppointmentAndBoundaries|TestSQLCompanyAdministratorLifecycleAndRevocation|TestSQLCompanyAdministratorOIDCDelegationAndRevocation|TestCompanyAdministratorScopeAndDelegationQualification|TestSQLAdministratorAuthenticationAndContinuity|TestSQLAdministratorWorkspacesFollowLiveAuthority|TestSQLAdministratorsCannotAddOwnBusinessAuthority|TestSQLDepartmentAdministratorMembershipAndAgentBoundary)$']
            receipt['scope'] = 'actual isolated PostgreSQL explicit replacement of one former global administrator by appointment-only tenant_admin v2, retained permanent global recovery identity, management without business membership, company-only department admission and fresh authenticated delegation; no project IAM migration'
        if args.department_agent_access:
            packages = ['./internal/identity', './internal/catalog']
            selection = ['-run', '^(' + '|'.join(sorted(DEPARTMENT_AGENT_REQUIRED_TESTS)) + ')$']
            receipt['scope'] = 'actual isolated PostgreSQL persisted department Agent ceilings, company-only fresh authenticated changes, audit-port rollback, concurrent revision fencing, managed department allocation without redundant per-Agent delegations, withdrawal/restoration source generations, legacy-mode rejection and corrupt-policy fail-closed; controlled Catalog/audit ports, no project IAM migration or deployed UI proof'
        if args.permission_batches:
            selection = ['-run', '^(' + '|'.join(sorted(PERMISSION_BATCH_REQUIRED_TESTS)) + ')$']
            receipt['scope'] = 'actual isolated PostgreSQL persisted multi-user authorization and request decision batches, per-item atomic results, concurrent continuation, partial conflict, audit-port rollback, cancellation, live authority loss and applicant withdrawal; controlled Catalog/audit ports, no deployed UI proof'
    if args.suite == 'index':
        packages = ['./internal/knowledge', './cmd/platform']
        selection = ['-run', '^TestPostgresIndex']
    if args.suite == 'source':
        packages = ['./internal/knowledge']
        selection = ['-run', '^TestPostgresSource']
    if args.suite == 'identity-full':
        packages = ['./internal/identity']
        selection = ['-run', '^(TestSQLAuthorizationChangeInvalidatesStepUpAtomically|TestSQLPermissionPrincipalDirectoryScopesAndValidity|TestSQLAdministratorAuthenticationAndContinuity|TestSQLAuthorizationEpochScopeShrinkRevocationAndOutageNeverReturnOldVersion|TestSQLAuthorizationEpochTracksIAMAndRejectsRevocation|TestSQLAuthorizationEpochTracksNaturalV2BoundariesWithAlternativeAllow|TestSQLCapabilityResourceRequestApprovalAndRevocation|TestSQLDelegationPreviewValidatesCurrentBoundaryWithoutWrites|TestSQLDelegationRevocationFencesPendingAuthorization|TestSQLEnrollmentApprovalAndRejectionRace|TestSQLEnrollmentPermissionApproval|TestSQLEnrollmentRejection|TestSQLEnrollmentRejectionTemporaryDelegation|TestSQLLegacyAuthenticationImportAndVerifiedExistingAdministrator|TestSQLLegacyPermissionRequestImportConcurrentAndDisabledSubject|TestSQLLegacyPermissionRequestImportPreservesSourceAndUsesNewApproval|TestSQLLegacyRequestMigrationPlanIsReadOnlyAndRejectsChangedSource|TestSQLMachineProtocolVersionedActionsAndLiveObjectScope|TestSQLMembershipRemovalPreservesDenyAndPreventsRejoinRevival|TestSQLMembershipRemovalRetainsOtherCoverageAndRejectsStaleCAS|TestSQLMigrationMappingCommitPreservesSourceAndRollsBack|TestSQLMigrationResourcesValidateOwnershipAndRejectConcurrentSourceChange|TestSQLMigrationSourcesPreserveProtectedFactsAndDetectUnversionedChanges|TestSQLOIDCBindingFollowsCurrentIAMState|TestSQLOIDCStepUpAppointmentAndOneUse|TestSQLOIDCStepUpAuditRollbackAndExpirationCleanup|TestSQLOIDCStepUpChallengeBindingAndFreshness|TestSQLOIDCStepUpRevocationAndQualification|TestSQLPermissionChangeAtomicRetryAndStalePlan|TestSQLPermissionExplanationSelfAdministratorScopeAndOutage|TestSQLPermissionExplanationTrustedObjectsAndExistenceBoundary|TestSQLPermissionPrincipalCreation|TestSQLPermissionRequestTwoAdministratorsOnlyOneSubsetCommits|TestSQLPermissionRequestWithdrawalAndDecisionRace|TestSQLPermissionRequestsBoundaryAndRejection|TestSQLPermissionRequestsSubsetAndAtomicAudit|TestSQLPermissionWorkloadCreationAtomicUnprivilegedAndRetry|TestSQLPresetChangeRetainsOtherApplicationAndRejectsPartialDelegation|TestSQLRefreshSessionLifecycle|TestSQLScopedMachineCredentialLifecycle|TestSQLStorePasswordChangeFailsClosedWithoutAtomicRecorder|TestSQLTaskAssignmentAtomicCASIdempotencyAndRevocation|TestSQLTaskAssignmentDelegationAndInputBoundary|TestSQLTaskAssignmentNaturalValidityPersistsEpoch|TestSQLWorkloadBindingCASAuditRetryAndRevocation|TestSQLWorkspaceSwitchAndRefresh)$']
    if args.suite == 'scale':
        packages = ['./internal/identity']
        selection = ['-run', '^TestSQLPermissionScaleAcceptance$']
        env['GOMAXPROCS']='2'
        receipt['go_max_procs']=2
        receipt['postgres_tmpfs_bytes']=1073741824
        env['PERMISSION_SCALE_TEST']='1'
        env['PERMISSION_SCALE_EVIDENCE_PATH']=str(SCALE_EVIDENCE)
    if args.suite == 'usage':
        packages = ['./internal/usagecost']
        selection = ['-run', 'TestSQLModelBudget|TestSQLUsageConcurrentFirstEventsRemainExactlyOnce|TestSQLUsageLegacyBrowserBoundaryAndAuthorizedBudget']
    if args.suite == 'execution':
        packages = ['./internal/execution']
        selection = ['-run', 'TestSQLProjectionKeysetFairness|TestSQLAtomicCreationAndOutcomeFaultRecovery|TestSQLProjectionOutageRecoversWithoutAgentExecution|TestSQLConcurrentCreationReplaysSingleWinner|TestSQLCancellationIntentAndOutcomeFaultRecovery|TestSQLTaskCheckpointLeaseTransactionFence|TestSQLControllerStopEvidenceAtomicAuditAndCAS']
    if args.suite == 'execution-recovery':
        packages = ['./internal/execution']
        selection = ['-run', '^(TestSQLConcurrentDispatchersOnlyInvokeOnce|TestSQLRecoveryStopBarrierRollsBackAndRetainsResume|TestSQLDualDispatcherFencesLeaseAndReadsLatestResume|TestSQLRecoverySnapshotReadsPersistedStates|TestPersistentSessionLeaseSQLOrdering|TestSQLDispatcherHeartbeatStopsAfterDatabaseRenewalFault|TestPersistentSessionLeaseSQLRestartAndHeartbeatRollback)$']
    if args.suite == 'models':
        packages = ['./internal/modelcapacity', './internal/modelgovernance']
        selection = ['-run', 'TestSQLProviderPostgresIntegration|TestPostgresGovernance']
    if args.suite == 'policy':
        packages = ['./internal/policyasset']
        selection = ['-run', 'TestSQLKnowledgeDocumentBindingsRoundTripAndIsolation|TestSQLPreparedPublicationPersistsSixPoliciesAndMatchesExactRetry']
    if args.suite == 'conversation':
        packages = ['./internal/conversation']
        selection = ['-run', 'TestSQLConversationInstallationProvenance|TestSQLRetentionAndLegalHoldSerializeOnSession|TestSQLRetentionSweepLimitSkipsUnexpiredOlderSession|TestSQLConversationExportCompletenessAndRollback|TestSQLProjectionUTF8AndLongReplay|TestSQLConversationConcurrentRevisionAndRegeneration']
    if args.suite == 'erasure-audit':
        packages = ['./internal/conversation','./internal/audit']
        selection = ['-run', '^(TestSQLConversationErasureRecoveryAndAtomicPayloadDeletion|TestSQLDeletionReviewFiltersBeforePaginationAndRollsBackDeniedCommit|TestSQLAuditMetadataScopeIsolationAndPagination|TestSQLAuditNotificationPortAtomicity)$']
    if args.suite == 'platform-ports':
        packages = ['./cmd/platform']
        selection = ['-run', '^(TestSQLDepartmentAgentCeilingActualCatalogAuditOutboxAndRuntime|TestSQLCatalogReleaseActualIAMAndAuditOutbox|TestSQLAuthorizationAdministrationVersionAndLifecycleAtomic|TestSQLNotificationGuardLossRollsBackOutbox|TestSQLNotificationCommitReceiptSurvivesReopenAndRejectsTampering)$']
    if args.suite == 'process':
        packages = ['./cmd/migrate','./cmd/deployment-observe']
        selection = ['-run', '^(TestSQLRealPlatformProcessStartsWithDMLAndRejectsBadSchema|TestSQLModelObservationUpdatesHealthAndCapacityWithRevision)$']
        if args.evaluation_restart:
            packages = ['./cmd/migrate']
            selection = ['-run', '^TestSQLRealPlatformProcessStartsWithDMLAndRejectsBadSchema$/^evaluation-seed-process-restart$']
    if args.suite == 'maintenance':
        packages = ['./cmd/migrate']
        selection = ['-run', '^TestSQLMigrationMappingCLIUsesSelectOnlyAndRejectsChangedSource$']
    if args.suite == 'kafka':
        packages = ['./cmd/platform']
        selection = ['-run', '^TestSQLKafkaAuthorizationEventsAtomicAndDurableReplay$']
    if args.retrieval_cache:
        packages = ['./internal/knowledge', './cmd/platform']
        selection = ['-run', '^(TestPostgresRetrievalCacheFreshBodiesAndVersionFences|TestPostgresKnowledgeQueryBackend)$']
    if args.answer_cache:
        packages = ['./cmd/platform', './internal/capability']
        selection = ['-run', '^(TestPostgresKnowledgeQueryBackend|TestKnowledgeAnswerRequiresCompleteGovernedReceiptAndKnownCitations|TestSignedKnowledgeAnswerRejectsWholeAnswerWhenEvidenceOrModelIsDenied|TestKnowledgeAnswerHasNoLegacyUngovernedFallback)$']
    if args.suite == 'tree-budget':
        packages = ['./internal/usagecost']
        selection = ['-run', '^TestSQLRunTreeBudget']
    if args.suite == 'evaluation':
        packages = ['./internal/evaluationproduct']
        selection = ['-run', 'TestEvaluationLeasePostgresIntegration|TestSQLSuccessfulFinalizationFailureRecoversWithoutDuplicateInvocation']
        if args.rag_evaluation:
            selection = ['-run', '^(TestEvaluationLeasePostgresIntegration|TestSQLSuccessfulFinalizationFailureRecoversWithoutDuplicateInvocation|TestSQLIndependentRAGGroundingEvidence)$']
        if args.real_rag_metrics:
            selection = ['-run', '^TestSQLRealFrozenRAGMetricServiceEvidence$']
    if args.suite == 'capability':
        packages = ['./internal/capability']
        selection = ['-run', 'TestSQLMemoryExpiryCleanupPreservesConcurrentRefresh|TestSQLMemoryWriteContinuityWithPrincipalRevocation|TestToolInvocationFailedAttemptCanRetryPostgresIntegration|TestGovernedModelBillingPostgresIntegration|TestGovernedEmbeddingBillingPostgresIntegration|TestGovernedKnowledgeEmbeddingBillingPostgresIntegration|TestSQLToolCommitGuardRejectsMissingForgedAndExpiredProof|TestSQLMemoryConcurrentQuotaCannotOverrun']
    if args.function_calling:
        packages = ['./internal/capability']
        selection = ['-run', '^(TestGovernedFunctionBillingPostgresIntegration|TestInvalidFunctionBillingPostgresIntegration|TestToolInvocationFailedAttemptCanRetryPostgresIntegration|TestMCPActualHTTPDiscoverySchemaPinAndInvocation|TestMCPUncertainReceiptDoesNotRetryRemoteSideEffect|TestModelReadOnlyReceiptDoesNotCreateInvocationOrChangeSpend)$']
    if args.business_state:
        packages = ['./internal/capability', './internal/execution', './cmd/migrate']
        selection = ['-run', '^(TestCheckpointRecoveryKeyKeepsIdentityAndVersionBoundary|TestCheckpointContentHashPreservesLargeNumbersAndSchema|TestCheckpointRejectsUnboundedOrAmbiguousDocuments|TestCheckpointMaintenanceStartsOnceAndStopsWithModule|TestSQLBusinessCheckpointCASRecoveryAndAuthority|TestSQLTaskCheckpointLeaseTransactionFence|TestPostgresMigrationCommandCompleteBundleAndReplay|TestContextWindowPreservesSystemLatestTurnAndToolPairs|TestContextSummaryIsBoundedUntrustedAndDeterministic|TestContextRejectModeAndOversizedCurrentTurnFailClosed|TestModelInputLimitRejectsBeforeProviderOrBudget)$']
    if args.runtime_observation:
        packages = ['./internal/capability']
        selection = ['-run', '^TestRuntimeObservation|^TestRuntimeToolAuditLedgerOutboxAtomicityPostgres$']
    if args.tool_approval:
        packages = ['./internal/capability', './internal/identity', './cmd/migrate', './cmd/platform']
        selection = ['-run', '^(TestToolConfirmationBindsApprovalToExactOperation|TestSignedToolGatewayRequiresConfirmationAndStillRechecksIAM|TestSQLToolApprovalRevocationAndAuditAtomicity|TestSQLToolStepUpExactActionAndTransaction|TestSQLOIDCToolStepUpExactSessionAndOperation|TestSQLOIDCToolStepUpMembershipRevocation|TestPostgresMigrationCommandCompleteBundleAndReplay|TestPostgresToolApprovalHTTPUsesRealSessionIAMAndStepUp|TestPostgresToolApprovalHTTPOIDCOnly)$']
    if args.skill_transactions:
        packages = ['./internal/capability']
        selection = ['-run', '^TestSQLSkillModelValidationCallerTransactionPostgres$']
    if args.suite == 'capability-recovery':
        packages = ['./internal/capability']
        selection = ['-run', '^(TestSQLPreparationRecoveryConcurrentBoundedBatches|TestSQLPreparingCrashRecoveryFencesStaleAttempt|TestSQLPreparedModelSendSurvivesTTLAndReopen|TestSQLBillingRecoveryCorruptRowIsIsolated|TestSQLToolLeaseContendersAndReopenFencing|TestSQLToolWorkerRecoversWithoutClientRetryAfterReopen|TestToolRenewalOwnership)$']
    if args.suite == 'capability-billing':
        packages = ['./internal/capability']
        selection = ['-run', '^(TestSQLUnsentProofSurvivesPartialRelease|TestSQLBillingManualDecisionAuditAndCompensation|TestSQLBillingRecoveryRetainsHoldAndReplaysAfterRestart)$']
    if args.suite == 'schema':
        packages = ['./internal/schemaversion', './cmd/migrate']
        selection = ['-run', 'TestPostgresSchema|TestPostgresDelegationAuthorityMarkerUpgradesFromModelUsageStep|TestPostgresDelegationAuthorityMarkerUpgradesFromPermissionCatalogV2|TestPostgresRuntimePrivileges|TestPostgresMigrationCommandCompleteBundleAndReplay']
    if args.suite == 'administration':
        migration_env = env.copy()
        migration_env['APP_ENV'] = 'test'
        migration_env['DB_DRIVER'] = 'pgx'
        migration_env['DB_DSN'] = env['PUBLIC_TEST_POSTGRES_MIGRATION_DSN']
        migration_env.pop('PLATFORM_DEV_RUNTIME_PASSWORD', None)
        if not args.containerized_go:
            run(['go', 'run', './cmd/migrate'], cwd=ROOT / 'platform', env=migration_env)
            receipt['actual_complete_migration_command'] = True
        packages = ['./cmd/bootstrap-admin']
        selection = ['-run', '^TestFirstAdministratorPostgres$']
        if args.local_admin_bootstrap:
            selection = ['-run', '^TestFirstAdministratorLocalPasswordPostgres$']
    if args.suite == 'checkpoint':
        import xml.etree.ElementTree as ET
        env['PYTHONPATH'] = os.pathsep.join([str(ROOT/'.cache/sdk-postgres'),str(ROOT/'sdk/python')])
        env['PYTHONDONTWRITEBYTECODE'] = '1'
        env['PYTHONIOENCODING'] = 'utf-8'
        env['PYTHONUTF8'] = '1'
        env['CHECKPOINT_ISOLATED_TEST_DSN'] = env['PUBLIC_TEST_POSTGRES_MIGRATION_DSN']
        env['APP_ENV'] = 'test'
        if args.sdk_full:
            # Keep the durable receipt fixture separate: checkpoint upgrade tests intentionally drop their own schema.
            durable_role = 'sdk_exit_rt_' + hashlib.sha256(OWNER.encode()).hexdigest()[:16]
            durable_admin = env['PUBLIC_TEST_POSTGRES_MIGRATION_DSN'].replace('/knowledge_test?', '/knowledge_durable_test?')
            run(['docker', 'exec', NAME, 'psql', '-X', '-v', 'ON_ERROR_STOP=1', '-U', 'postgres', '-d', 'knowledge_test', '-c', 'CREATE DATABASE knowledge_durable_test'])
            bootstrap_env = env.copy()
            bootstrap_env.update(APP_ENV='production', CHECKPOINT_DSN=durable_admin)
            run([sys.executable, '-B', '-m', 'agent_platform_sdk.checkpoint_bootstrap'], cwd=ROOT/'sdk/python', env=bootstrap_env)
            grants = "CREATE ROLE " + durable_role + " LOGIN PASSWORD '" + runtime_password + "';\n"
            grants += "REVOKE CREATE ON SCHEMA public FROM PUBLIC; REVOKE CREATE,TEMP ON DATABASE knowledge_durable_test FROM PUBLIC;\n"
            grants += "GRANT SELECT ON checkpoint_migrations TO " + durable_role + ";\n"
            grants += "GRANT SELECT,INSERT,UPDATE,DELETE ON checkpoints,checkpoint_blobs,checkpoint_writes TO " + durable_role + ";\n"
            grants += "GRANT SELECT,INSERT,UPDATE ON sdk_execution_generation TO " + durable_role + ";\n"
            run(['docker','exec','--interactive',NAME,'psql','-X','-v','ON_ERROR_STOP=1','-U','postgres','-d','knowledge_durable_test'], input=grants.encode('utf-8'))
            env['DURABLE_EXIT_TEST_DSN'] = 'postgresql://' + durable_role + ':' + runtime_password + '@127.0.0.1:' + binding['HostPort'] + '/knowledge_durable_test?sslmode=disable'
            env['DURABLE_EXIT_TEST_ADMIN_DSN'] = durable_admin
            receipt['durable_exit_fixture_isolated'] = True
            receipt['durable_exit_runtime_delete_privilege'] = False
        results = TEMP/'checkpoint-results.xml'
        paths = ['tests', 'agent_platform_sdk/test_runtime.py', 'agent_platform_sdk/test_checkpoint_scope.py'] if args.sdk_full else ['tests/test_checkpoint_postgres_integration.py']
        receipt['full_python_sdk'] = args.sdk_full
        with log.open('wb') as output:
            process = subprocess.run([sys.executable,'-m','pytest','-p','no:cacheprovider','-q','--tb=short','--basetemp',str(TEMP/'pytest-temporary'),'--junitxml',str(results),*paths],cwd=ROOT/'sdk/python',env=env,stdout=output,stderr=subprocess.STDOUT)
        if results.exists():
            cases = list(ET.parse(results).iter('testcase'))
            passed = [case.attrib['name'] for case in cases if not list(case)]
            skipped = [case.attrib['name'] for case in cases if case.find('skipped') is not None]
            with log.open('a',encoding='utf-8') as output:
                for name in passed: output.write('\n--- PASS: '+name+'\n')
                for name in skipped: output.write('\n--- SKIP: '+name+'\n')
        receipt['sdk_workflow_database'] = True
    else:
        with (open(os.devnull, 'wb') if args.suite == 'platform-all-go' else log.open("wb")) as output:
            if args.suite in {'process', 'maintenance', 'kafka', 'platform-all-go'} or args.containerized_go:
                go_image = 'golang:1.26.10-bookworm'
                run(['docker','image','inspect',go_image])
                project_mod_cache = ROOT/'.cache/go-mod'
                default_mod_cache = project_mod_cache if (project_mod_cache/'cache/download').is_dir() else Path(os.environ.get('USERPROFILE',str(Path.home())))/'go/pkg/mod'
                download = Path(os.environ.get('GOMODCACHE',str(default_mod_cache)))/'cache/download'
                if not download.is_dir(): raise RuntimeError('existing offline Go module download cache required')
                private_env = TEMP/'go.env'
                go_settings = {'PUBLIC_TEST_POSTGRES_MIGRATION_DSN': 'postgres://postgres:'+password+'@127.0.0.1:5432/knowledge_test?sslmode=disable',
                               'GOMAXPROCS':'2','GOPROXY':'file:///module-cache','GOSUMDB':'off','GOTOOLCHAIN':'local',
                               'GOCACHE':'/test-cache/build','GOMODCACHE':'/test-cache/mod','GOFLAGS':'-buildvcs=false','CGO_ENABLED':'1','HOME':'/tmp'}
                if args.containerized_go:
                    # Build caches stay in the disposable Linux filesystem;
                    # bind mounts on Windows are used only for small evidence.
                    go_settings.update(GOCACHE='/tmp/go-build', GOMODCACHE='/tmp/go-mod')
                if args.suite == 'scale':
                    go_settings.update(PERMISSION_SCALE_TEST='1', PERMISSION_SCALE_EVIDENCE_PATH='/test-cache/scale-evidence.json')
                if args.suite == 'platform-all-go':
                    runtime_internal_dsn = 'postgres://knowledge_test_runtime:'+runtime_password+'@127.0.0.1:5432/knowledge_test?sslmode=disable'
                    go_settings.update(PUBLIC_TEST_POSTGRES_RUNTIME_DSN=runtime_internal_dsn,
                                       KNOWLEDGE_TEST_POSTGRES_DSN=runtime_internal_dsn,
                                       APP_ENV='test', DB_DRIVER='pgx',
                                       DB_DSN=go_settings['PUBLIC_TEST_POSTGRES_MIGRATION_DSN'])
                if args.suite == 'kafka' or (args.suite == 'platform-all-go' and kafka_fixture_available):
                    go_settings['AUTHORIZATION_ISOLATED_KAFKA_BROKER']='127.0.0.1:9092'
                if args.checkpoint_agent_process:
                    go_settings['PLATFORM_TEST_CHECKPOINT_RECOVERY'] = '1'
                if args.evaluation_restart:
                    go_settings['PLATFORM_TEST_EVALUATION_RESTART'] = '1'
                if args.answer_cache_process:
                    go_settings['PLATFORM_TEST_PUBLIC_ANSWER_CACHE'] = '1'
                    go_settings['PLATFORM_TEST_PUBLIC_ANSWER_EVIDENCE'] = '/test-cache/answer-cache.json'
                if args.example_tool_loop:
                    go_settings['PLATFORM_TEST_EXAMPLE_TOOL_LOOP'] = '1'
                if external_example_process:
                    python_image = json.loads(run(['docker','image','inspect','agentplug:example-'+example_language]).stdout)[0]
                    receipt[example_language+'_image_id'] = python_image['Id']
                    go_settings.update({
                        'PLATFORM_TEST_'+example_language.upper()+'_RUNTIME_CONFIG': '/test-cache/'+example_language+'-runtime.json',
                        'PLATFORM_TEST_'+example_language.upper()+'_ARTIFACT': python_image['Id'],
                        'PLATFORM_TEST_'+example_language.upper()+'_EVIDENCE': '/test-cache/'+example_language+'-evidence.json'})
                if args.live_models:
                    metadata = ROOT / '.local-secrets/model-providers/runtime-mounts/providers.json'
                    if not metadata.is_file(): raise RuntimeError('prepared operator model metadata required')
                    go_settings['PLATFORM_TEST_LIVE_MODELS'] = '1'
                    go_settings['PLATFORM_TEST_LIVE_EVIDENCE'] = '/test-cache/live-rag.json'
                private_env.write_text(''.join(key+'='+value+'\n' for key,value in go_settings.items()),encoding='utf-8')
                private_env.chmod(0o600)
                go_cache = TEMP/'go-cache';go_cache.mkdir()
                shared_build_cache = ROOT/'.cache/go-linux-test-build'
                shared_build_cache.mkdir(parents=True, exist_ok=True)
                go_settings['GOCACHE'] = '/go-build-cache'
                private_env.write_text(''.join(key+'='+value+'\n' for key,value in go_settings.items()),encoding='utf-8')
                # Private handoff/evidence files are created with mode 0600.
                # On Linux they must belong to the host runner so it can read
                # them and remove the owned module/build cache after the test.
                # Docker Desktop bind mounts use the host filesystem ACLs.
                container_user = ['--user', str(os.getuid())+':'+str(os.getgid())] if os.name == 'posix' else []
                receipt['go_container_user'] = container_user[1] if container_user else 'Docker Desktop default'
                container_prefix = ['docker','run','--rm','--name',GO_NAME,'--label','agentplug.test.owner='+OWNER,
                    *container_user,
                    '--network','container:'+NAME,'--env-file',str(private_env),
                    '--mount','type=bind,source='+str(ROOT)+',target=/workspace,readonly',
                    '--mount','type=bind,source='+str(download)+',target=/module-cache,readonly',
                    '--mount','type=bind,source='+str(go_cache)+',target=/test-cache',
                    '--mount','type=bind,source='+str(shared_build_cache)+',target=/go-build-cache',
                    '--workdir','/workspace/platform',go_image]
                if args.suite == 'administration':
                    go_settings.update(APP_ENV='test', DB_DRIVER='pgx', DB_DSN=go_settings['PUBLIC_TEST_POSTGRES_MIGRATION_DSN'])
                    private_env.write_text(''.join(key+'='+value+'\n' for key,value in go_settings.items()), encoding='utf-8')
                    run([*container_prefix, 'go', 'run', './cmd/migrate'], timeout=300)
                    receipt['actual_complete_migration_command'] = True
                if args.suite == 'platform-all-go':
                    receipt['postgres_host_auth'].update(verify_postgres_runtime_password_auth(container_prefix, go_cache))
                    run([*container_prefix, 'go', 'run', './cmd/migrate'], timeout=300)
                    grant_sql = """GRANT USAGE ON SCHEMA public, knowledge TO knowledge_test_runtime;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO knowledge_test_runtime;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA knowledge TO knowledge_test_runtime;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO knowledge_test_runtime;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA knowledge TO knowledge_test_runtime;
ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO knowledge_test_runtime;
ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO knowledge_test_runtime;
ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA knowledge GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO knowledge_test_runtime;
ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA knowledge GRANT USAGE, SELECT ON SEQUENCES TO knowledge_test_runtime;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
REVOKE CREATE, TEMPORARY ON DATABASE knowledge_test FROM PUBLIC;
REVOKE INSERT,UPDATE,DELETE ON platform_schema_version,platform_compensation_schema_version,platform_notification_control_version,platform_kafka_dead_letter_schema_version FROM knowledge_test_runtime;
REVOKE UPDATE,DELETE ON platform_compensation_event,platform_cancellation_effect,platform_kafka_dead_letter_action FROM knowledge_test_runtime;
REVOKE DELETE ON platform_compensation_step,platform_compensation_local_effect,platform_cancellation_operation,platform_notification_inbox,platform_kafka_dead_letter FROM knowledge_test_runtime;
"""
                    run(['docker','exec','--interactive',NAME,'psql','-X','-v','ON_ERROR_STOP=1','-U','postgres','-d','knowledge_test'],input=grant_sql.encode('utf-8'))
                    receipt['complete_platform_migration_before_full_go_suite'] = True
                    receipt['runtime_role_is_dml_only'] = True
                    selection = ['-run', args.go_test_pattern] if args.go_test_pattern else []
                    command = [*container_prefix,'go','test','-json','-p=1','-parallel=1','-count=1','-timeout=20m',*selection,'./...']
                    process = run_bounded_capture(command, log, timeout=1260, max_bytes=GO_JSON_LIMIT)
                    receipt['go_json_summary'] = parse_platform_go_jsonl(log)
                    if args.go_test_pattern:
                        required_go_tests = (GO_WORKER_DIAGNOSTIC_REQUIRED_TESTS if args.go_test_pattern == GO_WORKER_DIAGNOSTIC_PATTERN else GO_AFFECTED_REQUIRED_TESTS)
                        receipt['required_go_test_states'] = required_platform_go_test_states(log, required_go_tests)
                    else:
                        receipt['required_go_test_states'] = required_platform_go_test_states(log, GO_GOVERNED_BILLING_REQUIRED_TESTS)
                        receipt['required_go_test_states'].update(required_platform_go_test_states(log, GO_PERMISSION_AUTHENTICATION_REQUIRED_TESTS))
                    receipt['test_exit_code'] = process.returncode
                    try:
                        private_record = persist_private_go_jsonl(log, args.batch_id, OWNER, (password, runtime_password))
                        receipt['private_go_jsonl'] = private_record
                    except Exception as error:
                        receipt['private_go_jsonl_error'] = type(error).__name__
                    if args.go_test_pattern:
                        sdk_summary = {'status': 'not_selected',
                                       'reason': 'not rerun in the fixed affected-regression batch; prior isolated checkpoint integration result was 1/1 PASS'}
                    else:
                        sdk_env = env.copy()
                        secret_environment_name = re.compile(r'(?i)(?:DSN|DATABASE_URL|API[_-]?KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL|OPENAI|ANTHROPIC|DEEPSEEK|AZURE)')
                        for name in list(sdk_env):
                            if name == 'DB_DSN' or secret_environment_name.search(name):
                                sdk_env.pop(name, None)
                        sdk_env['CHECKPOINT_ISOLATED_TEST_DSN'] = env['PUBLIC_TEST_POSTGRES_MIGRATION_DSN']
                        sdk_env['PYTHONPATH'] = os.pathsep.join([str(ROOT/'.cache/sdk-postgres'),str(ROOT/'sdk/python')])
                        sdk_env['PYTHONDONTWRITEBYTECODE'] = '1'
                        sdk_env['PYTHONIOENCODING'] = 'utf-8'
                        sdk_env['PYTHONUTF8'] = '1'
                        sdk_xml = TEMP/'platform-all-go-checkpoint-results.xml'
                        sdk_log = TEMP/'platform-all-go-checkpoint.log'
                        sdk_command = [sys.executable,'-m','pytest','-p','no:cacheprovider','-q','--tb=short',
                                       '--basetemp',str(TEMP/'platform-all-go-checkpoint-temporary'),
                                       '--junitxml',str(sdk_xml),'sdk/python/tests/test_checkpoint_postgres_integration.py']
                        with sdk_log.open('wb') as sdk_output:
                            sdk_process = subprocess.run(sdk_command,cwd=ROOT,env=sdk_env,stdout=sdk_output,
                                                         stderr=subprocess.STDOUT,timeout=300)
                        sdk_summary = {'command_scope':'only the previously fixture-skipped PostgreSQL checkpoint integration test; no SDK full-suite rerun',
                                       'exit_code':sdk_process.returncode,'test_count':0,'passed_count':0,'failed_count':0,
                                       'error_count':0,'skipped_count':0,'test_cases':[]}
                        if sdk_xml.is_file():
                            import xml.etree.ElementTree as ET
                            xml_root = ET.parse(sdk_xml).getroot()
                            cases = list(xml_root.iter('testcase'))
                            sdk_summary.update(test_count=len(cases),
                                                passed_count=sum(1 for case in cases if not any(case.find(tag) is not None for tag in ('failure','error','skipped'))),
                                                failed_count=sum(1 for case in cases if case.find('failure') is not None),
                                                error_count=sum(1 for case in cases if case.find('error') is not None),
                                                skipped_count=sum(1 for case in cases if case.find('skipped') is not None),
                                                test_cases=[{'name':case.attrib.get('name',''),
                                                             'status':'skipped' if case.find('skipped') is not None else 'failed' if case.find('failure') is not None or case.find('error') is not None else 'passed',
                                                             'reason':safe_event_value(case.find('skipped').attrib.get('message',''),(password,runtime_password)) if case.find('skipped') is not None else ''}
                                                            for case in cases])
                    receipt['sdk_checkpoint_postgres'] = sdk_summary
                else:
                    command = [*container_prefix,'go','test',*(['-race'] if args.suite == 'kafka' else []),'-p=1','-count=1','-timeout='+('600s' if args.live_models else '300s' if args.checkpoint_agent_process or args.evaluation_restart else '180s'),'-v',*selection,*packages]
                if external_example_process:
                    process = subprocess.Popen(command, stdout=output, stderr=subprocess.STDOUT)
                    deadline = time.monotonic()+(900 if args.live_models else 420)
                    configuration = go_cache/(example_language+'-runtime.json')
                    while not configuration.is_file():
                        if process.poll() is not None: break
                        if time.monotonic()>deadline: raise RuntimeError(example_title+' runtime handoff timed out')
                        time.sleep(0.2)
                    if configuration.is_file():
                        settings=json.loads(configuration.read_text(encoding='utf-8'))
                        required={'PORT','APP_ENV','AGENT_PLATFORM_PUBLIC_KEY_BASE64','AGENT_PLATFORM_ISSUER','AGENT_PLATFORM_AUDIENCE',
                                  'PLATFORM_CAPABILITY_URL','INTERNAL_TOKEN','INTERNAL_SIGNING_SECRET','AGENT_CLIENT_ID','AGENT_CLIENT_SECRET','OTEL_EXPORTER_OTLP_ENDPOINT'}
                        if set(settings)!=required or any(not isinstance(value,str) or '\n' in value or '\r' in value for value in settings.values()):
                            raise RuntimeError('invalid private '+example_title+' runtime handoff')
                        agent_env=TEMP/(example_language+'.env')
                        agent_env.write_text(''.join(key+'='+value+'\n' for key,value in settings.items()),encoding='utf-8')
                        agent_env.chmod(0o600)
                        run(['docker','run','--detach','--name',EXAMPLE_NAME,'--label','agentplug.test.owner='+OWNER,
                             '--network','container:'+NAME,'--read-only','--cap-drop','ALL','--security-opt','no-new-privileges',
                             '--tmpfs','/tmp:rw,noexec,nosuid,size=32m','--env-file',str(agent_env),python_image['Id']])
                        receipt[example_language+'_started_with_ephemeral_workload_credentials']=True
                    process.wait(timeout=max(1,deadline-time.monotonic()))
                    evidence=go_cache/(example_language+'-evidence.json')
                    receipt[example_language+'_platform_flow']=json.loads(evidence.read_text(encoding='utf-8')) if evidence.is_file() else {'result':'FAIL','reason':'successful full flow evidence absent'}
                elif args.suite != 'platform-all-go':
                    process = subprocess.run(command, stdout=output,stderr=subprocess.STDOUT,
                                             # This wall-clock limit includes module unpacking and cold
                                             # race compilation; Go's separate 180s test limit stays intact.
                                             timeout=900 if args.live_models else 420 if args.suite == 'process' else 600)
                if args.suite == 'scale' and (go_cache/'scale-evidence.json').is_file():
                    shutil.copyfile(go_cache/'scale-evidence.json', SCALE_EVIDENCE)
                if args.live_models and not external_example_process:
                    evidence = go_cache / 'live-rag.json'
                    if evidence.is_file():
                        receipt['live_model_rag'] = json.loads(evidence.read_text(encoding='utf-8'))
                    else:
                        receipt['live_model_rag'] = {'result':'FAIL','reason':'successful complete live flow evidence absent'}
                if args.answer_cache_process:
                    evidence = go_cache / 'answer-cache.json'
                    receipt['public_answer_cache'] = json.loads(evidence.read_text(encoding='utf-8')) if evidence.is_file() else {'result':'FAIL','reason':'complete actual process proof absent'}
                if args.suite == 'process':
                    receipt['actual_linux_platform_executable'] = True
                    receipt['platform_executable_built_with_race_detector'] = True
                elif args.suite == 'maintenance':
                    receipt['actual_linux_maintenance_cli'] = True
                    receipt['maintenance_cli_built_with_race_detector'] = True
                if args.suite == 'kafka':
                    receipt['actual_postgres_kafka_authorization_transport']=True
                    receipt['go_test_race_detector_enabled']=True
                receipt['go_test_image'] = go_image
                receipt['project_mount_readonly'] = True
            else:
                process = subprocess.run(["go", "test", "-p=1", "-count=1", "-v", *selection, *packages], cwd=ROOT / "platform", env=env, stdout=output, stderr=subprocess.STDOUT)
    if args.suite == 'platform-all-go':
        go_summary = receipt['go_json_summary']
        receipt['test_exit_code'] = process.returncode
        receipt['skipped_tests'] = go_summary['skipped_tests']
        receipt['failed_tests'] = go_summary['failed_tests']
        receipt['test_suite_status'] = 'passed_with_skips' if process.returncode == 0 and not go_summary['failed_tests'] and go_summary['counts']['skipped'] else 'passed' if process.returncode == 0 and not go_summary['failed_tests'] else 'failed'
    else:
        receipt["test_exit_code"] = process.returncode
        lines = [line.strip() for line in log.read_text(encoding="utf-8").splitlines()]
        receipt["passed_tests"] = passed if args.suite == 'checkpoint' else [line.split()[2] for line in lines if line.startswith("--- PASS:")]
        receipt["skipped_tests"] = skipped if args.suite == 'checkpoint' else [line.split()[2] for line in lines if line.startswith("--- SKIP:")]
    if args.suite == 'checkpoint':
        receipt['sdk_test_cases'] = len(cases)
        receipt['sdk_passed_count'] = len(passed)
    if args.suite == 'scale':
        measurement = SCALE_EVIDENCE
        if measurement.is_file():
            metrics = json.loads(measurement.read_text(encoding='utf-8'))
            receipt['scale_metrics'] = {key: metrics[key] for key in (
                'users', 'role_bindings', 'resource_grants', 'concurrency',
                'samples_per_operation', 'list_p95_ms', 'decision_p95_ms', 'passed')}
    expected = 0 if args.suite == 'platform-all-go' else 5 if args.suite == 'index' else 7 if args.suite == 'source' else (15 if args.suite == 'knowledge' else 11)
    if args.retrieval_cache:
        expected = 2
    if args.answer_cache:
        expected = 4
    if args.suite == 'identity':
        expected = 5
        if args.administrator_scopes:
            expected = len(ADMINISTRATOR_SCOPE_REQUIRED_TESTS)
    if args.suite in {'administration','checkpoint'}:
        expected = 1
    if args.suite == "schema":
        expected = 4
    if args.suite in {"capability", "capability-recovery"}:
        expected = 7 if args.suite == "capability-recovery" else 6
    if args.suite == "capability-billing":
        expected = 3
    if args.suite == "erasure-audit":
        expected = 4
    if args.suite == "platform-ports":
        expected = 4
    if args.suite == "process":
        expected = 1 if args.evaluation_restart else 2
    if args.suite == "maintenance":
        expected = 1
    if args.suite == "kafka":
        expected = 1
    if args.suite == "scale":
        expected = 1
    if args.suite == "evaluation":
        expected = 3 if args.rag_evaluation else 2
        if args.real_rag_metrics: expected = 1
    if args.suite == "conversation":
        expected = 6
    if args.suite == "policy":
        expected = 2
    if args.suite == "models":
        expected = 3
    if args.suite == "execution":
        expected = 5
    if args.suite == "execution-recovery":
        expected = 7
    if args.suite == "identity-full":
        expected = 44
    if args.suite == "tree-budget":
        expected = 5
    if args.suite == "usage":
        expected = 7
    if args.function_calling: expected = 6
    if args.business_state: expected = 11
    if args.tool_approval: expected = 9
    if args.runtime_observation: expected = 13
    if args.skill_transactions: expected = 8
    if args.suite == 'platform-all-go':
        sdk_summary = receipt.get('sdk_checkpoint_postgres', {})
        required_go_names = (GO_WORKER_DIAGNOSTIC_REQUIRED_TESTS if args.go_test_pattern == GO_WORKER_DIAGNOSTIC_PATTERN else
                             GO_AFFECTED_REQUIRED_TESTS if args.go_test_pattern else GO_GOVERNED_BILLING_REQUIRED_TESTS + GO_PERMISSION_AUTHENTICATION_REQUIRED_TESTS)
        required_go_states = receipt.get('required_go_test_states', {})
        required_go_ok = (set(required_go_states) == set(required_go_names) and
                          all(status == 'pass' for status in required_go_states.values()))
        sdk_ok = (sdk_summary.get('status') == 'not_selected' if args.go_test_pattern else
                  sdk_summary.get('exit_code') == 0 and sdk_summary.get('test_count') == 1 and
                  sdk_summary.get('passed_count') == 1 and sdk_summary.get('failed_count') == 0 and
                  sdk_summary.get('error_count') == 0 and sdk_summary.get('skipped_count') == 0)
        receipt['tests_passed'] = (process.returncode == 0 and not receipt['failed_tests'] and
                                   required_go_ok and
                                   isinstance(receipt.get('postgres_host_auth'), dict) and
                                   receipt['postgres_host_auth'].get('incorrect_tcp_password_rejected') is True and
                                   sdk_ok and
                                   'private_go_jsonl' in receipt)
        receipt['test_suite_status'] = ('passed_with_skips' if receipt['tests_passed'] and receipt['go_json_summary']['counts']['skipped'] else
                                        'passed' if receipt['tests_passed'] else 'failed')
    else:
        receipt["tests_passed"] = process.returncode == 0 and len(receipt["passed_tests"]) >= expected and not receipt["skipped_tests"]
    if args.live_models:
        live_proof = receipt.get(example_language+'_platform_flow',{}) if external_example_process else receipt.get('live_model_rag',{})
        receipt['tests_passed'] = receipt['tests_passed'] and live_proof.get('result') == 'PASS' and (not external_example_process or live_proof.get('external_models') is True)
        receipt['real_model_calls'] = True
    if args.answer_cache_process:
        receipt['tests_passed'] = receipt['tests_passed'] and receipt.get('public_answer_cache',{}).get('result') == 'PASS'
    if args.suite == 'knowledge':
        required = {'TestPostgresKnowledgeQueryBackend', 'TestCurrentKnowledgeSourceIntersectsCallerMachineAndPublication', 'TestPostgresGovernedQueryPipeline', 'TestPostgresMetadataFilteringBeforeVectorLimit', 'TestPostgresFinalAuthorityRecheckDoesNotLeakContent', 'TestPostgresRetrievalCacheFreshBodiesAndVersionFences'}
        if args.retrieval_cache:
            required = {'TestPostgresKnowledgeQueryBackend', 'TestPostgresRetrievalCacheFreshBodiesAndVersionFences'} | {'TestPostgresRetrievalCacheFreshBodiesAndVersionFences/' + mode for mode in ('hit','generation-change','revoke','revoke-after-cache','body-corrupt','scope-change')}
        if args.answer_cache:
            required = {'TestPostgresKnowledgeQueryBackend','TestKnowledgeAnswerRequiresCompleteGovernedReceiptAndKnownCitations','TestSignedKnowledgeAnswerRejectsWholeAnswerWhenEvidenceOrModelIsDenied','TestKnowledgeAnswerHasNoLegacyUngovernedFallback'} | {'TestPostgresKnowledgeQueryBackend/sql-answer-' + mode for mode in ('cache-hit','cache-cold','cache-bypass','cache-model-revoked','cache-generation-change','invalid-citation','source-deleted-during-model')}
        receipt['required_parent_tests'] = sorted(required)
        receipt['tests_passed'] = receipt['tests_passed'] and required.issubset(receipt['passed_tests'])
    if args.suite == 'identity':
        required = {'TestSQLRefreshSessionLifecycle', 'TestSQLPermissionChangeAtomicRetryAndStalePlan', 'TestSQLAdministratorAuthenticationAndContinuity', 'TestSQLOIDCBindingFollowsCurrentIAMState', 'TestSQLAuthorizationEpochTracksIAMAndRejectsRevocation'}
        if args.administrator_scopes:
            required = ADMINISTRATOR_SCOPE_REQUIRED_TESTS
        if args.company_administration:
            required = {'TestSQLCompanyAdministratorAppointmentAndBoundaries', 'TestSQLCompanyAdministratorLifecycleAndRevocation', 'TestSQLCompanyAdministratorOIDCDelegationAndRevocation', 'TestCompanyAdministratorScopeAndDelegationQualification', 'TestSQLAdministratorAuthenticationAndContinuity', 'TestSQLAdministratorWorkspacesFollowLiveAuthority', 'TestSQLAdministratorsCannotAddOwnBusinessAuthority', 'TestSQLDepartmentAdministratorMembershipAndAgentBoundary'}
        if args.department_agent_access:
            required = DEPARTMENT_AGENT_REQUIRED_TESTS
        if args.permission_batches:
            required = PERMISSION_BATCH_REQUIRED_TESTS
        receipt['required_parent_tests'] = sorted(required)
        receipt['tests_passed'] = receipt['tests_passed'] and required.issubset(receipt['passed_tests'])
        receipt['identity_sql'] = True
        receipt['platform_http_live'] = False
    required_by_suite = {
        'index': {'TestPostgresIndexKnowledgeManagementControl', 'TestPostgresIndexPersistentCheckpointExecutionFence', 'TestPostgresIndexCheckpointRestorePreservesWorkAndCAS', 'TestPostgresIndexFullIncrementalReuseAndDeletion','TestPostgresIndexCompletenessCancellationAndRollback','TestPostgresIndexSourceFenceCASAndAuditRollback','TestPostgresIndexConfigurationScopeAndEventContinuity'},
        'source': {'TestPostgresSourceSelectedCurrentSnapshot', 'TestPostgresSourceHistoricalSnapshotsForRecovery', 'TestPostgresSourceVersionsACLAndTombstones','TestPostgresSourceAuditRollbackAndRetry','TestPostgresSourceConcurrentReplayAndCAS','TestPostgresSourceCommitOrderAndSnapshot','TestPostgresSourceContinuityAndScope','TestPostgresSourceRequiresRecorderAndDMLOnly'},
        'scale': {'TestSQLPermissionScaleAcceptance'},
        'kafka': {'TestSQLKafkaAuthorizationEventsAtomicAndDurableReplay'},
        'maintenance': {'TestSQLMigrationMappingCLIUsesSelectOnlyAndRejectsChangedSource'},
        'process': {'TestSQLRealPlatformProcessStartsWithDMLAndRejectsBadSchema','TestSQLRealPlatformProcessStartsWithDMLAndRejectsBadSchema/knowledge-index-worker','TestSQLRealPlatformProcessStartsWithDMLAndRejectsBadSchema/knowledge-index-worker/go-example-platform-flow','TestSQLModelObservationUpdatesHealthAndCapacityWithRevision'},
        'identity-full': {'TestSQLPermissionPrincipalDirectoryScopesAndValidity', 'TestSQLWorkloadBindingCASAuditRetryAndRevocation', 'TestSQLMembershipRemovalRetainsOtherCoverageAndRejectsStaleCAS', 'TestSQLTaskAssignmentNaturalValidityPersistsEpoch', 'TestSQLOIDCStepUpChallengeBindingAndFreshness', 'TestSQLPermissionRequestTwoAdministratorsOnlyOneSubsetCommits', 'TestSQLStorePasswordChangeFailsClosedWithoutAtomicRecorder', 'TestSQLMigrationSourcesPreserveProtectedFactsAndDetectUnversionedChanges', 'TestSQLAdministratorAuthenticationAndContinuity', 'TestSQLDelegationPreviewValidatesCurrentBoundaryWithoutWrites', 'TestSQLEnrollmentRejectionTemporaryDelegation', 'TestSQLTaskAssignmentDelegationAndInputBoundary', 'TestSQLPermissionChangeAtomicRetryAndStalePlan', 'TestSQLOIDCStepUpAuditRollbackAndExpirationCleanup', 'TestSQLAuthorizationEpochScopeShrinkRevocationAndOutageNeverReturnOldVersion', 'TestSQLPermissionRequestWithdrawalAndDecisionRace', 'TestSQLTaskAssignmentAtomicCASIdempotencyAndRevocation', 'TestSQLPermissionExplanationTrustedObjectsAndExistenceBoundary', 'TestSQLEnrollmentRejection', 'TestSQLDelegationRevocationFencesPendingAuthorization', 'TestSQLScopedMachineCredentialLifecycle', 'TestSQLRefreshSessionLifecycle', 'TestSQLPermissionRequestsSubsetAndAtomicAudit', 'TestSQLPermissionPrincipalCreation', 'TestSQLCapabilityResourceRequestApprovalAndRevocation', 'TestSQLLegacyPermissionRequestImportPreservesSourceAndUsesNewApproval', 'TestSQLPresetChangeRetainsOtherApplicationAndRejectsPartialDelegation', 'TestSQLOIDCStepUpAppointmentAndOneUse', 'TestSQLWorkspaceSwitchAndRefresh', 'TestSQLPermissionExplanationSelfAdministratorScopeAndOutage', 'TestSQLMachineProtocolVersionedActionsAndLiveObjectScope', 'TestSQLPermissionWorkloadCreationAtomicUnprivilegedAndRetry', 'TestSQLPermissionRequestsBoundaryAndRejection', 'TestSQLOIDCBindingFollowsCurrentIAMState', 'TestSQLLegacyPermissionRequestImportConcurrentAndDisabledSubject', 'TestSQLAuthorizationEpochTracksIAMAndRejectsRevocation', 'TestSQLLegacyAuthenticationImportAndVerifiedExistingAdministrator', 'TestSQLAuthorizationEpochTracksNaturalV2BoundariesWithAlternativeAllow', 'TestSQLLegacyRequestMigrationPlanIsReadOnlyAndRejectsChangedSource', 'TestSQLOIDCStepUpRevocationAndQualification', 'TestSQLMembershipRemovalPreservesDenyAndPreventsRejoinRevival', 'TestSQLMigrationResourcesValidateOwnershipAndRejectConcurrentSourceChange', 'TestSQLEnrollmentApprovalAndRejectionRace', 'TestSQLEnrollmentPermissionApproval', 'TestSQLMigrationMappingCommitPreservesSourceAndRollsBack'},
        'platform-ports': {'TestSQLDepartmentAgentCeilingActualCatalogAuditOutboxAndRuntime', 'TestSQLNotificationGuardLossRollsBackOutbox', 'TestSQLAuthorizationAdministrationVersionAndLifecycleAtomic', 'TestSQLNotificationCommitReceiptSurvivesReopenAndRejectsTampering', 'TestSQLCatalogReleaseActualIAMAndAuditOutbox'},
        'erasure-audit': {'TestSQLConversationErasureRecoveryAndAtomicPayloadDeletion', 'TestSQLDeletionReviewFiltersBeforePaginationAndRollsBackDeniedCommit', 'TestSQLAuditNotificationPortAtomicity', 'TestSQLAuditMetadataScopeIsolationAndPagination'},
        'execution-recovery': {'TestSQLDispatcherHeartbeatStopsAfterDatabaseRenewalFault', 'TestSQLRecoveryStopBarrierRollsBackAndRetainsResume', 'TestPersistentSessionLeaseSQLOrdering', 'TestSQLDualDispatcherFencesLeaseAndReadsLatestResume', 'TestSQLConcurrentDispatchersOnlyInvokeOnce', 'TestSQLRecoverySnapshotReadsPersistedStates', 'TestPersistentSessionLeaseSQLRestartAndHeartbeatRollback'},
        'capability-billing': {'TestSQLBillingRecoveryRetainsHoldAndReplaysAfterRestart', 'TestSQLUnsentProofSurvivesPartialRelease', 'TestSQLBillingManualDecisionAuditAndCompensation'},
        'capability-recovery': {'TestSQLPreparationRecoveryConcurrentBoundedBatches', 'TestSQLPreparingCrashRecoveryFencesStaleAttempt', 'TestToolRenewalOwnership', 'TestSQLToolLeaseContendersAndReopenFencing', 'TestSQLBillingRecoveryCorruptRowIsIsolated', 'TestSQLPreparedModelSendSurvivesTTLAndReopen', 'TestSQLToolWorkerRecoversWithoutClientRetryAfterReopen'},
        'checkpoint': {'test_checkpoint_postgres_roles_upgrade_and_resume'},
        'administration': {'TestFirstAdministratorPostgres'},
        'schema': {'TestPostgresDelegationAuthorityMarkerUpgradesFromModelUsageStep', 'TestPostgresDelegationAuthorityMarkerUpgradesFromPermissionCatalogV2', 'TestPostgresMigrationCommandCompleteBundleAndReplay/company_administration_catalog_upgrade_preserves_assignments', 'TestPostgresMigrationCommandCompleteBundleAndReplay/department_Agent_ceiling_upgrade_preserves_existing_authority', 'TestPostgresMigrationCommandCompleteBundleAndReplay/permission_batch_upgrade_preserves_department_ceilings', 'TestPostgresSchemaNativePredecessorUpgrade', 'TestPostgresSchemaConcurrentMigrationAndDrift', 'TestPostgresSchemaBundleRollbackAndRetry', 'TestPostgresSchemaRejectsLegacyLineage', 'TestPostgresRuntimePrivilegesEffectiveGrants', 'TestPostgresMigrationCommandCompleteBundleAndReplay'},
        'capability': {'TestSQLMemoryExpiryCleanupPreservesConcurrentRefresh', 'TestSQLMemoryWriteContinuityWithPrincipalRevocation', 'TestToolInvocationFailedAttemptCanRetryPostgresIntegration', 'TestGovernedModelBillingPostgresIntegration', 'TestGovernedEmbeddingBillingPostgresIntegration', 'TestGovernedKnowledgeEmbeddingBillingPostgresIntegration', 'TestSQLToolCommitGuardRejectsMissingForgedAndExpiredProof', 'TestSQLMemoryConcurrentQuotaCannotOverrun'},
        'evaluation': {'TestEvaluationLeasePostgresIntegration', 'TestSQLSuccessfulFinalizationFailureRecoversWithoutDuplicateInvocation'},
        'models': {'TestSQLProviderPostgresIntegration', 'TestPostgresGovernanceConcurrentPriceIntervals', 'TestPostgresGovernanceDeploymentCapacityAtomicity'},
        'policy': {'TestSQLKnowledgeDocumentBindingsRoundTripAndIsolation', 'TestSQLPreparedPublicationPersistsSixPoliciesAndMatchesExactRetry'},
        'conversation': {'TestSQLConversationInstallationProvenance', 'TestSQLConversationConcurrentRevisionAndRegeneration', 'TestSQLProjectionUTF8AndLongReplay', 'TestSQLConversationExportCompletenessAndRollback', 'TestSQLRetentionAndLegalHoldSerializeOnSession', 'TestSQLRetentionSweepLimitSkipsUnexpiredOlderSession'},
        'tree-budget': {'TestSQLRunTreeBudgetConcurrentRootAndChildReservationsShareLimitAndReplay', 'TestSQLRunTreeBudgetUnknownKeepsHoldAndRejectsReleaseWithoutProviderReceipt', 'TestSQLRunTreeBudgetSettlesActualOverestimateOnceAndBlocksAdmission', 'TestSQLRunTreeBudgetAuditFailureRollsBackReservationAndRejectsMissingAudit', 'TestSQLRunTreeBudgetRejectsCrossUserAndWrongRootFacts', 'TestSQLRunTreeBudgetDenialDiagnosticIsSafeAndNonMutating'},
        'usage': {'TestSQLUsageLegacyBrowserBoundaryAndAuthorizedBudget', 'TestSQLUsageConcurrentFirstEventsRemainExactlyOnce', 'TestSQLModelBudgetLedgerTransactionalLifecycle', 'TestSQLModelBudgetConcurrentReservationsCannotOverrunWindow', 'TestSQLModelBudgetReleaseIsIdempotentAndAgentScopesAreIsolated', 'TestSQLModelBudgetExpiryReclaimsLeaseExactlyOnce', 'TestSQLModelBudgetReconciliationHoldSurvivesLeaseExpiryAndSettles'},
        'execution': {'TestSQLCancellationIntentAndOutcomeFaultRecovery', 'TestSQLProjectionKeysetFairness', 'TestSQLAtomicCreationAndOutcomeFaultRecovery', 'TestSQLProjectionOutageRecoversWithoutAgentExecution', 'TestSQLConcurrentCreationReplaysSingleWinner', 'TestSQLTaskCheckpointLeaseTransactionFence', 'TestSQLControllerStopEvidenceAtomicAuditAndCAS'},
    }
    if args.suite in required_by_suite:
        required = required_by_suite[args.suite]
        if args.administrator_scopes:
            required = ADMINISTRATOR_SCOPE_REQUIRED_TESTS
        if args.suite == 'tree-budget':
            required_cases = {'TestSQLRunTreeBudgetDenialDiagnosticIsSafeAndNonMutating/' + name for name in ('cost', 'tokens', 'both')}
            receipt['required_sql_cases'] = sorted(required_cases)
            receipt['tests_passed'] = receipt['tests_passed'] and required_cases.issubset(receipt['passed_tests'])
        if args.tool_approval:
            required = {'TestToolConfirmationBindsApprovalToExactOperation', 'TestSignedToolGatewayRequiresConfirmationAndStillRechecksIAM', 'TestSQLToolApprovalRevocationAndAuditAtomicity', 'TestSQLToolStepUpExactActionAndTransaction', 'TestSQLOIDCToolStepUpExactSessionAndOperation', 'TestSQLOIDCToolStepUpMembershipRevocation', 'TestPostgresMigrationCommandCompleteBundleAndReplay', 'TestPostgresToolApprovalHTTPUsesRealSessionIAMAndStepUp', 'TestPostgresToolApprovalHTTPOIDCOnly'}
            required |= {'TestSQLOIDCToolStepUpExactSessionAndOperation/' + action for action in ('tool.approval.approve', 'tool.approval.revoke')}
            required |= {'TestPostgresToolApprovalHTTPOIDCOnly/' + case for case in ('same-user-other-login-cannot-consume-proof', 'proof-does-not-grant-tool-permission', 'changed-claims-cannot-use-proof', 'audit-failure-rolls-back-approve-and-proof-consumption', 'audit-failure-rolls-back-revoke-and-proof-consumption')}
        if args.function_calling:
            required = {'TestGovernedFunctionBillingPostgresIntegration',
                        'TestInvalidFunctionBillingPostgresIntegration',
                        'TestToolInvocationFailedAttemptCanRetryPostgresIntegration',
                        'TestMCPActualHTTPDiscoverySchemaPinAndInvocation',
                        'TestMCPUncertainReceiptDoesNotRetryRemoteSideEffect', 'TestModelReadOnlyReceiptDoesNotCreateInvocationOrChangeSpend'}
        if args.business_state:
            required = {'TestCheckpointRecoveryKeyKeepsIdentityAndVersionBoundary',
                        'TestCheckpointContentHashPreservesLargeNumbersAndSchema',
                        'TestCheckpointRejectsUnboundedOrAmbiguousDocuments',
                        'TestCheckpointMaintenanceStartsOnceAndStopsWithModule',
                        'TestSQLBusinessCheckpointCASRecoveryAndAuthority',
                        'TestSQLTaskCheckpointLeaseTransactionFence',
                        'TestPostgresMigrationCommandCompleteBundleAndReplay',
                        'TestContextWindowPreservesSystemLatestTurnAndToolPairs',
                        'TestContextSummaryIsBoundedUntrustedAndDeterministic',
                        'TestContextRejectModeAndOversizedCurrentTurnFailClosed',
                        'TestModelInputLimitRejectsBeforeProviderOrBudget'}
            required_cases = {
                'TestSQLBusinessCheckpointCASRecoveryAndAuthority/recovery-checkpoint-snapshot/renewal-reference-allows-only-exact-live-history',
                'TestSQLBusinessCheckpointCASRecoveryAndAuthority/expired-payload-pruning-preserves-lineage',
                'TestSQLBusinessCheckpointCASRecoveryAndAuthority/actual-iam-disabled-principal-cannot-replay-state',
            }
            receipt['required_sql_cases'] = sorted(required_cases)
            receipt['tests_passed'] = receipt['tests_passed'] and required_cases.issubset(receipt['passed_tests'])
        if args.runtime_observation:
            required = {'TestRuntimeObservationSanitizesBoundsAndReplaysOriginalReceipt',
                        'TestRuntimeObservationRejectsStoredScopeTampering',
                        'TestRuntimeObservationSignedReplayRechecksResourceBeforeDisclosure',
                        'TestRuntimeObservationFailureDoesNotClaimUnknownEffectRolledBack',
                        'TestRuntimeObservationHandlesLegacyTimingAndCyclicOutputs',
                        'TestRuntimeObservationPostgresReceiptReopenPrecisionAndIsolation',
                        'TestRuntimeObservationReadOnlyReceiptDoesNotExecute',
                        'TestRuntimeObservationSignedReceiptRechecksPermissionBeforeReturn',
                        'TestRuntimeObservationDispatcherFreezesRegistrationAndRejectsUnsafeExecutors',
                        'TestRuntimeObservationDispatcherCompositionPreservesAllProviders',
                        'TestRuntimeObservationDispatcherBoundsTimeAndRejectsInvalidScope',
                        'TestRuntimeObservationWriteRiskRequiresApprovalEvenWhenPolicyOmitsIt',
                        'TestRuntimeToolAuditLedgerOutboxAtomicityPostgres'}
        if args.skill_transactions:
            parent = 'TestSQLSkillModelValidationCallerTransactionPostgres'
            required = {parent}
            required_cases = {parent + '/' + name for name in (
                'success_reuses_locked_run_transaction_and_outer_rollback',
                'scope_mismatch_rejected',
                'database_mismatch_rejected',
                'operation_error_rolls_back_owned_transaction',
                'fence_failure_skips_operation',
                'progressive_disclosure_and_current_dependency_revocation',
                'revoked_version_blocks_existing_pin_without_rewriting_it',
            )}
            receipt['required_sql_cases'] = sorted(required_cases)
            receipt['tests_passed'] = receipt['tests_passed'] and required_cases.issubset(receipt['passed_tests'])
        if args.suite == 'identity-full':
            required |= {
                'TestSQLAuthorizationChangeInvalidatesStepUpAtomically',
                'TestSQLAuthorizationChangeInvalidatesStepUpAtomically/local',
                'TestSQLAuthorizationChangeInvalidatesStepUpAtomically/oidc',
            }
        if args.local_admin_bootstrap:
            required = {'TestFirstAdministratorLocalPasswordPostgres'}
        if args.real_rag_metrics:
            required = {'TestSQLRealFrozenRAGMetricServiceEvidence'} | {'TestSQLRealFrozenRAGMetricServiceEvidence/'+name for name in ('supported','fabricated-source','unknown-reference','wrong-revision')}
        if external_example_process:
            required = (required-{'TestSQLRealPlatformProcessStartsWithDMLAndRejectsBadSchema/knowledge-index-worker/go-example-platform-flow'}) | {'TestSQLRealPlatformProcessStartsWithDMLAndRejectsBadSchema/knowledge-index-worker/'+example_language+'-example-platform-flow'}
            receipt['tests_passed'] = receipt['tests_passed'] and receipt.get(example_language+'_platform_flow',{}).get('result') == 'PASS'
        if args.checkpoint_agent_process:
            required = (required - {'TestSQLRealPlatformProcessStartsWithDMLAndRejectsBadSchema/knowledge-index-worker', 'TestSQLRealPlatformProcessStartsWithDMLAndRejectsBadSchema/knowledge-index-worker/go-example-platform-flow'}) | {'TestSQLRealPlatformProcessStartsWithDMLAndRejectsBadSchema/checkpoint-agent-process-recovery'}
        if args.evaluation_restart:
            required = {'TestSQLRealPlatformProcessStartsWithDMLAndRejectsBadSchema', 'TestSQLRealPlatformProcessStartsWithDMLAndRejectsBadSchema/evaluation-seed-process-restart'}
            receipt['original_evaluation_seed_executed'] = any('original_restart_seed_test=PASS' in line for line in lines)
            receipt['actual_evaluation_process_restart'] = any('actual_platform_restart_recovered_original_seed=PASS' in line for line in lines)
            receipt['tests_passed'] = receipt['tests_passed'] and receipt['original_evaluation_seed_executed'] and receipt['actual_evaluation_process_restart']
        if args.rag_evaluation:
            required = required | {'TestSQLIndependentRAGGroundingEvidence','TestSQLIndependentRAGGroundingEvidence/OK','TestSQLIndependentRAGGroundingEvidence/UNKNOWN','TestSQLIndependentRAGGroundingEvidence/BLOCKED'}
        receipt['required_parent_tests'] = sorted(required)
        receipt['tests_passed'] = receipt['tests_passed'] and required.issubset(receipt['passed_tests'])
    receipt["ddl_identity_separate"] = True
    receipt["real_postgresql"] = True
    if args.business_state:
        receipt['checkpoint_renewal_exact_history_sql'] = 'TestSQLBusinessCheckpointCASRecoveryAndAuthority/recovery-checkpoint-snapshot/renewal-reference-allows-only-exact-live-history' in receipt['passed_tests']
        receipt['checkpoint_principal_lifecycle_sql'] = 'TestSQLBusinessCheckpointCASRecoveryAndAuthority/actual-iam-disabled-principal-cannot-replay-state' in receipt['passed_tests']
        receipt['checkpoint_retention_sql'] = 'TestSQLBusinessCheckpointCASRecoveryAndAuthority/expired-payload-pruning-preserves-lineage' in receipt['passed_tests']
    live_call_count = receipt.get(example_language+'_platform_flow',{}).get('model_invocations',0) if external_example_process else receipt.get('live_model_rag',{}).get('external_model_invocations_settled',0)
    receipt["real_model_calls"] = (True if live_call_count > 0 else None) if args.live_models else False
    receipt["live_model_mode"] = args.live_models
    receipt["live_iam"] = args.suite == "process"
    if args.checkpoint_agent_process:
        recovered = 'TestSQLRealPlatformProcessStartsWithDMLAndRejectsBadSchema/checkpoint-agent-process-recovery' in receipt['passed_tests']
        receipt['actual_checkpoint_process_recovery'] = recovered
        receipt['live_iam'] = recovered
        receipt['actual_linux_platform_executable'] = recovered
        receipt['platform_http_live'] = recovered
        receipt['platform_executable_built_with_race_detector'] = recovered
    if focused_knowledge_cache:
        backend_cases = {'TestPostgresKnowledgeQueryBackend/' + mode for mode in ('sql-success','sql-machine-revoked-during-rerank','sql-caller-revoked-during-rerank','sql-machine-expired-during-rerank','sql-caller-expired-during-rerank','sql-machine-denied-before-model','sql-cache-hit','sql-cache-caller-model-revoked','sql-cache-machine-model-revoked','sql-cache-cold','sql-cache-bypass','sql-cache-invalid')}
        receipt['retrieval_cache_current_sql_iam_and_modes_verified'] = backend_cases.issubset(receipt['passed_tests'])
        receipt['tests_passed'] = receipt['tests_passed'] and receipt['retrieval_cache_current_sql_iam_and_modes_verified']
    if args.suite == 'knowledge' and not focused_knowledge_cache:
        sql_iam_cases = {'TestPostgresKnowledgeQueryBackend/sql-success', 'TestPostgresKnowledgeQueryBackend/sql-machine-revoked-during-rerank', 'TestPostgresKnowledgeQueryBackend/sql-caller-revoked-during-rerank', 'TestPostgresKnowledgeQueryBackend/sql-machine-expired-during-rerank', 'TestPostgresKnowledgeQueryBackend/sql-caller-expired-during-rerank', 'TestPostgresKnowledgeQueryBackend/sql-machine-denied-before-model'}
        receipt['knowledge_query_backend_real_sql_iam'] = sql_iam_cases.issubset(receipt['passed_tests'])
        cache_cases = {'TestStageCacheConcurrentLoadsAndDetachedValues', 'TestStageCacheExpiryEvictionAndFailure', 'TestStageCacheCancellationDoesNotPoisonWaiters', 'TestCachedQueryModelsCurrentPermissionAndVersionBoundaries', 'TestPostgresKnowledgeQueryBackend/sql-cache-hit', 'TestPostgresKnowledgeQueryBackend/sql-cache-caller-model-revoked', 'TestPostgresKnowledgeQueryBackend/sql-cache-machine-model-revoked'}
        receipt['knowledge_query_rewrite_embedding_cache_verified'] = cache_cases.issubset(receipt['passed_tests'])
        receipt['knowledge_query_rewrite_embedding_reranking_cache_verified'] = receipt['knowledge_query_rewrite_embedding_cache_verified'] and 'TestCachedQueryModelsInvalidRerankingIsNeverCached' in receipt['passed_tests']
        receipt['tests_passed'] = receipt['tests_passed'] and receipt['knowledge_query_rewrite_embedding_reranking_cache_verified']
        receipt['knowledge_query_different_question_embedding_reuse_verified'] = 'TestPostgresKnowledgeQueryBackend/sql-cache-rewritten-query-reuse' in receipt['passed_tests']
        receipt['knowledge_query_cache_modes_verified'] = {'TestPostgresKnowledgeQueryBackend/sql-cache-cold','TestPostgresKnowledgeQueryBackend/sql-cache-bypass','TestPostgresKnowledgeQueryBackend/sql-cache-invalid'}.issubset(receipt['passed_tests'])
        receipt['index_embedding_worker_batches_and_resume_verified'] = {'TestPostgresIndexEmbeddingWorkerCheckpointAndResume','TestPostgresIndexEmbeddingWorkerCheckpointAndResume/resume','TestPostgresIndexEmbeddingWorkerCheckpointAndResume/canceled','TestPostgresIndexEmbeddingWorkerCheckpointAndResume/source-changed','TestPostgresIndexEmbeddingWorkerCheckpointAndResume/invalid-version','TestPostgresIndexEmbeddingWorkerCheckpointAndResume/invalid-vector','TestPostgresIndexEmbeddingWorkerCheckpointAndResume/invalid-count','TestPostgresIndexEmbeddingWorkerCheckpointAndResume/oversized','TestIndexEmbeddingsUsePublishedGovernedBatchCallback','TestIndexEmbeddingWorkerBoundsSerializedBatchBytes'}.issubset(receipt['passed_tests'])
        receipt['tests_passed'] = receipt['tests_passed'] and receipt['index_embedding_worker_batches_and_resume_verified']
        receipt['index_build_and_publication_replay_verified'] = {'TestPostgresIndexBuildReplayVerifiesImmutableContent','TestPostgresIndexPublicationReplayPreservesFenceAndAudit','TestPostgresIndexPublicationReplayRechecksAfterLocks'}.issubset(receipt['passed_tests'])
        receipt['tests_passed'] = receipt['tests_passed'] and receipt['index_build_and_publication_replay_verified']
        receipt['index_task_driver_durable_stage_recovery_verified'] = {'TestPostgresIndexTaskDriverRestartsFromDurableStages','TestPostgresIndexTaskDriverRestartsFromDurableStages/model-outage','TestPostgresIndexTaskDriverRestartsFromDurableStages/publication-ack-lost','TestPostgresIndexTaskDriverRestartsFromDurableStages/canceled-after-publication'}.issubset(receipt['passed_tests'])
        receipt['tests_passed'] = receipt['tests_passed'] and receipt['index_task_driver_durable_stage_recovery_verified']
        receipt['tests_passed'] = receipt['tests_passed'] and receipt['knowledge_query_cache_modes_verified']
        receipt['tests_passed'] = receipt['tests_passed'] and receipt['knowledge_query_different_question_embedding_reuse_verified']
        receipt['tests_passed'] = receipt['tests_passed'] and receipt['knowledge_query_rewrite_embedding_cache_verified']
        receipt['knowledge_query_backend_sql_iam_scope'] = 'Actual SQL principals, v2 roles/memberships/grants, workload binding, credential and run authorization epoch; model callback and source/publish audit recorders remain fixtures; no signed HTTP execution in this case'
        receipt['tests_passed'] = receipt['tests_passed'] and receipt['knowledge_query_backend_real_sql_iam']
    if args.suite in {'index','knowledge'} and not focused_knowledge_cache:
        composition_cases = {'TestPostgresIndexTaskCompositionUsesLiveIAMLeaseAndAudit'} | {'TestPostgresIndexTaskCompositionUsesLiveIAMLeaseAndAudit/'+mode for mode in ['allowed','supervised','scheduled','admission-service','admission-billing','issued-index','cancel-service','cancel-running','cancel-settlement','stop-recovery','admission-tx','command-tx','manager-revoked','model-denied','model-no-rows','canceled','batch-manager-revoked','batch-model-revoked','batch-source-changed','audit-fault','publication-fault','wrong-task']}
        receipt['index_task_real_sql_iam_lease_audit_outbox_composed'] = composition_cases.issubset(receipt['passed_tests'])
        receipt['index_signed_context_sql_workload_model_grants_verified'] = 'TestPostgresIndexTaskCompositionUsesLiveIAMLeaseAndAudit/admission-service' in receipt['passed_tests']
        receipt['index_signed_sql_model_billing_verified'] = 'TestPostgresIndexTaskCompositionUsesLiveIAMLeaseAndAudit/admission-billing' in receipt['passed_tests']
        receipt['index_full_signed_sql_execution_verified'] = 'TestPostgresIndexTaskCompositionUsesLiveIAMLeaseAndAudit/issued-index' in receipt['passed_tests']
        receipt['index_full_signed_sql_execution_scope'] = 'Actual management admission, persisted command, fresh signed task contexts, SQL caller/machine model authority, guarded loopback HTTP embedding, SQL billing, checkpoint, source-fenced index publication, audit/outbox and successful outcome. Catalog/published-policy/selection metadata remain fixtures; not a live external provider.'
        receipt['index_signed_sql_model_billing_scope'] = 'Actual signed context and SQL caller/machine IAM, approved provider/model/price, capacity, invocation, budget and usage ledgers with guarded loopback HTTP embeddings. Catalog target/policy and selection metadata are fixtures; not a live provider or complete index-worker acceptance.'
        receipt['index_signed_context_sql_scope'] = 'Real Ed25519/HMAC, persisted command and execution lease, SQL management-only caller epoch, machine credential/binding and independent model grants with revocation. Catalog target, published policy and approved model selection remain fixtures; no model sends/billing in this case.'
        receipt['tests_passed'] = receipt['tests_passed'] and receipt['index_task_real_sql_iam_lease_audit_outbox_composed']
        receipt['index_task_composition_scope'] = 'Actual SQL Identity management authorization, execution lease, durable checkpoint, formal audit and Outbox; model callbacks are fixtures. Internal factory, not production scheduler/API or live signed provider indexing.'
    if args.suite == 'index':
        receipt['knowledge_management_real_sql_iam_and_audit_outbox'] = 'TestPostgresIndexKnowledgeManagementControl' in receipt['passed_tests']
        receipt['knowledge_management_public_http_integrated'] = 'TestPostgresIndexKnowledgeManagementControl' in receipt['passed_tests']
        receipt['knowledge_management_http_test_scope'] = 'Real loopback HTTP, SQL IAM and browser session checks; seeded authentication facts, not full frontend password login or real platform subprocess'
    if args.suite == "process" and not args.checkpoint_agent_process: receipt["platform_http_live"] = True
    if args.coverage and receipt['tests_passed']:
        coverage_log = TEMP / 'critical-coverage.log'
        with coverage_log.open('wb') as output:
            coverage = subprocess.run([sys.executable, str(ROOT/'scripts/check_go_coverage.py')], cwd=ROOT,
                                      env=env, stdout=output, stderr=subprocess.STDOUT, timeout=600)
        diagnostic = safe_event_value(coverage_log.read_text(encoding='utf-8', errors='replace'), (password, runtime_password))
        with log.open('a', encoding='utf-8') as output:
            output.write('\n' + diagnostic)
        print(diagnostic, flush=True)
        receipt['critical_coverage_exit_code'] = coverage.returncode
        receipt['critical_coverage_passed'] = coverage.returncode == 0
        receipt['critical_coverage_scope'] = 'All nine critical packages with owned real PostgreSQL; packages run serially; original thresholds unchanged'
        receipt['tests_passed'] = receipt['tests_passed'] and receipt['critical_coverage_passed']
    if not receipt["tests_passed"]:
        print(json.dumps({
            'suite': args.suite,
            'acceptance_failure': {
                'test_exit_code': receipt.get('test_exit_code'),
                'skipped_tests': receipt.get('skipped_tests', []),
                'missing_required_tests': sorted(set(receipt.get('required_parent_tests', [])) -
                                                 set(receipt.get('passed_tests', []))),
                'critical_coverage_passed': receipt.get('critical_coverage_passed'),
            },
        }, ensure_ascii=True), flush=True)
        raise RuntimeError("PostgreSQL suite acceptance failed; see saved log")
except Exception as error:
    # Never dump subprocess stdout/stderr or its credential-bearing environment.
    receipt["failure"] = type(error).__name__ + (": " + str(error) if not isinstance(error, subprocess.CalledProcessError) else ": fixture command failed")
    if 'log' in locals() and log.is_file():
        private_values = [locals().get('password', ''), locals().get('runtime_password', '')]
        private_values.extend(value for key, value in locals().get('env', {}).items()
                              if re.search(r'(?i)password|secret|token|key|dsn|credential', key))
        diagnostic = sanitized_test_tail(log, private_values)
        receipt['test_failure_summary'] = diagnostic
        print('PostgreSQL suite ' + args.suite + ' failed:\n' + diagnostic, flush=True)
finally:
    if args.suite == 'platform-all-go' and 'log' in locals() and log.is_file():
        if 'go_json_summary' not in receipt:
            try:
                receipt['go_json_summary'] = parse_platform_go_jsonl(log)
                receipt['go_json_summary_is_partial'] = True
            except Exception as error:
                receipt['go_json_summary_error'] = type(error).__name__
        if 'private_go_jsonl' not in receipt:
            try:
                private_values = tuple(value for value in (locals().get('password'), locals().get('runtime_password')) if isinstance(value, str))
                receipt['private_go_jsonl'] = persist_private_go_jsonl(log, args.batch_id, OWNER, private_values)
            except Exception as error:
                receipt['private_go_jsonl_error'] = type(error).__name__
    if not docker_access_confirmed:
        receipt['cleanup_errors'].append('Docker daemon access unavailable; absence of containers cannot be verified')
    python_inspect=subprocess.run(['docker','inspect',EXAMPLE_NAME],capture_output=True)
    if python_inspect.returncode==0:
        actual_python=json.loads(python_inspect.stdout)[0]
        if actual_python.get('Config',{}).get('Labels',{}).get('agentplug.test.owner')!=OWNER:
            receipt['cleanup_errors'].append(example_title+' container ownership mismatch')
        else:
            if 'failure' in receipt:
                try:
                    python_log = subprocess.run(['docker','logs','--tail','80',EXAMPLE_NAME], capture_output=True, timeout=15)
                    private_values = [locals().get('password', ''), locals().get('runtime_password', '')]
                    private_values.extend(value for key, value in locals().get('settings', {}).items()
                                          if re.search(r'(?i)password|secret|token|key|dsn|credential', key))
                    diagnostic = safe_event_value((python_log.stdout + python_log.stderr).decode('utf-8', errors='replace'), private_values)[-8000:]
                    receipt[example_language+'_failure_summary'] = diagnostic
                    print('Owned '+example_title+' Agent failure diagnostic:\n' + diagnostic, flush=True)
                except (OSError, subprocess.SubprocessError) as diagnostic_error:
                    receipt[example_language+'_failure_summary'] = 'Agent logs unavailable: ' + type(diagnostic_error).__name__
            if subprocess.run(['docker','rm','--force',EXAMPLE_NAME],capture_output=True).returncode:
                receipt['cleanup_errors'].append('owned '+example_title+' container removal failed')
    receipt['temporary_'+example_language+'_container_removed']=subprocess.run(['docker','inspect',EXAMPLE_NAME],capture_output=True).returncode!=0
    if not receipt['temporary_'+example_language+'_container_removed']:receipt['cleanup_errors'].append('owned '+example_title+' container remains')
    go_inspect = subprocess.run(['docker','inspect',GO_NAME],capture_output=True)
    if go_inspect.returncode == 0:
        actual_go = json.loads(go_inspect.stdout)[0]
        if actual_go.get('Config',{}).get('Labels',{}).get('agentplug.test.owner') != OWNER:
            receipt['cleanup_errors'].append('Go container ownership mismatch')
        elif subprocess.run(['docker','rm','--force',GO_NAME],capture_output=True).returncode:
            receipt['cleanup_errors'].append('owned Go container removal failed')
    receipt['temporary_go_container_removed'] = subprocess.run(['docker','inspect',GO_NAME],capture_output=True).returncode != 0
    if not receipt['temporary_go_container_removed']: receipt['cleanup_errors'].append('owned Go container remains')
    kafka_inspect=subprocess.run(['docker','inspect',KAFKA_NAME],capture_output=True)
    if kafka_inspect.returncode==0:
        actual_kafka=json.loads(kafka_inspect.stdout)[0]
        if actual_kafka.get('Config',{}).get('Labels',{}).get('agentplug.test.owner')!=OWNER:
            receipt['cleanup_errors'].append('Kafka container ownership mismatch')
        elif subprocess.run(['docker','rm','--force','--volumes',KAFKA_NAME],capture_output=True).returncode:
            receipt['cleanup_errors'].append('owned Kafka container removal failed')
    receipt['temporary_kafka_container_removed']=subprocess.run(['docker','inspect',KAFKA_NAME],capture_output=True).returncode!=0
    if not receipt['temporary_kafka_container_removed']:receipt['cleanup_errors'].append('owned Kafka container remains')
    inspect = subprocess.run(["docker", "inspect", NAME], capture_output=True)
    if inspect.returncode == 0:
        actual = json.loads(inspect.stdout)[0]
        if actual.get("Config", {}).get("Labels", {}).get("agentplug.test.owner") != OWNER:
            receipt["cleanup_errors"].append("container ownership mismatch")
        else:
            removed = subprocess.run(["docker", "rm", "--force", NAME], capture_output=True)
            if removed.returncode:
                receipt["cleanup_errors"].append("owned container removal failed")
    receipt["temporary_container_removed"] = subprocess.run(["docker", "inspect", NAME], capture_output=True).returncode != 0
    resolved = TEMP.resolve()
    if resolved.is_relative_to((ROOT / ".tmp").resolve()) and resolved.name == OWNER and not TEMP.is_symlink():
        if TEMP.exists():
            def remove_readonly(function, path, error):
                candidate = Path(path)
                if not candidate.resolve().is_relative_to(resolved) or candidate.is_symlink():
                    raise RuntimeError('refusing cleanup outside owned temporary directory')
                candidate.chmod(stat.S_IREAD | stat.S_IWRITE | (stat.S_IEXEC if candidate.is_dir() else 0))
                # Go module files live in owner-readable, non-writable
                # directories. Unlink/rmdir needs write access on the parent,
                # even when the file itself has already been made writable.
                parent = candidate.parent
                if parent.resolve().is_relative_to(resolved) and not parent.is_symlink():
                    parent.chmod(stat.S_IREAD | stat.S_IWRITE | stat.S_IEXEC)
                function(path)
            try:
                shutil.rmtree(TEMP, onexc=remove_readonly)
            except OSError:
                receipt['cleanup_errors'].append('owned temporary directory removal failed')
    else:
        receipt["cleanup_errors"].append("temporary path ownership mismatch")
    receipt["temporary_credentials_removed"] = not TEMP.exists()
    if not docker_access_confirmed:
        for key in ('temporary_'+example_language+'_container_removed','temporary_go_container_removed','temporary_kafka_container_removed','temporary_container_removed'):
            receipt[key] = None
    receipt["complete"] = receipt.get("tests_passed", False) and not receipt["cleanup_errors"] and receipt["temporary_container_removed"] and receipt["temporary_credentials_removed"]
    basename = basenames[args.suite]
    (EVIDENCE / (basename + '.json')).write_text(json.dumps(receipt, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
print(json.dumps(receipt, ensure_ascii=False))
raise SystemExit(0 if receipt["complete"] else 1)
