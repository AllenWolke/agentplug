// Package schemaversion separates deployment migrations from DML-only startup.
// schemaversion 将部署迁移与只需DML权限的运行期启动分开。
package schemaversion

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/lexagent/platform/internal/sqlutil"
)

// Never edit a released bundle in place: bump the version and append a bundle.
// 已发布迁移不可原地修改；任何Schema变更必须增加版本并保留旧迁移。
const LegacyVersion uint64 = 2026092801

// Immutable checksum of the first released schema bundle.
const legacyReleasedChecksum = "36fda3e649112d6bb44cac424c7a6a7e29a221cc2cc84bde332e8a275fb14985"
const EarlierVersion uint64 = 2026092901
const EarlierManifest = "2026092901:2026092801+evaluation_queue_index,model_budget_reconcile_index"
const PreviousVersion uint64 = 2026092902
const PreviousManifest = "2026092902:2026092901+identity_oidc_binding"
const PermissionPredecessorVersion uint64 = 2026092903
const PermissionPredecessorManifest = "2026092903:2026092902+execution_recovery_index,identity_oidc_binding_revision_updated_at"
const PermissionVersion uint64 = 2026093001
const PermissionManifest = "2026093001:2026092903+identity_versioned_permissions,identity_grant_permission_json"
const RefreshVersion uint64 = 2026093002
const RefreshManifest = "2026093002:2026093001+identity_refresh_family,identity_refresh_token,identity_refresh_oidc_binding"
const StepUpVersion uint64 = 2026093003
const StepUpManifest = "2026093003:2026093002+identity_step_up"
const PermissionRequestVersion uint64 = 2026093004
const PermissionRequestManifest = "2026093004:2026093003+identity_permission_request"
const TaskAssignmentVersion uint64 = 2026093005
const TaskAssignmentManifest = "2026093005:2026093004+identity_task_assignment"
const OIDCStepUpVersion uint64 = 2026093006
const OIDCStepUpManifest = "2026093006:2026093005+identity_oidc_step_up_challenge,identity_oidc_step_up_proof"
const ConversationBindingVersion uint64 = 2026093007
const ConversationBindingManifest = "2026093007:2026093006+conversation_session_installation_id"
const WorkloadBindingVersion uint64 = 2026100101
const WorkloadBindingManifest = "2026100101:2026093007+identity_workload_binding"
const ErasureVersion uint64 = 2026100102
const ErasureManifest = "2026100102:2026100101+conversation_erasure_queue,execution_session_quiescence_index"
const PublicPredecessorVersion uint64 = 2026100103
const PublicPredecessorManifest = "2026100103:2026100102+catalog_submission_provenance"
const PublicVersion uint64 = 2026100201
const PublicManifest = "2026100201:2026100103+generic_public_platform_module_set"
const PostgresInitialVersion uint64 = 2026100202
const PostgresInitialManifest = "2026100202:postgresql-new-lineage+platform-modules+knowledge-pgvector+transactional-ddl"
const PostgresDirectoryVersion uint64 = 2026100301
const PostgresDirectoryManifest = "2026100301:postgresql-new-lineage+platform-modules+knowledge-pgvector+transactional-ddl+membership-directory-index"
const PostgresSourceVersion uint64 = 2026100302
const PostgresSourceManifest = "2026100302:2026100301+knowledge-authoritative-source-versions+commit-ordered-source-outbox"
const PostgresIndexVersion uint64 = 2026100303
const PostgresIndexManifest = "2026100303:2026100302+knowledge-complete-source-bound-index-generation-receipts"
const PostgresCheckpointVersion uint64 = 2026100304
const PostgresCheckpointManifest = "2026100304:2026100303+knowledge-protected-task-checkpoint-cas"
const BusinessStateVersion uint64 = 2026100401
const BusinessStateManifest = "2026100401:2026100304+business-state-versioned-checkpoint-cas"
const ToolApprovalVersion uint64 = 2026100402
const ToolApprovalManifest = "2026100402:2026100401+operation-bound-tool-approval-revocation"
const SkillVersion uint64 = 2026100403
const SkillManifest = "2026100403:2026100402+immutable-skill-versions-release-history-run-pins"
const RouteVersion uint64 = 2026100404
const RouteManifest = "2026100404:2026100403+agent-route-plans-child-reservations"
const RunTreeBudgetVersion uint64 = 2026100405
const RunTreeBudgetManifest = "2026100405:2026100404+run-tree-token-cost-reservations"
const ChildLifecycleVersion uint64 = 2026100406
const ChildLifecycleManifest = "2026100406:2026100405+child-lifecycle-terminal-state-active-scan-index"
const ExecutionPendingVersion uint64 = 2026100407
const ExecutionPendingManifest = "2026100407:2026100406+execution-pending-keyset-scan-index"
const GenerationJournalVersion uint64 = 2026100408
const GenerationJournalManifest = "2026100408:2026100407+execution-generation-claim-dispatch-journal"
const ModelUsageStepVersion uint64 = 2026100409
const ModelUsageStepManifest = "2026100409:2026100408+model-usage-stable-step-id"
const PermissionCatalogV2Version uint64 = 2026100501
const PermissionCatalogV2Manifest = "2026100501:2026100409+identity_skill_user_agent_delegate_v2_role_preset_definitions"
const DelegationAuthorityVersion uint64 = 2026100601
const DelegationAuthorityManifest = "2026100601:2026100501+agent_child_delegation_authority_json,root_machine_authority_stamp"
const CancellationCompensationVersion uint64 = 2026100901
const CancellationCompensationManifest = "2026100901:2026100601+versioned-cancellation-operations+durable-compensation-steps+append-only-compensation-events"
const LocalCompensationVersion uint64 = 2026100902
const LocalCompensationManifest = "2026100902:2026100901+private-local-effect-before-images+atomic-owner-cas-compensation-receipts"
const NotificationReversalVersion uint64 = 2026100903
const NotificationReversalManifest = "2026100903:2026100902+recipient-bound-notification-reversal-receipts+durable-inbox-tombstones"
const CancellationEnrollmentVersion uint64 = 2026100904
const CancellationEnrollmentManifest = "2026100904:2026100903+immutable-effect-enrollment-for-parent-child-cancellation+single-inverse-key"
const IndexCompensationVersion uint64 = 2026100905
const IndexCompensationManifest = "2026100905:2026100904+knowledge-active-index-causal-stamp+owned-publication-cas-compensation"
const KafkaDeadLetterVersion uint64 = 2026100906
const KafkaDeadLetterManifest = "2026100906:2026100905+durable-kafka-source-attempts+protected-dead-letter-records+cas-actions"
const DepartmentAdministrationVersion uint64 = 2026101001
const DepartmentAdministrationManifest = "2026101001:2026100906+immutable-department-admin-v2-role-and-preset+scoped-membership-and-basic-application-authority"
const CompanyAdministrationVersion uint64 = 2026101002
const CompanyAdministrationManifest = "2026101002:2026101001+immutable-tenant-admin-v2-company-role-and-appointment-only-preset+company-scoped-management-without-business-membership"
const DepartmentAgentAccessVersion uint64 = 2026101003
const DepartmentAgentAccessManifest = "2026101003:2026101002+explicit-managed-department-agent-ceiling-head-entries-and-atomic-command-receipts+empty-ceiling-for-new-company-departments+runtime-and-version-constraints+per-action-source-generations-and-reviewed-ceiling-preview"
const PermissionBatchVersion uint64 = 2026101004
const PermissionBatchManifest = "2026101004:2026101003+durable-owner-scoped-permission-batches+per-subject-atomic-authorization-request-decision-audit-outbox-and-recoverable-results"
const AutoModelRoutingVersion uint64 = 2026101401
const AutoModelRoutingManifest = "2026101401:2026100906+immutable-model-route-decisions+run-model-selection-bindings"
const ContextCacheVersion uint64 = 2026101402
const ContextCacheManifest = "2026101402:2026101401+optional-approved-cached-input-token-pricing"
const ModelAvailabilityVersion uint64 = 2026101501
const ModelAvailabilityManifest = "2026101501:2026101402+scoped-model-availability+fenced-recovery-probes"
const ModelRouteExecutionVersion uint64 = 2026101502
const ModelRouteExecutionManifest = "2026101502:2026101501+durable-logical-model-execution+retained-unknown-attempts"
const CheckpointAdmissionVersion uint64 = 2026101503
const CheckpointAdmissionManifest = "2026101503:2026101502+short-transaction-checkpoint-quota-admission"
const ModelBudgetEvidenceVersion uint64 = 2026101801
const ModelBudgetEvidenceManifest = "2026101801:2026101503+indexed-model-budget-reservation-evidence"
const AccountingReadIndexesVersion uint64 = 2026102001
const AccountingReadIndexesManifest = "2026102001:2026101801+active-accounting-reads+billing-tail+active-outbox-indexes"
const PublicCapabilityUpgradeVersion uint64 = 2026102201
const PublicCapabilityUpgradeManifest = "2026102201:2026101004+model-routing-cache-schema+checkpoint-capacity-and-admission+identity-packages+runtime-observation-and-evaluation"
const CurrentVersion uint64 = PublicCapabilityUpgradeVersion
const Manifest = PublicCapabilityUpgradeManifest

func IndexCompensationChecksum() string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(IndexCompensationManifest)))
}

func CancellationEnrollmentChecksum() string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(CancellationEnrollmentManifest)))
}

func GenerationJournalChecksum() string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(GenerationJournalManifest)))
}

func ModelUsageStepChecksum() string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(ModelUsageStepManifest)))
}

func PermissionCatalogV2Checksum() string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(PermissionCatalogV2Manifest)))
}

func DelegationAuthorityChecksum() string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(DelegationAuthorityManifest)))
}

func CancellationCompensationChecksum() string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(CancellationCompensationManifest)))
}

func LocalCompensationChecksum() string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(LocalCompensationManifest)))
}

func NotificationReversalChecksum() string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(NotificationReversalManifest)))
}

func ChildLifecycleChecksum() string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(ChildLifecycleManifest)))
}

func RunTreeBudgetChecksum() string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(RunTreeBudgetManifest)))
}

func RouteChecksum() string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(RouteManifest)))
}

func SkillChecksum() string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(SkillManifest)))
}

func ToolApprovalChecksum() string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(ToolApprovalManifest)))
}

func BusinessStateChecksum() string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(BusinessStateManifest)))
}

func PostgresCheckpointChecksum() string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(PostgresCheckpointManifest)))
}

func PostgresIndexChecksum() string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(PostgresIndexManifest)))
}

func PostgresSourceChecksum() string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(PostgresSourceManifest)))
}

func PostgresDirectoryChecksum() string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(PostgresDirectoryManifest)))
}

func PostgresInitialChecksum() string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(PostgresInitialManifest)))
}

func ErasureChecksum() string { return fmt.Sprintf("%x", sha256.Sum256([]byte(ErasureManifest))) }

func WorkloadBindingChecksum() string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(WorkloadBindingManifest)))
}

func ConversationBindingChecksum() string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(ConversationBindingManifest)))
}

func OIDCStepUpChecksum() string { return fmt.Sprintf("%x", sha256.Sum256([]byte(OIDCStepUpManifest))) }

func TaskAssignmentChecksum() string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(TaskAssignmentManifest)))
}

func PermissionRequestChecksum() string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(PermissionRequestManifest)))
}

func StepUpChecksum() string { return fmt.Sprintf("%x", sha256.Sum256([]byte(StepUpManifest))) }

func RefreshChecksum() string { return fmt.Sprintf("%x", sha256.Sum256([]byte(RefreshManifest))) }

func PermissionChecksum() string { return fmt.Sprintf("%x", sha256.Sum256([]byte(PermissionManifest))) }

func PublicPredecessorChecksum() string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(PublicPredecessorManifest)))
}

func CurrentChecksum() string { return fmt.Sprintf("%x", sha256.Sum256([]byte(Manifest))) }
func ExecutionPendingChecksum() string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(ExecutionPendingManifest)))
}
func LegacyChecksum() string   { return legacyReleasedChecksum }
func PreviousChecksum() string { return fmt.Sprintf("%x", sha256.Sum256([]byte(PreviousManifest))) }
func EarlierChecksum() string  { return fmt.Sprintf("%x", sha256.Sum256([]byte(EarlierManifest))) }
func PermissionPredecessorChecksum() string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(PermissionPredecessorManifest)))
}

var ErrIncompatible = errors.New("platform schema version is incompatible; run the versioned migration command")

func knownPostgresPredecessor(version uint64, checksum string) bool {
	switch version {
	case PostgresInitialVersion:
		return checksum == PostgresInitialChecksum()
	case PostgresDirectoryVersion:
		return checksum == PostgresDirectoryChecksum()
	case PostgresSourceVersion:
		return checksum == PostgresSourceChecksum()
	case PostgresIndexVersion:
		return checksum == PostgresIndexChecksum()
	case PostgresCheckpointVersion:
		return checksum == PostgresCheckpointChecksum()
	case BusinessStateVersion:
		return checksum == BusinessStateChecksum()
	case ToolApprovalVersion:
		return checksum == ToolApprovalChecksum()
	case SkillVersion:
		return checksum == SkillChecksum()
	case RouteVersion:
		return checksum == RouteChecksum()
	case RunTreeBudgetVersion:
		return checksum == RunTreeBudgetChecksum()
	case ChildLifecycleVersion:
		return checksum == ChildLifecycleChecksum()
	case ExecutionPendingVersion:
		return checksum == ExecutionPendingChecksum()
	case GenerationJournalVersion:
		return checksum == GenerationJournalChecksum()
	case ModelUsageStepVersion:
		return checksum == ModelUsageStepChecksum()
	case PermissionCatalogV2Version:
		return checksum == PermissionCatalogV2Checksum()
	case DelegationAuthorityVersion:
		return checksum == DelegationAuthorityChecksum()
	case CancellationCompensationVersion:
		return checksum == CancellationCompensationChecksum()
	case LocalCompensationVersion:
		return checksum == LocalCompensationChecksum()
	case NotificationReversalVersion:
		return checksum == NotificationReversalChecksum()
	case CancellationEnrollmentVersion:
		return checksum == CancellationEnrollmentChecksum()
	case IndexCompensationVersion:
		return checksum == IndexCompensationChecksum()
	case KafkaDeadLetterVersion:
		return checksum == fmt.Sprintf("%x", sha256.Sum256([]byte(KafkaDeadLetterManifest)))
	case DepartmentAdministrationVersion:
		return checksum == fmt.Sprintf("%x", sha256.Sum256([]byte(DepartmentAdministrationManifest)))
	case CompanyAdministrationVersion:
		return checksum == fmt.Sprintf("%x", sha256.Sum256([]byte(CompanyAdministrationManifest)))
	case PermissionBatchVersion:
		return checksum == fmt.Sprintf("%x", sha256.Sum256([]byte(PermissionBatchManifest)))
	case DepartmentAgentAccessVersion:
		return checksum == fmt.Sprintf("%x", sha256.Sum256([]byte(DepartmentAgentAccessManifest)))
	default:
		return false
	}
}

// Check performs SELECT only. Missing, older, newer or drifted versions fail closed.
// Check只执行SELECT；缺失、旧版、新版和校验值漂移均拒绝启动。
func Check(ctx context.Context, db *sql.DB) error {
	var version uint64
	var checksum string
	if err := db.QueryRowContext(ctx, `SELECT version,checksum FROM platform_schema_version ORDER BY version DESC LIMIT 1`).Scan(&version, &checksum); err != nil {
		return fmt.Errorf("%w: version query unavailable", ErrIncompatible)
	}
	if version != CurrentVersion || checksum != CurrentChecksum() {
		return ErrIncompatible
	}
	return nil
}

// ApplyPostgres owns one transaction for the schema, immutable definitions and
// version marker. A failed bundle rolls back its DDL and never leaves a marker.
// Old database lineages are rejected; no legacy checksum is reinterpreted.
func ApplyPostgres(ctx context.Context, db *sql.DB, migrate func(context.Context, *sql.DB) error) error {
	if db == nil || migrate == nil {
		return errors.New("migration database and bundle are required")
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `SET LOCAL lock_timeout = '10s'`); err != nil {
		return err
	}
	var database string
	if err := tx.QueryRowContext(ctx, `SELECT current_database()`).Scan(&database); err != nil || database == "" {
		return errors.New("migration database is required")
	}
	digest := sha256.Sum256([]byte("platform-schema-postgres:" + database))
	lock := int64(binary.BigEndian.Uint64(digest[:8]))
	if _, err := tx.ExecContext(ctx, sqlutil.Bind(`SELECT pg_advisory_xact_lock(?)`), lock); err != nil {
		return errors.New("migration lock unavailable")
	}
	if _, err := tx.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS platform_schema_version(version BIGINT NOT NULL PRIMARY KEY,checksum VARCHAR(64) NOT NULL,applied_at TIMESTAMPTZ(6) NOT NULL)`); err != nil {
		return err
	}
	var version uint64
	var checksum string
	err = tx.QueryRowContext(ctx, `SELECT version,checksum FROM platform_schema_version ORDER BY version DESC LIMIT 1`).Scan(&version, &checksum)
	if err == nil {
		if version == CurrentVersion && checksum == CurrentChecksum() {
			return tx.Commit()
		}
		// Only known native PostgreSQL lineages with exact checksums may be
		// upgraded. MySQL-era lineages and checksum drift remain incompatible.
		if !knownPostgresPredecessor(version, checksum) {
			return ErrIncompatible
		}
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	facade := sqlutil.TransactionDB(tx)
	defer facade.Close()
	if err := migrate(ctx, facade); err != nil {
		return fmt.Errorf("migration bundle failed: %w", err)
	}
	if _, err := tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_schema_version(version,checksum,applied_at) VALUES(?,?,clock_timestamp())`), CurrentVersion, CurrentChecksum()); err != nil {
		return err
	}
	return tx.Commit()
}

func ModelBudgetEvidenceChecksum() string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(ModelBudgetEvidenceManifest)))
}

func CheckpointAdmissionChecksum() string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(CheckpointAdmissionManifest)))
}

func ModelRouteExecutionChecksum() string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(ModelRouteExecutionManifest)))
}

func ModelAvailabilityChecksum() string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(ModelAvailabilityManifest)))
}

func ContextCacheChecksum() string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(ContextCacheManifest)))
}

func AutoModelRoutingChecksum() string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(AutoModelRoutingManifest)))
}

func KafkaDeadLetterChecksum() string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(KafkaDeadLetterManifest)))
}
