// Command migrate is the explicit migration entry point.
// migrate 命令是显式数据库迁移入口，避免业务进程隐式改库。
package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/lexagent/platform/internal/agentcoordination"
	"github.com/lexagent/platform/internal/agentfactory"
	"github.com/lexagent/platform/internal/audit"
	"github.com/lexagent/platform/internal/bootstrap"
	"github.com/lexagent/platform/internal/capability"
	"github.com/lexagent/platform/internal/catalog"
	"github.com/lexagent/platform/internal/compensation"
	"github.com/lexagent/platform/internal/conversation"
	"github.com/lexagent/platform/internal/evaluationproduct"
	"github.com/lexagent/platform/internal/execution"
	"github.com/lexagent/platform/internal/identity"
	"github.com/lexagent/platform/internal/knowledge"
	"github.com/lexagent/platform/internal/modelcapacity"
	"github.com/lexagent/platform/internal/modelgovernance"
	"github.com/lexagent/platform/internal/notification"
	"github.com/lexagent/platform/internal/policyasset"
	"github.com/lexagent/platform/internal/schemaversion"
	"github.com/lexagent/platform/internal/usagecost"
)

func main() {
	config := loadMigrationConfig()
	if err := run(context.Background(), config); err != nil {
		log.Fatal(err)
	}
	log.Println("platform migrations completed")
}

// Migration owns only the schema credential. Loading the runtime configuration
// would force the Job to receive unrelated signing, RAG, and service tokens.
func loadMigrationConfig() bootstrap.Config {
	environment := strings.ToLower(strings.TrimSpace(os.Getenv("APP_ENV")))
	if environment == "" {
		environment = "development"
	}
	driver := strings.ToLower(strings.TrimSpace(os.Getenv("DB_DRIVER")))
	if driver == "" {
		driver = "pgx"
	}
	return bootstrap.Config{Runtime: bootstrap.RuntimeConfig{
		Environment: environment,
		DBDriver:    driver,
		DBDSN:       os.Getenv("DB_DSN"),
	}}
}

// run applies every platform-owned schema against one shared SQL pool. The
// command intentionally does not seed business data or start HTTP/worker
// modules; process startup remains responsible for runtime readiness checks.
// run 使用一个共享 SQL 池执行平台所有者的 schema；不写入业务种子数据，也不启动
// HTTP/Worker，运行进程仍负责运行期就绪检查。
func run(parent context.Context, config bootstrap.Config) error {
	if config.LoadError != nil {
		return fmt.Errorf("invalid platform configuration: %w", config.LoadError)
	}
	if config.Runtime.DBDriver != "pgx" && config.Runtime.DBDriver != "postgres" {
		return errors.New("platform migrations require DB_DRIVER=pgx or postgres")
	}
	switch config.Runtime.Environment {
	case "development", "test", "production", "prod":
	default:
		return errors.New("APP_ENV must identify development, test, or production for migrations")
	}
	if strings.TrimSpace(config.Runtime.DBDSN) == "" {
		return errors.New("DB_DSN is required for platform migrations")
	}
	if config.Runtime.Environment == "production" || config.Runtime.Environment == "prod" {
		lowerDSN := strings.ToLower(config.Runtime.DBDSN)
		if strings.Contains(lowerDSN, "root:root") || strings.Contains(lowerDSN, "dev-") {
			return errors.New("production migration DB_DSN must not use development placeholders")
		}
		if os.Getenv("PLATFORM_DEV_RUNTIME_PASSWORD") != "" {
			return errors.New("production migrations cannot provision a development runtime account")
		}
	}
	runtimePassword := os.Getenv("PLATFORM_DEV_RUNTIME_PASSWORD")
	if runtimePassword != "" && (config.Runtime.Environment != "development" || !runtimePasswordPattern.MatchString(runtimePassword)) {
		return errors.New("development runtime account requires APP_ENV=development and a 24-128 character URL-safe password")
	}
	ctx, cancel := context.WithTimeout(parent, 2*time.Minute)
	defer cancel()
	store, err := execution.ConnectSQLStore(ctx, config.Runtime.DBDriver, config.Runtime.DBDSN)
	if err != nil {
		return err
	}
	defer store.Close()
	db := store.DB()
	err = schemaversion.ApplyPostgres(ctx, db, func(ctx context.Context, transactionDB *sql.DB) error {
		db := transactionDB

		steps := []struct {
			name string
			fn   func(context.Context) error
		}{
			{"execution", func(ctx context.Context) error { return execution.MigrateSchema(ctx, db) }},
			{"cancellation_compensation", func(ctx context.Context) error { return compensation.ApplySchema(ctx, db) }},
			{"cancellation_effect_enrollment", func(ctx context.Context) error { return compensation.ApplyEnrollmentSchema(ctx, db) }},
			{"local_compensation_effects", func(ctx context.Context) error { return compensation.ApplyLocalEffectSchema(ctx, db) }},
			{"execution_pending_scan", func(ctx context.Context) error { return execution.MigratePendingScanSchema(ctx, db) }},
			{"execution_session_quiescence", func(ctx context.Context) error {
				_, err := db.ExecContext(ctx, `CREATE INDEX IF NOT EXISTS idx_execution_session_quiescence ON platform_execution_run (tenant_id,department_id,application_id,session_id)`)
				return err
			}},
			{"knowledge_projection", func(ctx context.Context) error {
				_, err := db.ExecContext(ctx, knowledge.ProjectionSchema+"\n"+knowledge.SourceSchema)
				return err
			}},
			{"catalog", catalog.NewSQLStore(db, config.Runtime.DBDriver).EnsureSchema},
			{"identity", identity.NewSQLStore(db).EnsureSchema},
			{"agent_factory", agentfactory.NewSQLStore(db).EnsureSchema},
			{"evaluation_product", evaluationproduct.NewSQLStore(db).EnsureSchema},
			{"model_governance", modelgovernance.NewSQLStore(db).EnsureSchema},
			{"model_capacity", modelcapacity.NewSQLProvider(db).EnsureSchema},
			{"notification", notification.NewSQLStore(db).EnsureSchema},
			{"notification_reversal", func(ctx context.Context) error { return notification.ApplyReversalSchema(ctx, db) }},
			{"kafka_dead_letter", func(ctx context.Context) error { return notification.ApplyDeadLetterSchema(ctx, db) }},
			{"conversation", conversation.NewSQLStore(db).EnsureSchema},
			{"usage", usagecost.NewSQLStore(db).EnsureSchema},
			{"run_tree_budget", usagecost.NewSQLRunTreeBudgetStore(db).EnsureSchema},
			{"audit", audit.NewSQLStore(db).EnsureSchema},
			{"policy", policyasset.NewSQLStore(db).EnsureSchema},
			{"policy_resolver", policyasset.NewSQLResolver(db).EnsureSchema},
		}
		memory, err := capability.NewSQLMemoryStore(db)
		if err != nil {
			return err
		}
		state, err := capability.NewSQLCheckpointStore(db)
		if err != nil {
			return err
		}
		approvals, err := capability.NewSQLToolApprovalStore(db)
		if err != nil {
			return err
		}
		skills, err := capability.NewSQLSkillStore(db)
		if err != nil {
			return err
		}
		routes, err := agentcoordination.NewSQLRouteStore(db)
		if err != nil {
			return err
		}
		model, err := capability.NewSQLModelInvocationStore(db)
		if err != nil {
			return err
		}
		tool, err := capability.NewSQLToolInvocationStore(db)
		if err != nil {
			return err
		}
		steps = append(steps,
			struct {
				name string
				fn   func(context.Context) error
			}{"knowledge_index_compensation", func(ctx context.Context) error { return knowledge.MigrateIndexCompensation(ctx, db) }},
			struct {
				name string
				fn   func(context.Context) error
			}{"memory", memory.EnsureSchema},
			struct {
				name string
				fn   func(context.Context) error
			}{"memory_compensation", func(ctx context.Context) error { return capability.MigrateMemoryCompensation(ctx, db) }},
			struct {
				name string
				fn   func(context.Context) error
			}{"business_checkpoint", state.EnsureSchema},
			struct {
				name string
				fn   func(context.Context) error
			}{"tool_approval", approvals.EnsureSchema},
			struct {
				name string
				fn   func(context.Context) error
			}{"skill_registry", skills.EnsureSchema},
			struct {
				name string
				fn   func(context.Context) error
			}{"agent_coordination", routes.EnsureSchema},
			struct {
				name string
				fn   func(context.Context) error
			}{"agent_child_lifecycle", routes.EnsureLifecycleSchema},
			struct {
				name string
				fn   func(context.Context) error
			}{"agent_child_delegation_authority", routes.EnsureDelegationAuthoritySchema},
			struct {
				name string
				fn   func(context.Context) error
			}{"model_invocation", model.EnsureSchema},
			struct {
				name string
				fn   func(context.Context) error
			}{"tool_invocation", tool.EnsureSchema},
		)
		for _, step := range steps {
			if err := step.fn(ctx); err != nil {
				return fmt.Errorf("migrate %s: %w", step.name, err)
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	if runtimePassword != "" {
		return provisionDevRuntimeAccount(ctx, db, config.Runtime.Environment, config.Runtime.DBDSN, runtimePassword)
	}
	return nil
}
