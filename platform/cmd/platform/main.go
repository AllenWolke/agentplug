// Command platform is the future modular-monolith process entry point.
// platform 命令是未来模块化单体进程的入口。
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/lexagent/platform/cmd/internal/permissionresources"
	"github.com/lexagent/platform/internal/agentcoordination"
	"github.com/lexagent/platform/internal/agentfactory"
	"github.com/lexagent/platform/internal/agentgateway"
	"github.com/lexagent/platform/internal/audit"
	"github.com/lexagent/platform/internal/bootstrap"
	"github.com/lexagent/platform/internal/capability"
	"github.com/lexagent/platform/internal/catalog"
	"github.com/lexagent/platform/internal/contract"
	"github.com/lexagent/platform/internal/conversation"
	"github.com/lexagent/platform/internal/evaluationproduct"
	"github.com/lexagent/platform/internal/execution"
	"github.com/lexagent/platform/internal/identity"
	"github.com/lexagent/platform/internal/knowledge"
	"github.com/lexagent/platform/internal/modelcapacity"
	"github.com/lexagent/platform/internal/modelgateway"
	"github.com/lexagent/platform/internal/modelgovernance"
	"github.com/lexagent/platform/internal/notification"
	"github.com/lexagent/platform/internal/policyasset"
	"github.com/lexagent/platform/internal/schemaversion"
	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/telemetry"
	"github.com/lexagent/platform/internal/usagecost"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	config := bootstrap.LoadConfig()
	if config.LoadError != nil {
		log.Fatal("invalid platform configuration: ", config.LoadError)
	}
	if config.Runtime.DBDSN != "" && len(config.Runtime.BrowserGatewayToken) < 32 {
		log.Fatal("BROWSER_GATEWAY_TOKEN is required for the platform browser boundary")
	}
	// Sampling is process configuration, never caller-controlled policy.
	// 采样只由进程配置控制，不由调用方或 Agent 策略注入。
	sampleRatio, err := strconv.ParseFloat(envOrDefault("OTEL_TRACES_SAMPLER_ARG", "1"), 64)
	if err != nil {
		log.Fatal("invalid telemetry sampling ratio")
	}
	tracing, err := telemetry.New(ctx, telemetry.Config{Endpoint: config.Runtime.OTelEndpoint, Service: "agentplug-platform", Version: envOrDefault("PLATFORM_BUILD_VERSION", "development"), SampleRatio: sampleRatio})
	if err != nil {
		log.Fatal("initialize platform telemetry failed")
	}
	tracing.Install()
	defer func() {
		closeCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := tracing.Close(closeCtx); err != nil {
			log.Print("telemetry shutdown code=OTEL_SHUTDOWN_FAILED")
		}
	}()
	modules := bootstrap.NewModuleRegistry()
	executionModule := execution.NewModule(config.Runtime.InternalToken)
	var contextSigner conversation.ContextTokenSigner
	var policyResolver policyasset.Resolver
	var knowledgeModule *knowledge.ControlModule
	var memoryStore capability.MemoryStore
	var checkpointStore capability.CheckpointStore
	var evaluationBudgetAuthority *evaluationExecutionAuthority
	var toolApprovalStore *capability.SQLToolApprovalStore
	var modelInvocationStore capability.ModelInvocationStore
	var toolInvocationStore capability.ToolInvocationStore
	var sqlStore *execution.SQLStore
	var catalogStore *catalog.SQLStore
	var catalogModule *catalog.Module
	var identityStore *identity.SQLStore
	var identityModule *identity.Module
	var modelGovernanceStore *modelgovernance.SQLStore
	var agentFactoryStore *agentfactory.SQLStore
	var evaluationProductStore *evaluationproduct.SQLStore
	var policyAssetStore *policyasset.SQLStore
	var notificationStore *notification.SQLStore
	var conversationStore *conversation.SQLStore
	var usageStore *usagecost.SQLStore
	var auditStore *audit.SQLStore
	// Candidate gate stays explicit until write-provider coverage is complete.
	cancellationEnabled := envBool("PLATFORM_CANCELLATION_COMPENSATION_ENABLED", false)
	var cancellationChannel *agentNotificationChannel
	if cancellationEnabled {
		cancellationChannel = &agentNotificationChannel{}
	}
	var cancellationNotifications *notification.Module
	var cancellationBudgetTree *usagecost.SQLRunTreeBudgetStore
	var cancellationDomain cancellationDomainInstaller
	var indexCompensation *knowledge.IndexCompensation
	if encoded := config.Runtime.PlatformContextPrivateKey; encoded != "" {
		raw, err := base64.StdEncoding.DecodeString(encoded)
		// The repository's ephemeral-key helper intentionally emits the
		// 32-byte Ed25519 seed (Raw format), while Secret Manager mounts may
		// provide the expanded 64-byte private key. Accept both at this
		// boundary and keep the signer itself strongly typed.
		// 仓库临时密钥脚本输出 32 字节 Ed25519 seed，Secret Manager 也可能
		// 挂载展开后的 64 字节私钥；在边界统一转换，Signer 内部仍保持强类型。
		if err == nil && len(raw) == ed25519.SeedSize {
			raw = ed25519.NewKeyFromSeed(raw)
		}
		if err != nil || len(raw) != ed25519.PrivateKeySize {
			log.Fatal("PLATFORM_CONTEXT_PRIVATE_KEY must be base64 encoded Ed25519 private key")
		}
		contextSigner = conversation.Ed25519ContextTokenSigner{
			PrivateKey: ed25519.PrivateKey(raw), Issuer: config.Runtime.PlatformContextIssuer,
			Audience: config.Runtime.PlatformContextAudience, TTL: 2 * time.Minute,
		}
	}
	if config.Runtime.DBDSN != "" {
		dbCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		var err error
		sqlStore, err = execution.ConnectSQLStore(dbCtx, config.Runtime.DBDriver, config.Runtime.DBDSN)
		if err == nil {
			err = schemaversion.Check(dbCtx, sqlStore.DB())
		}
		if err == nil && config.Runtime.IsProduction() {
			err = schemaversion.CheckRuntimePrivileges(dbCtx, sqlStore.DB())
		}
		cancel()
		if err != nil {
			log.Fatal(err)
		}
		telemetry.SetDatabaseProbe(sqlStore.DB().PingContext)
		telemetry.SetRunRecoverySource(func(ctx context.Context) (telemetry.RunRecoveryMetrics, error) {
			snapshot, err := sqlStore.RecoverySnapshot(ctx)
			return telemetry.RunRecoveryMetrics{
				Cancelling: snapshot.Cancelling, Recovering: snapshot.Recovering,
				OldestCancellingAt: snapshot.OldestCancellingAt, OldestRecoveringAt: snapshot.OldestRecoveringAt,
			}, err
		})
		catalogStore = catalog.NewSQLStore(sqlStore.DB(), config.Runtime.DBDriver)
		identityStore = identity.NewSQLStore(sqlStore.DB())
		identityModule = identity.NewModule(identityStore, config.Runtime.InternalToken)
		modelGovernanceStore = modelgovernance.NewSQLStore(sqlStore.DB())
		agentFactoryStore = agentfactory.NewSQLStore(sqlStore.DB())
		evaluationProductStore = evaluationproduct.NewSQLStore(sqlStore.DB())
		policyAssetStore = policyasset.NewSQLStore(sqlStore.DB())
		enrollmentConfig := identity.EnrollmentConfig{
			Scope: identity.EnrollmentScope{
				TenantID:      config.Runtime.IdentityEnrollmentTenantID,
				DepartmentID:  config.Runtime.IdentityEnrollmentDepartmentID,
				ApplicationID: config.Runtime.IdentityEnrollmentApplicationID,
			},
			InviteCode:             config.Runtime.IdentityEnrollmentInviteCode,
			Environment:            config.Runtime.Environment,
			VerificationHMACKey:    config.Runtime.IdentityEnrollmentHMACKey,
			ContactDeliveryEnabled: config.Runtime.Environment != "development" && config.Runtime.NotificationAdapter != "none" && len(config.Runtime.IdentityEnrollmentDeliveryKey) == 32,
		}
		if config.Runtime.Environment == "development" {
			if enrollmentConfig.Scope.TenantID == "" {
				enrollmentConfig.Scope.TenantID = "tenant-demo"
			}
			if enrollmentConfig.Scope.DepartmentID == "" {
				enrollmentConfig.Scope.DepartmentID = "dept-demo"
			}
			if enrollmentConfig.Scope.ApplicationID == "" {
				enrollmentConfig.Scope.ApplicationID = "app-demo"
			}
			if enrollmentConfig.InviteCode == "" {
				enrollmentConfig.InviteCode = "local-only-registration-invite"
			}
		}
		identityModule.ConfigureEnrollment(enrollmentConfig)
		if reader, ok := any(catalogStore).(catalog.AvailableAgentReader); ok {
			identityModule.SetEnrollmentCatalogResolver(identityEnrollmentCatalog{reader: reader})
		}
		notificationStore = notification.NewSQLStore(sqlStore.DB())
		conversationStore = conversation.NewSQLStore(sqlStore.DB())
		conversationStore.SetDeletionContinuityGuard(identityStore.AcquirePermissionReadContinuity)
		usageStore = usagecost.NewSQLStore(sqlStore.DB())
		auditStore = audit.NewSQLStoreWithOutbox(sqlStore.DB(), notificationStore)
		conversationStore.SetDeletionApprovalReplayChecker(func(ctx context.Context, tx *sql.Tx, scope conversation.Scope, item conversation.DeletionRequest) (bool, error) {
			return auditStore.MatchesCommittedActorTx(ctx, tx, audit.Event{ID: "deletion-approval-" + item.ID, TenantID: scope.TenantID, DepartmentID: scope.DepartmentID, ApplicationID: scope.ApplicationID, ActorType: scope.PrincipalType, ActorID: scope.PrincipalID, AggregateType: "conversation_deletion", AggregateID: item.ID, Action: "conversation.deletion.approved", Outcome: "success", CreatedAt: item.ApprovedAt})
		})
		conversationStore.SetDeletionApprovalRecorder(func(_ context.Context, tx *sql.Tx, scope conversation.Scope, item conversation.DeletionRequest) error {
			return auditStore.RecordTx(tx, audit.Event{ID: "deletion-approval-" + item.ID, TenantID: scope.TenantID, DepartmentID: scope.DepartmentID, ApplicationID: scope.ApplicationID, ActorType: scope.PrincipalType, ActorID: scope.PrincipalID, TraceID: scope.TraceID, AggregateType: "conversation_deletion", AggregateID: item.ID, Action: "conversation.deletion.approved", Outcome: "success", Summary: "Approved deletion request for session " + item.SessionID + " requested by " + item.OwnerID, CreatedAt: item.ApprovedAt})
		})
		identityStore.SetAdministrativeRecorder(recordVersionedAdministration(auditStore, notificationStore, identityStore))
		identityStore.SetRefreshSessionRecorder(func(_ context.Context, tx *sql.Tx, event identity.RefreshSessionEvent) error {
			return auditStore.RecordTx(tx, audit.Event{ID: event.ID, TenantID: event.Identity.TenantID, DepartmentID: event.Identity.DepartmentID, ApplicationID: event.Identity.ApplicationID,
				ActorType: "user", ActorID: event.Identity.PrincipalID, AggregateType: "identity_refresh_session", AggregateID: event.FamilyID, Action: "identity.session." + event.Action, Outcome: "success", Summary: "Authentication session " + event.Action, CreatedAt: event.OccurredAt})
		})
		identityStore.SetAuthorizationChangeRecorder(recordVersionedAuthorizationChange(auditStore, notificationStore))
		identityStore.SetAgentAccessDecisionRecorder(func(recordCtx context.Context, tx *sql.Tx, scope sharedkernel.Scope, request identity.AgentAccessRequest) error {
			eventID := fmt.Sprintf("identity-agent-access-%s-r%d", request.ID, request.Revision)
			auditEvent := audit.Event{
				ID: eventID, TenantID: request.TenantID, DepartmentID: request.DepartmentID, ApplicationID: request.ApplicationID,
				ActorType: string(identity.PrincipalUser), ActorID: request.ReviewerID, TraceID: scope.TraceID,
				AggregateType: "user_agent_access_request", AggregateID: request.ID,
				Action: "agent_access_request." + request.Status, Outcome: request.Status,
				Summary: "Agent access request " + request.Status, CreatedAt: request.UpdatedAt,
			}
			if err := auditStore.RecordTx(tx, auditEvent); err != nil {
				return fmt.Errorf("record agent access decision audit: %w", err)
			}
			_, err := notificationStore.EnqueueTx(recordCtx, tx, notification.Event{
				ID:       "user-agent-access-" + request.ID + fmt.Sprintf("-r%d", request.Revision),
				TenantID: request.TenantID, DepartmentID: request.DepartmentID, ApplicationID: request.ApplicationID,
				Topic: "agent-platform.user-access.v1", EventType: "user.agent-access-" + request.Status + ".v1",
				PartitionKey: request.TenantID + ":" + request.SubjectID,
				Payload:      map[string]any{"request_id": request.ID, "subject_id": request.SubjectID, "agent_id": request.AgentID, "revision": request.Revision},
			})
			if err != nil {
				return fmt.Errorf("enqueue agent access decision event: %w", err)
			}
			return nil
		})
		identityStore.SetEnrollmentDecisionRecorder(func(recordCtx context.Context, tx *sql.Tx, scope sharedkernel.Scope, decision identity.EnrollmentDecision) error {
			eventID := fmt.Sprintf("identity-enrollment-%s-r%d", decision.EnrollmentID, decision.Revision)
			auditEvent := audit.Event{
				ID: eventID, TenantID: decision.TenantID, DepartmentID: decision.DepartmentID, ApplicationID: decision.ApplicationID,
				ActorType: string(identity.PrincipalUser), ActorID: decision.ReviewerID, TraceID: decision.TraceID,
				AggregateType: "identity_enrollment", AggregateID: decision.EnrollmentID,
				Action: "identity_enrollment." + decision.Status, Outcome: decision.Status,
				Summary: "Identity enrollment " + decision.Status, CreatedAt: decision.OccurredAt,
			}
			if err := auditStore.RecordTx(tx, auditEvent); err != nil {
				return fmt.Errorf("record identity enrollment decision audit: %w", err)
			}
			_, err := notificationStore.EnqueueTx(recordCtx, tx, notification.Event{
				ID:       "identity-enrollment-decision-" + decision.EnrollmentID + fmt.Sprintf("-r%d", decision.Revision),
				TenantID: decision.TenantID, DepartmentID: decision.DepartmentID, ApplicationID: decision.ApplicationID,
				Topic: "identity.enrollment.v1", EventType: "identity.enrollment-" + decision.Status + ".v1",
				PartitionKey: decision.TenantID + ":" + decision.SubjectID,
				Payload:      map[string]any{"enrollment_id": decision.EnrollmentID, "subject_id": decision.SubjectID, "status": decision.Status, "revision": decision.Revision},
			})
			if err != nil {
				return fmt.Errorf("enqueue identity enrollment decision event: %w", err)
			}
			return nil
		})
		identityStore.SetPrincipalLifecycleRecorder(recordVersionedPrincipalLifecycle(auditStore, notificationStore))
		identityStore.SetOIDCBindingRecorder(func(_ context.Context, tx *sql.Tx, scope sharedkernel.Scope, decision identity.OIDCBindingDecision) error {
			key := fmt.Sprintf("%s:%s:%d", decision.IdentityKey, decision.Status, decision.Revision)
			digest := sha256.Sum256([]byte(key))
			return auditStore.RecordTx(tx, audit.Event{
				ID:       "identity-oidc-binding-" + hex.EncodeToString(digest[:]),
				TenantID: decision.TenantID, DepartmentID: decision.DepartmentID, ApplicationID: decision.ApplicationID,
				ActorType: scope.PrincipalType, ActorID: scope.PrincipalID, TraceID: scope.TraceID,
				AggregateType: "identity_oidc_binding", AggregateID: decision.IdentityKey,
				Action: "identity.oidc_binding." + decision.Status, Outcome: "success",
				Summary: "OIDC binding " + decision.Status, CreatedAt: decision.OccurredAt,
			})
		})
		identityStore.SetCredentialLifecycleRecorder(func(recordCtx context.Context, tx *sql.Tx, scope sharedkernel.Scope, decision identity.CredentialLifecycleDecision) error {
			key := fmt.Sprintf("%s:%s:%d", scope.TenantID, decision.PrincipalID, decision.AuthRevision)
			digest := sha256.Sum256([]byte(key))
			eventID := "identity-credential-" + hex.EncodeToString(digest[:])
			auditEvent := audit.Event{
				ID: eventID, TenantID: scope.TenantID, DepartmentID: scope.DepartmentID, ApplicationID: scope.ApplicationID,
				ActorType: string(identity.PrincipalUser), ActorID: decision.PrincipalID, TraceID: scope.TraceID,
				AggregateType: "identity_local_credential", AggregateID: decision.PrincipalID,
				Action: "identity.credential.password_changed", Outcome: "success",
				Summary: "Identity local credential password changed", CreatedAt: decision.OccurredAt,
			}
			if err := auditStore.RecordTx(tx, auditEvent); err != nil {
				return fmt.Errorf("record identity credential lifecycle audit: %w", err)
			}
			_, err := notificationStore.EnqueueTx(recordCtx, tx, notification.Event{
				ID:       "identity-credential-notify-" + hex.EncodeToString(digest[:]),
				TenantID: scope.TenantID, DepartmentID: scope.DepartmentID, ApplicationID: scope.ApplicationID,
				Topic: "agent-platform.identity.v1", EventType: "identity.credential-password-changed.v1",
				PartitionKey: scope.TenantID + ":" + decision.PrincipalID,
				Payload:      map[string]any{"principal_id": decision.PrincipalID, "auth_revision": decision.AuthRevision},
			})
			if err != nil {
				return fmt.Errorf("enqueue identity credential lifecycle event: %w", err)
			}
			return nil
		})
		if enrollmentConfig.ContactDeliveryEnabled {
			identityStore.SetEnrollmentVerificationRecorder(func(recordCtx context.Context, tx *sql.Tx, scope sharedkernel.Scope, item identity.EnrollmentCommand) error {
				delivery, err := json.Marshal(map[string]string{
					"registration_id": item.ID,
					"recipient":       item.ContactForDelivery,
					"code":            item.VerificationCode,
					"expires_at":      item.VerifyExpiresAt.UTC().Format(time.RFC3339),
				})
				if err != nil {
					return fmt.Errorf("encode identity verification delivery: %w", err)
				}
				sealed, err := notification.SealSensitivePayload([]byte(config.Runtime.IdentityEnrollmentDeliveryKey), delivery)
				if err != nil {
					return err
				}
				_, err = notificationStore.EnqueueTx(recordCtx, tx, notification.Event{
					ID:       "identity-enrollment-verification-" + item.ID,
					TenantID: scope.TenantID, DepartmentID: scope.DepartmentID, ApplicationID: scope.ApplicationID,
					Topic: "identity.enrollment.v1", EventType: notification.EnrollmentVerificationEventType,
					PartitionKey: scope.TenantID + ":" + item.Username,
					Payload:      map[string]any{"registration_id": item.ID, "sealed_delivery": sealed},
				})
				if err != nil {
					return fmt.Errorf("enqueue encrypted identity verification notification: %w", err)
				}
				return nil
			})
		}
		if config.Runtime.DemoIdentityBootstrap {
			if err := seedModularDemoIdentities(ctx, identityStore); err != nil {
				log.Fatal(err)
			}
		}
		if os.Getenv("PLATFORM_RUN_EXECUTOR") == "platform" {
			workers := config.Runtime.RunWorkers
			if workers == 0 {
				workers = 4 // Programmatic test config; environment-loaded configs are always explicit.
			}
			gateway := agentgateway.RemoteAdapter{
				Transport: agentgateway.RoutingTransport{
					HTTP: agentgateway.NewHTTPTransport(&http.Client{Timeout: 5 * time.Minute, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}),
					GRPC: agentgateway.GRPCTransport{},
				},
				Timeout: 5 * time.Minute,
			}
			executionModule = execution.NewModuleWithDispatcherAndSharedRepository(config.Runtime.InternalToken, sqlStore, execution.NewDispatcherWithGateway(sqlStore, config.Runtime.InternalToken, gateway, workers))
		} else {
			executionModule = execution.NewModuleWithSharedRepository(config.Runtime.InternalToken, sqlStore)
		}
		if config.Runtime.PolicyResolverMode == "sql" {
			resolver := policyasset.NewSQLResolver(sqlStore.DB())
			if err := seedPolicySnapshots(ctx, resolver, config.Runtime.PolicyBootstrapJSON); err != nil {
				log.Fatal(err)
			}
			if err := resolver.EnsurePromptTemplates(ctx, config.Runtime.PromptTemplatesJSON); err != nil {
				log.Fatal(err)
			}
			policyResolver = resolver
		}
		persistentMemory, err := capability.NewSQLMemoryStore(sqlStore.DB())
		if err != nil {
			log.Fatal(err)
		}
		memoryStore = persistentMemory
		persistentMemory.SetAuthorizationContinuityGuard(identityStore.AcquirePermissionReadContinuity)
		persistentState, err := capability.NewSQLCheckpointStore(sqlStore.DB())
		if err != nil {
			log.Fatal(err)
		}
		persistentState.SetContinuityGuard(func(ctx context.Context, tx *sql.Tx, scope sharedkernel.Scope, lease sharedkernel.ExecutionLeaseBinding) error {
			if err := identityStore.AcquirePermissionReadContinuity(ctx, tx); err != nil {
				return err
			}
			// The later current-authority check reads parent leases. Take their
			// Run fences before locking this child, matching parent stop control.
			if err := lockCheckpointAncestors(ctx, tx, sqlStore, evaluationBudgetAuthority, scope); err != nil {
				return err
			}
			return sqlStore.CheckCapabilityLeaseTx(ctx, tx, scope, lease)
		})
		persistentState.SetAuditRecorder(auditStore)
		checkpointStore = persistentState
		sqlStore.SetRecoveryCheckpointCapture(persistentState.CaptureRecoveryCheckpointsTx)
		executionModule.SetRecoveryCheckpointReader(func(ctx context.Context, scope sharedkernel.Scope, reference contract.RecoveryCheckpointReference) (map[string]any, error) {
			checkpoint, err := persistentState.LoadReference(ctx, scope, reference)
			if err != nil {
				return nil, err
			}
			return checkpoint.Value, nil
		})
		executionModule.SetRecoveryRenewalCheckpointReader(func(ctx context.Context, scope sharedkernel.Scope, reference contract.RecoveryCheckpointReference) (map[string]any, error) {
			checkpoint, err := persistentState.LoadRenewalReference(ctx, scope, reference)
			if err != nil {
				return nil, err
			}
			return checkpoint.Value, nil
		})
		toolApprovalStore, err = capability.NewSQLToolApprovalStore(sqlStore.DB())
		if err != nil {
			log.Fatal(err)
		}
		toolApprovalStore.SetAuditRecorder(auditStore)
		persistentModelStore, err := capability.NewSQLModelInvocationStore(sqlStore.DB())
		if err != nil {
			log.Fatal(err)
		}
		modelInvocationStore = persistentModelStore
		persistentToolStore, err := capability.NewSQLToolInvocationStore(sqlStore.DB())
		if err != nil {
			log.Fatal(err)
		}
		persistentToolStore.SetAuditRecorder(auditStore)
		toolInvocationStore = persistentToolStore
	}
	var checkCoordinatedAncestry func(context.Context, sharedkernel.Scope) error
	var isCoordinatedBusinessRun func(context.Context, sharedkernel.Scope) bool
	var coordinationRouteStore *agentcoordination.SQLRouteStore
	if conversationStore != nil {
		// Execution publishes Run input through a narrow Port so product history
		// is durable without making the runtime depend on conversation SQL.
		// Execution 通过窄 Port 投影 Run 输入，运行时不依赖会话 SQL 实现。
		executionModule.SetConversationRecorder(conversationStore)
	}
	if identityStore != nil {
		// Resolve the reviewer from current identity state, not browser-supplied roles.
		// 审核角色以实时身份数据为准，不信任浏览器声明。
		executionModule.SetReviewPermissionAuthorizer((identityBusinessReviewControl{store: identityStore}).Authorize)
		identityStore.SetPermissionTaskResolver(permissionTaskResolver{runs: executionModule})
		executionModule.SetBrowserRunAuthorizer((identityExecutionBrowserControl{store: identityStore, runs: sqlStore}).Authorize)
	}
	if auditStore != nil {
		executionModule.SetReviewAuditRecorder(func(ctx context.Context, scope sharedkernel.Scope, reviewerID, action string) error {
			var id [16]byte
			if _, err := rand.Read(id[:]); err != nil {
				return err
			}
			return auditStore.Record(ctx, audit.Event{
				ID: hex.EncodeToString(id[:]), TenantID: scope.TenantID,
				DepartmentID: scope.DepartmentID, ApplicationID: scope.ApplicationID,
				ActorType: "user", ActorID: reviewerID, TraceID: scope.TraceID,
				AggregateType: "agent_run", AggregateID: scope.RunID, Action: action,
				Outcome: "attempted", Summary: "Agent 人工审核受控访问",
				CreatedAt: time.Now().UTC(),
			})
		})
	}
	if err := modules.Register(executionModule); err != nil {
		log.Fatal(err)
	}
	if catalogStore != nil {
		configureCatalogRelease(catalogStore, identityStore, auditStore)
		catalogModule = catalog.NewModuleWithScopeValidator(catalogStore, config.Runtime.InternalToken, identityStore)
		if identityStore != nil {
			identityStore.SetCapabilityResourceResolver(publishedPermissionResourceResolver{catalog: catalogStore, policies: policyResolver})
			catalogModule.SetAgentAccessChecker(identityCatalogAccess{store: identityStore})
			catalogModule.SetControlAuthorizer(identityCatalogControl{store: identityStore})
			if identityModule != nil {
				if availableAgents, ok := any(catalogStore).(catalog.AvailableAgentReader); ok {
					identityModule.SetAgentInstallationResolver(identityCatalogInstallationResolver{reader: availableAgents})
				}
				executionModule.SetMachineAccessPorts(machineIdentityAdapter{module: identityModule}, machineCatalogAdapter{module: catalogModule})
				executionModule.SetMachineRunPolicyResolver(conversationPolicyAdapter{resolver: policyResolver})
				executionModule.SetAuthorizationEpochResolver((identityConversationAgentRunAuthorizer{store: identityStore}).CurrentAuthorizationEpoch)
			}
		}
		if err := modules.Register(catalogModule); err != nil {
			log.Fatal(err)
		}
	}
	if usageStore != nil {
		telemetry.SetBudgetReconciliationSource(func(ctx context.Context) (telemetry.BudgetReconciliationMetrics, error) {
			snapshot, err := usageStore.ReconciliationSnapshot(ctx)
			return telemetry.BudgetReconciliationMetrics{Pending: snapshot.Pending, OldestAt: snapshot.OldestAt}, err
		})
		usageModule := usagecost.NewModule(usageStore, config.Runtime.InternalToken)
		usageModule.SetAuthorizer(identityUsageControl{store: identityStore})
		if err := modules.Register(usageModule); err != nil {
			log.Fatal(err)
		}
	}
	if modelGovernanceStore != nil {
		modelModule := modelgovernance.NewModule(modelGovernanceStore, config.Runtime.InternalToken, identityModelGovernanceControl{store: identityStore})
		if err := modules.Register(modelModule); err != nil {
			log.Fatal(err)
		}
	}
	if agentFactoryStore != nil {
		factoryModule := agentfactory.NewModule(agentFactoryStore, identityAgentFactoryControl{store: identityStore}, config.Runtime.InternalToken)
		if err := modules.Register(factoryModule); err != nil {
			log.Fatal(err)
		}
	}
	if policyAssetStore != nil {
		policyModule := policyasset.NewModule(policyAssetStore, identityPolicyAssetControl{store: identityStore}, config.Runtime.InternalToken)
		if err := modules.Register(policyModule); err != nil {
			log.Fatal(err)
		}
	}
	if sqlStore != nil && identityStore != nil && auditStore != nil {
		knowledgeService := knowledgeControl{persistence: knowledgePersistence{db: sqlStore.DB(), iam: identityStore, execution: sqlStore, audit: auditStore}, targets: catalogStore, policies: policyResolver}
		knowledgeModule = knowledge.NewControlModule(config.Runtime.InternalToken, knowledgeService)
		knowledgeModule.SetIndexService(knowledgeService)
		if err := modules.Register(knowledgeModule); err != nil {
			log.Fatal(err)
		}
	}
	auditContentControl := &identityAuditContentControl{store: identityStore, runs: executionModule}
	if auditStore != nil {
		auditModule := audit.NewModule(auditStore, config.Runtime.InternalToken)
		if identityStore != nil {
			auditModule.SetMetadataAuthorizer((identityAuditMetadataControl{store: identityStore}).Authorize)
			auditModule.SetContentAuthorizer(auditContentControl.Authorize)
		}
		if err := modules.Register(auditModule); err != nil {
			log.Fatal(err)
		}
	}
	if identityStore != nil {
		if err := modules.Register(identityModule); err != nil {
			log.Fatal(err)
		}
	}
	if notificationStore != nil {
		if err := notification.CheckDeadLetterSchema(ctx, sqlStore.DB()); err != nil {
			log.Fatal("Kafka dead-letter schema requires explicit migration")
		}
		deadLetters, err := notification.NewSQLDeadLetterStore(sqlStore.DB())
		if err != nil {
			log.Fatal("Kafka dead-letter store unavailable")
		}
		dlqAccess := deadLetterAuthority{iam: identityStore, outbox: notificationStore, audit: auditStore, cancellation: cancellationChannel}
		if err = deadLetters.SetOperations(dlqAccess.Authorize, dlqAccess.Record, dlqAccess.Redrive); err != nil {
			log.Fatal("Kafka dead-letter control unavailable")
		}
		// The platform owns the durable Outbox and injects the concrete event bus
		// only when EVENT_BUS_MODE=kafka. Without that explicit mode the module
		// remains local and a missing ChannelAdapter fails closed at dispatch.
		// 平台拥有持久化 Outbox；只有显式 EVENT_BUS_MODE=kafka 才注入真实事件总线。
		var channel notification.ChannelAdapter
		if config.Runtime.NotificationAdapter == "audit" {
			channel = auditStore.NotificationChannel()
		}
		if config.Runtime.NotificationAdapter == "webhook" {
			webhook := config.Runtime.NotificationWebhookURL
			adapter, err := notification.NewHTTPAdapter(webhook)
			if err != nil {
				log.Fatal(err)
			}
			channel = adapter
			if len(config.Runtime.IdentityEnrollmentDeliveryKey) == 32 {
				channel = notification.SensitivePayloadAdapter{Inner: adapter, Key: []byte(config.Runtime.IdentityEnrollmentDeliveryKey)}
			}
		}
		if identityStore != nil {
			channel = notification.VersionedAuthorizationAdapter{Inner: channel, ReadRevision: readAuthorizationRevision(identityStore)}
		}
		if cancellationEnabled {
			cancellationChannel.fallback = channel
			channel = cancellationChannel
		}
		var eventBus notification.EventBus
		if config.Runtime.EventBusMode == "kafka" {
			bus, err := notification.NewKafkaGoEventBus(notification.KafkaGoConfig{
				Brokers:          splitCSV(config.Runtime.KafkaBrokers),
				ClientID:         config.Runtime.KafkaClientID,
				Topic:            config.Runtime.KafkaNotificationTopic,
				AdditionalTopics: []string{"platform.audit", "platform.notification", "agent-platform.identity.v1"},
				GroupID:          config.Runtime.KafkaNotificationGroup,
				DLQTopic:         config.Runtime.KafkaNotificationDLQ,
				MaxAttempts:      config.Runtime.KafkaMaxAttempts,
				RetryBackoff:     config.Runtime.KafkaRetryBackoff,
				DeadLetters:      deadLetters,
			})
			if err != nil {
				log.Fatal(err)
			}
			eventBus = bus
		}
		var notificationModule *notification.Module
		if eventBus != nil {
			notificationModule = notification.NewModuleWithEventBus(notificationStore, eventBus, channel, config.Runtime.InternalToken)
		} else {
			notificationModule = notification.NewModule(notificationStore, channel, config.Runtime.InternalToken)
		}
		if err := notificationModule.SetDeadLetterOperations(deadLetters, dlqAccess.ResolveBrowser); err != nil {
			log.Fatal("Kafka dead-letter browser boundary unavailable")
		}
		if err := modules.Register(notificationModule); err != nil {
			log.Fatal(err)
		}
		cancellationNotifications = notificationModule
	}
	if conversationStore != nil {
		// Conversation history is a platform-owned projection.  Managed views
		// remain disabled by default and must be enabled by an explicit IAM
		// adapter in a later deployment profile.
		// 会话历史由平台统一拥有；托管视图默认关闭，后续部署配置显式接入 IAM 后再开启。
		conversationModule := conversation.NewModule(conversationStore, config.Runtime.InternalToken, false)
		conversationModule.SetAccessControl(identityConversationAccess{store: identityStore})
		conversationStore.SetErasurePorts(
			func(ctx context.Context, scope conversation.Scope, resource conversation.SessionResource) error {
				return (identityConversationAccess{store: identityStore}).Authorize(ctx, scope, resource, "business.review")
			},
			func(ctx context.Context, tx *sql.Tx, scope conversation.Scope, sessionID string) (bool, error) {
				return sqlStore.SessionQuiescentTx(ctx, tx, sharedkernel.Scope{TenantID: scope.TenantID, DepartmentID: scope.DepartmentID, ApplicationID: scope.ApplicationID}, sessionID)
			},
			func(ctx context.Context, tx *sql.Tx, scope conversation.Scope, receipt conversation.ErasureReceipt) error {
				return auditStore.RecordTx(tx, audit.Event{ID: "conversation-erased-" + receipt.RequestID, TenantID: scope.TenantID, DepartmentID: scope.DepartmentID, ApplicationID: scope.ApplicationID, ActorType: "service_principal", ActorID: "platform.conversation.erasure", TraceID: scope.TraceID, AggregateType: "conversation_deletion", AggregateID: receipt.RequestID, Action: "conversation.payload.erased", Outcome: "success", Summary: "Conversation payload erasure receipt " + receipt.Digest, CreatedAt: receipt.ErasedAt})
			},
		)
		conversationModule.SetErasureWorkerEnabled(envBool("PLATFORM_CONVERSATION_ERASURE_ENABLED", true))
		conversationModule.SetRunReplayResolver(conversationRunReplay{repository: sqlStore, sessions: conversationStore})
		conversationStore.SetPublicShareAccessControl(identityConversationAccess{store: identityStore})
		if identityStore != nil {
			conversationModule.SetPrincipalRoleResolver(func(ctx context.Context, scope conversation.Scope) ([]string, error) {
				if scope.PrincipalType != string(identity.PrincipalUser) {
					return nil, identity.ErrInvalidPrincipal
				}
				principal, err := identityStore.GetPrincipal(ctx, identity.PrincipalUser, scope.PrincipalID)
				if err != nil {
					return nil, err
				}
				if !principal.IsActive || principal.TenantID != scope.TenantID {
					return nil, identity.ErrScopeMismatch
				}
				{
					snapshot, err := identityStore.PermissionSnapshot(ctx, identity.PrincipalUser, scope.PrincipalID)
					if err != nil {
						return nil, err
					}
					if snapshot.Mode != "legacy" && snapshot.Mode != "shadow" {
						return []string{}, nil
					}
				}
				return principal.Roles, nil
			})
		}
		conversationModule.SetRunStarter(executionModule)
		conversationModule.SetRuntimeBindingResolver(catalogConversationRuntimeBindings{
			targets:   catalogModule,
			authorize: identityConversationAgentRunAuthorizer{store: identityStore},
		})
		if policyResolver != nil {
			conversationModule.SetRunPolicyResolver(conversationPolicyAdapter{resolver: policyResolver})
		}
		if contextSigner != nil {
			conversationModule.SetContextTokenSigner(contextSigner)
			executionModule.SetMachineRunContextSigner(contextSigner)
			executionModule.SetDispatchSecurity(contextSigner, func(ctx context.Context, scope sharedkernel.Scope) error {
				if scope.ParentRunID != "" {
					if checkCoordinatedAncestry == nil {
						return errors.New("parented execution authority denied")
					}
					if err := checkCoordinatedAncestry(ctx, scope); err != nil {
						// Keep lock-wait errors so a heartbeat can tell an
						// unfinished ancestor row from a finished denial.
						// Rewriting the SQLSTATE makes that tick cancel the child.
						if ancestryLockWait(err) {
							return err
						}
						return errors.New("parented execution authority denied")
					}
				} else {
					epoch, versionErr := (identityConversationAgentRunAuthorizer{store: identityStore}).CurrentAuthorizationEpoch(ctx, scope, "run")
					if versionErr != nil || epoch != scope.AuthorizationEpoch {
						return errors.New("execution IAM authorization version changed")
					}
					allowed, err := (identityConversationAgentRunAuthorizer{store: identityStore}).AuthorizeConversationRun(ctx, scope)
					if err != nil || !allowed {
						return errors.New("current execution grant denied")
					}
					if coordinationRouteStore != nil {
						pinRoute := agentRouteAuthority{identity: identityStore, runs: sqlStore, routes: coordinationRouteStore}
						if pinRoute.PinRootMachineAuthority(ctx, scope) != nil {
							return errors.New("root workload authority changed")
						}
					}
				}
				target, err := catalogModule.ResolveEvaluationAgentTarget(ctx, scope, scope.AgentID, scope.AgentVersionID)
				if err != nil || target.InstallationID != scope.InstallationID || target.AgentVersionID != scope.AgentVersionID {
					return errors.New("current execution installation denied")
				}
				return nil
			})
		}
		if err := modules.Register(conversationModule); err != nil {
			log.Fatal(err)
		}
	}
	evaluationModes, modesErr := loadEvaluationSimulationProfiles(strings.TrimSpace(os.Getenv("PLATFORM_EVALUATION_SIMULATION_PROFILES_FILE")), strings.TrimSpace(os.Getenv("PLATFORM_API_BINDINGS_FILE")), catalogModule, policyResolver)
	if modesErr != nil {
		log.Fatal("evaluation simulation profiles are invalid")
	}
	var evaluationProductModule *evaluationproduct.Module
	if evaluationProductStore != nil {
		evaluationSources := evaluationInspection{catalog: catalogModule, execution: executionModule, runs: sqlStore, identity: identityStore, audit: auditStore, usage: usageStore}
		telemetry.SetEvaluationQueueSource(func(ctx context.Context) (telemetry.EvaluationQueueMetrics, error) {
			snapshot, err := evaluationProductStore.QueueSnapshot(ctx)
			return telemetry.EvaluationQueueMetrics{Depth: snapshot.Depth, OldestQueuedAt: snapshot.OldestQueuedAt}, err
		})
		var dispatcher evaluationproduct.Dispatcher
		if catalogModule != nil && identityStore != nil && policyResolver != nil && contextSigner != nil {
			options, e := evaluationRunnerOptions()
			if e != nil {
				log.Fatal("evaluation worker time limits are invalid")
			}
			runner, err := evaluationproduct.NewRunner(
				evaluationProductStore,
				evaluationAgentInvoker{catalog: catalogModule, store: evaluationProductStore, identity: identityStore, policies: policyResolver, signer: contextSigner, execution: executionModule, modes: evaluationModes, sources: evaluationSources},
				evaluationproduct.RemoteMetricEvaluator{
					URL:     strings.TrimSpace(os.Getenv("PLATFORM_METRIC_RUNNER_URL")),
					Token:   strings.TrimSpace(os.Getenv("PLATFORM_METRIC_RUNNER_TOKEN")),
					Timeout: envDuration("PLATFORM_METRIC_RUNNER_TIMEOUT", 20*time.Second),
				},
				evaluationProductStore,
				options,
			)
			if err != nil {
				log.Fatal("configure evaluation product runner: ", err)
			}
			telemetry.SetEvaluationWorkerSource(func() telemetry.EvaluationWorkerMetrics {
				stats := runner.Stats()
				return telemetry.EvaluationWorkerMetrics{
					ClaimFailures: stats.ClaimFailures, FinalizeFailures: stats.FinalizeFailures,
					Active: stats.Active, Capacity: stats.Capacity, Ready: stats.Ready,
				}
			})
			dispatcher = runner
		} else if config.Runtime.Environment != "development" {
			log.Fatal("evaluation product requires Catalog, Identity, policy resolver, and platform context signer")
		} else {
			log.Print("evaluation product dispatcher unavailable: Catalog, Identity, policy resolver, and platform context signer are required")
		}
		productModule := evaluationproduct.NewModule(evaluationProductStore, config.Runtime.InternalToken, identityEvaluationProductControl{store: identityStore}, dispatcher)
		evaluationProductModule = productModule
		productModule.SetModeAdmission(evaluationModes)
		productModule.SetInspection(evaluationSources)
		productModule.SetSourceAuthorizer(evaluationSources)
		if err := modules.Register(productModule); err != nil {
			log.Fatal(err)
		}
	}
	var publicKey ed25519.PublicKey
	if encoded := config.Runtime.PlatformContextPublicKey; encoded != "" {
		raw, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil || len(raw) != ed25519.PublicKeySize {
			log.Fatal("PLATFORM_CONTEXT_PUBLIC_KEY must be base64 encoded Ed25519 public key")
		}
		publicKey = ed25519.PublicKey(raw)
	}
	// All copied authority interfaces retain this closure. Configure it once
	// before starting workers/HTTP; do not leave earlier provider copies stale.
	knowledgeAuthority := capabilityExecutionAuthority{execution: executionModule, identity: identityStore, catalog: catalogModule, ancestry: func(ctx context.Context, scope sharedkernel.Scope) error {
		if checkCoordinatedAncestry == nil {
			return nil
		}
		return checkCoordinatedAncestry(ctx, scope)
	}, isDelegatedBusinessRun: func(ctx context.Context, scope sharedkernel.Scope) bool {
		return isCoordinatedBusinessRun != nil && isCoordinatedBusinessRun(ctx, scope)
	}}
	var knowledgeSourceDB *sql.DB
	if sqlStore != nil {
		knowledgeSourceDB = sqlStore.DB()
	}
	knowledgeProvider, knowledgeDB, err := knowledgeProviderFromConfig(ctx, config.Runtime, knowledgeSourceDB, knowledgeAuthority)
	if err != nil {
		log.Fatal(err)
	}
	if knowledgeDB != nil {
		defer knowledgeDB.Close()
	}
	capabilityModule := capability.NewModuleWithGovernanceAndToolLedger(config.Runtime.InternalToken, config.Runtime.InternalSigningSecret, publicKey, config.Runtime.PlatformContextIssuer, config.Runtime.PlatformContextAudience, knowledgeProvider, policyResolver, memoryStore, modelInvocationStore, toolInvocationStore)
	capabilityModule.EnableDevelopmentMock(config.Runtime.Environment)
	capabilityModule.SetCheckpointStore(checkpointStore)
	if sqlStore != nil {
		sqlStore.SetRecoveryFailureDisposition(func(err error) bool {
			return errors.Is(err, capability.ErrStateContinuityLost)
		}, capabilityModule.CheckTaskEffectQuiescence)
	}
	if sqlStore != nil {
		sqlStore.SetTerminalOutcomeFence(func(ctx context.Context, tx *sql.Tx, scope sharedkernel.Scope) error {
			// The caller owns Run UPDATE. New model/tool execution and child
			// admission must acquire that same row before any external effect.
			if coordinationRouteStore != nil {
				if err := coordinationRouteStore.CheckDescendantStopTx(ctx, tx, scope); err != nil {
					return err
				}
			}
			return capabilityModule.CheckTaskEffectQuiescence(ctx, scope)
		})
	}
	if sqlStore != nil && identityStore != nil && auditStore != nil {
		skillStore, err := capability.NewSQLSkillStore(sqlStore.DB())
		if err != nil {
			log.Fatal("skill registry unavailable")
		}
		skillStore.SetAuditRecorder(auditStore)
		skillAccess := skillAuthority{identity: identityStore, runs: sqlStore, resources: knowledgeAuthority}
		skillStore.SetAuthorizer(skillAccess.Authorize)
		skillStore.SetTransactionFence(skillAccess)
		registry, err := capability.NewSkillRegistry(skillStore)
		if err != nil {
			log.Fatal("skill registry unavailable")
		}
		capabilityModule.SetSkillRegistry(registry)
		routeStore, err := agentcoordination.NewSQLRouteStore(sqlStore.DB())
		if err != nil {
			log.Fatal("agent route store unavailable")
		}
		routeStore.SetAuditRecorder(auditStore)
		routeStore.SetAuthority(agentRouteAuthority{identity: identityStore, runs: sqlStore, catalog: catalogModule, resources: knowledgeAuthority, routes: routeStore})
		if persistentState, ok := checkpointStore.(*capability.SQLCheckpointStore); ok {
			sqlStore.SetAgentGroupWaitPorts(persistentState.CaptureAgentGroupWaitTx, routeStore.ValidateGroupWaitTx)
			sqlStore.SetAgentGroupStopBarrier(func(ctx context.Context, tx *sql.Tx, scope sharedkernel.Scope, handoff contract.AgentGroupHandoff) error {
				if err := routeStore.GroupStopQuiescentTx(ctx, tx, scope, handoff); err != nil {
					return err
				}
				return routeStore.CheckDescendantStopTx(ctx, tx, scope)
			})
			sqlStore.SetAgentGroupResumeQuiescence(capabilityModule.CheckTaskEffectQuiescence)
			sqlStore.SetAgentGroupWaitFence((agentRouteAuthority{identity: identityStore, runs: sqlStore, catalog: catalogModule, resources: knowledgeAuthority, routes: routeStore}).GroupWaitFenceTx)
		} else {
			log.Fatal("persistent agent group wait state unavailable")
		}
		router, err := agentcoordination.NewRouter(routeStore)
		if err != nil {
			log.Fatal("agent router unavailable")
		}
		capabilityModule.SetAgentRouter(router)
		coordinationRouteStore = routeStore
		routeAuthority := agentRouteAuthority{identity: identityStore, runs: sqlStore, catalog: catalogModule, resources: knowledgeAuthority, routes: routeStore}
		ancestry := coordinatedAncestryGuard{route: routeAuthority}
		if evaluationProductStore != nil {
			evaluationAuthority := &evaluationExecutionAuthority{products: evaluationProductStore, route: routeAuthority, policies: policyResolver, catalog: catalogModule}
			evaluationBudgetAuthority = evaluationAuthority
			routeStore.SetExternalRootVerifier(evaluationAuthority.VerifyExternalRootTx)
			ancestry.evaluation = evaluationAuthority
			executionModule.SetSynchronousRunAuthorizer(evaluationAuthority.AuthorizeSynchronous)
			if err := sqlStore.SetSynchronousCreationGuard(evaluationAuthority.AuthorizeSynchronousCreationTx); err != nil {
				log.Fatal("evaluation child creation fence unavailable")
			}
			executionModule.SetSynchronousRunAbortCheck(evaluationAuthority.ParentAborted)
			if err := sqlStore.SetCompletedEvaluationCompensationAuthority(evaluationAuthority.AuthorizeCompletedCompensationTx); err != nil {
				log.Fatal("completed evaluation inverse authority unavailable")
			}
			if evaluationProductModule != nil {
				evaluationProductModule.SetCancellationCoordinator(evaluationCancellationCoordinator{authority: evaluationAuthority, runs: sqlStore, products: evaluationProductStore, execution: executionModule, capabilities: capabilityModule})
			}
		}
		checkCoordinatedAncestry = ancestry.Check
		isCoordinatedBusinessRun = ancestry.IsDelegatedBusinessRun
		executionModule.SetCoordinatedGuard(ancestry.Check)

		identityStore.SetCapabilityResourceResolver(publishedPermissionResourceResolver{catalog: catalogStore, policies: policyResolver, skills: skillStore})
		capabilityModule.SetSkillControlPlane(&capability.SkillControlPlane{Registry: registry, Resolve: skillAccess.ResolveBrowser})
	}
	capabilityModule.SetToolConfirmationAuthority(toolApprovalStore)
	if keyFile := strings.TrimSpace(os.Getenv("PLATFORM_TOOL_CONFIRMATION_PUBLIC_KEY_FILE")); keyFile != "" {
		file, err := os.Open(keyFile)
		if err != nil {
			log.Fatal("tool confirmation verification key unavailable")
		}
		body, readErr := io.ReadAll(io.LimitReader(file, 1025))
		file.Close()
		if readErr != nil || len(body) > 1024 {
			log.Fatal("tool confirmation verification key invalid")
		}
		raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(body)))
		verifier, verifyErr := capability.NewToolConfirmationVerifier(ed25519.PublicKey(raw))
		if err != nil || verifyErr != nil || bytes.Equal(raw, publicKey) {
			log.Fatal("tool confirmation must use a distinct verification key")
		}
		capabilityModule.SetToolConfirmationVerifier(verifier)
	}
	if bindingsFile := strings.TrimSpace(os.Getenv("PLATFORM_MCP_BINDINGS_FILE")); bindingsFile != "" {
		file, err := os.Open(bindingsFile)
		if err != nil {
			log.Fatal("MCP binding configuration is unavailable")
		}
		body, readErr := io.ReadAll(io.LimitReader(file, (1<<20)+1))
		file.Close()
		if readErr != nil || len(body) > 1<<20 {
			log.Fatal("MCP binding configuration exceeds limit")
		}
		var bindings []capability.MCPBinding
		decoder := json.NewDecoder(strings.NewReader(string(body)))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&bindings) != nil || decoder.Decode(new(any)) != io.EOF {
			log.Fatal("MCP binding configuration is invalid")
		}
		provider, err := capability.NewMCPToolProvider(bindings, modelgateway.MountedSecretResolver{Root: config.Runtime.ModelSecretRoot}, config.Runtime.Environment == "development", modelgateway.NewGuardedEndpointClient)
		if err != nil {
			log.Fatal("MCP provider configuration is invalid")
		}
		if err := capabilityModule.SetMCPToolProvider(provider); err != nil {
			log.Fatal("MCP runtime registration is invalid")
		}
	}
	if bindingsFile := strings.TrimSpace(os.Getenv("PLATFORM_API_BINDINGS_FILE")); bindingsFile != "" {
		file, err := os.Open(bindingsFile)
		if err != nil {
			log.Fatal("API binding configuration is unavailable")
		}
		body, readErr := io.ReadAll(io.LimitReader(file, (1<<20)+1))
		file.Close()
		if readErr != nil || len(body) > 1<<20 {
			log.Fatal("API binding configuration exceeds limit")
		}
		if len(evaluationModes.profiles) > 0 {
			digest := sha256.Sum256(body)
			if hex.EncodeToString(digest[:]) != evaluationModes.bindingsHash {
				log.Fatal("evaluation provider configuration changed during startup")
			}
		}
		var bindings []capability.APIBinding
		decoder := json.NewDecoder(strings.NewReader(string(body)))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&bindings) != nil || decoder.Decode(new(any)) != io.EOF {
			log.Fatal("API binding configuration is invalid")
		}
		provider, err := capability.NewAPIToolProvider(bindings, modelgateway.MountedSecretResolver{Root: config.Runtime.ModelSecretRoot}, config.Runtime.Environment == "development", modelgateway.NewGuardedEndpointClient)
		if err != nil || capabilityModule.SetAPIToolProvider(provider) != nil {
			log.Fatal("API provider configuration is invalid")
		}
	}
	capabilityModule.SetLiveExecutionAuthority(knowledgeAuthority)
	if executionModule != nil {
		executionModule.SetEventReadAuthority(knowledgeAuthority.AuthorizeEventRead)
	}
	capabilityModule.SetModelBillingAuthorizer(identityModelGovernanceControl{store: identityStore})
	if executionModule != nil {
		executionModule.SetStopQuiescence(capabilityModule.CheckTaskEffectQuiescence)
		receiptDir := strings.TrimSpace(os.Getenv("PLATFORM_EXECUTION_STOP_RECEIPT_DIR"))
		keyFile := strings.TrimSpace(os.Getenv("PLATFORM_EXECUTION_STOP_RECEIPT_KEY_FILE"))
		if receiptDir != "" || keyFile != "" {
			key, err := os.ReadFile(keyFile)
			if receiptDir == "" || keyFile == "" || err != nil || len(key) != 32 {
				log.Fatal("runtime stop receipt verifier requires a controller-owned directory and 32-byte key file")
			}
			executionModule.SetStopEvidenceVerifier(execution.FileStopEvidence{Directory: receiptDir, Key: key})
		}
	}
	if notificationStore != nil {
		adapter := platformNotificationToolAdapter{outbox: notificationStore}
		if sqlStore != nil {
			guard, ok := toolInvocationStore.(capability.ToolCommitGuard)
			if !ok {
				log.Fatal("persistent notification tool guard is required")
			}
			adapter.db, adapter.guard = sqlStore.DB(), guard
		}
		capabilityModule.SetNotificationToolPort(adapter)
	}
	if modelGovernanceStore != nil && policyResolver != nil && len(config.Runtime.ModelEndpointMappings) > 0 {
		capacityProvider := modelcapacity.NewSQLProvider(sqlStore.DB())
		capacityProvider.SetDeploymentReader(modelGovernanceStore)
		// Composition root injects the capacity Port; governance owns no foreign
		// SQL implementation. / 组合根注入容量Port，治理模块不构造其他模块SQL实现。
		accessResolver := modelgovernance.AccessResolver{Store: modelGovernanceStore, Capacity: capacityProvider}
		modelHTTPConfig, timeoutErr := governedModelHTTPConfig(config.Runtime.ModelSecretRoot, config.Runtime.Environment == "development")
		if timeoutErr != nil {
			log.Fatal("configure governed model deadlines: ", timeoutErr)
		}
		modelAdapter, adapterErr := modelgateway.NewHTTPAdapter(modelHTTPConfig, accessResolver, modelGovernanceStore, modelGovernanceStore,
			modelgateway.MountedSecretResolver{Root: config.Runtime.ModelSecretRoot},
			modelgateway.StaticEndpointResolver(config.Runtime.ModelEndpointMappings),
		)
		if adapterErr != nil {
			log.Fatal("configure governed model gateway: ", adapterErr)
		}
		capabilityModule.SetGovernedModelInvocation(accessResolver, modelAdapter)
		capabilityModule.SetModelCapacity(capacityProvider)
	} else if config.Runtime.Environment != "development" && policyResolver != nil {
		log.Fatal("non-development SQL policy runtime requires a configured governed model gateway")
	}
	runTreeBudgetSetting := strings.TrimSpace(os.Getenv("PLATFORM_RUN_TREE_BUDGET_ENABLED"))
	if runTreeBudgetSetting != "" && runTreeBudgetSetting != "true" && runTreeBudgetSetting != "false" {
		log.Fatal("PLATFORM_RUN_TREE_BUDGET_ENABLED must be true or false")
	}
	runTreeBudgetEnabled := runTreeBudgetSetting == "true"
	legacyBudgetIDs := strings.TrimSpace(os.Getenv("PLATFORM_LEGACY_MODEL_ACCOUNTING_RESERVATIONS"))
	if legacyBudgetIDs != "" && !runTreeBudgetEnabled {
		log.Fatal("legacy model accounting allowlist requires shared Run budget mode")
	}
	if runTreeBudgetEnabled && (sqlStore == nil || usageStore == nil || modelGovernanceStore == nil || identityStore == nil || auditStore == nil || coordinationRouteStore == nil) {
		log.Fatal("shared Run budget requires persistent execution, identity, coordination, audit and model billing")
	}
	if usageStore != nil {
		capabilityModule.SetUsageRecorder(usageStore)
		if modelGovernanceStore != nil {
			var modelBudgets usagecost.ModelBudgetStore = usageStore
			if runTreeBudgetEnabled {
				models, ok := modelInvocationStore.(*capability.SQLModelInvocationStore)
				if !ok {
					log.Fatal("shared Run budget requires persistent model receipts")
				}
				tree := usagecost.NewSQLRunTreeBudgetStore(sqlStore.DB())
				cancellationBudgetTree = tree
				tree.SetAuditRecorder(auditStore)
				modelAuthority := treeModelBudgetAuthority{tree: tree, models: models}
				routeAuthority := agentRouteAuthority{identity: identityStore, runs: sqlStore, catalog: catalogModule, resources: knowledgeAuthority, routes: coordinationRouteStore}
				tree.SetAuthority(runTreeBudgetAuthority{route: routeAuthority, evaluation: evaluationBudgetAuthority, verifyOutcome: modelAuthority.VerifyOutcome})
				tools, ok := toolInvocationStore.(*capability.SQLToolInvocationStore)
				if !ok {
					log.Fatal("shared Run budget requires persistent tool admission")
				}
				tools.SetExecutionAdmission(tree.CheckRuntimeAdmissionTx)
				coordinationRouteStore.SetChildExecutionAdmitter(childExecutionAdmitter{route: routeAuthority, budget: tree, quiescence: capabilityModule.CheckTaskEffectQuiescence})
				sqlStore.SetRecoveryDescendantBarrier(coordinationRouteStore.CheckDescendantStopTx)
				stopChildren := &coordinatedStopReconciler{db: sqlStore.DB(), runs: sqlStore, routes: coordinationRouteStore, audit: auditStore, route: agentRouteAuthority{identity: identityStore, runs: sqlStore, catalog: catalogModule, resources: knowledgeAuthority, routes: coordinationRouteStore}}
				executionModule.SetCoordinatedReconciler(stopChildren.Reconcile)
				childWorkers := min(max(1, config.Runtime.RunWorkers), 8)
				if value := strings.TrimSpace(os.Getenv("PLATFORM_CHILD_RUN_WORKERS")); value != "" {
					parsed, err := strconv.Atoi(value)
					if err != nil {
						log.Fatal("PLATFORM_CHILD_RUN_WORKERS must be an integer")
					}
					childWorkers = parsed
				}
				if err := executionModule.ConfigureDelegationCapacity(childWorkers); err != nil {
					log.Fatal("child workers must be 1..32 and root + 4*child workers must be <=128")
				}
				var legacyReservations []string
				if legacyBudgetIDs != "" {
					for _, id := range strings.Split(legacyBudgetIDs, ",") {
						legacyReservations = append(legacyReservations, strings.TrimSpace(id))
					}
				}
				combined, err := usagecost.NewSQLRunTreeModelBudgetStore(sqlStore.DB(), tree, usageStore, modelAuthority, legacyReservations...)
				if err != nil {
					log.Fatal("shared Run budget composition unavailable")
				}
				modelBudgets = combined
			}
			capabilityModule.SetModelBilling(modelGovernanceStore, modelBudgets)
		}
	}
	if identityStore != nil {
		identityStore.SetPermissionTaskResolver(permissionTaskResolver{runs: executionModule})
	}
	if err := modules.Register(capabilityModule); err != nil {
		log.Fatal(err)
	}
	if err := configureToolApprovalControl(capabilityModule, toolApprovalStore, toolApprovalAdapter{
		identity: identityStore, runs: executionModule, execution: executionModule, policy: policyResolver, resources: knowledgeAuthority, checkpoints: checkpointStore, runSQL: sqlStore,
		waitingAncestry: (coordinatedAncestryGuard{route: agentRouteAuthority{identity: identityStore, runs: sqlStore, catalog: catalogModule, resources: knowledgeAuthority, routes: coordinationRouteStore}}).CheckWaitingTx,
	}, publicKey); err != nil {
		log.Fatal(err)
	}
	if err := configureCodeRuntime(capabilityModule, sqlStore != nil && toolApprovalStore != nil, config.Runtime.Environment == "development", publicKey); err != nil {
		log.Fatal(err)
	}
	if err := configureReversibleAPIRuntime(capabilityModule, cancellationEnabled && sqlStore != nil && toolApprovalStore != nil, config.Runtime.Environment == "development", modelgateway.MountedSecretResolver{Root: config.Runtime.ModelSecretRoot}); err != nil {
		log.Fatal(err)
	}
	if cancellationEnabled {
		memory, memoryOK := memoryStore.(*capability.SQLMemoryStore)
		tools, toolsOK := toolInvocationStore.(*capability.SQLToolInvocationStore)
		if !memoryOK || !toolsOK {
			log.Fatal("cancellation requires persistent effect owners")
		}
		setup := cancellationSetup{runs: sqlStore, execution: executionModule, routes: coordinationRouteStore, capabilities: capabilityModule, tools: tools, memory: memory, tree: cancellationBudgetTree, iam: identityStore, evaluation: evaluationBudgetAuthority, outbox: notificationStore, notifications: cancellationNotifications, channel: cancellationChannel, audit: auditStore, domain: cancellationDomain}
		owner, err := setup.configure(ctx)
		if err != nil {
			log.Fatal("cancellation compensation composition unavailable; check migrated schema and installed owners")
		}
		indexCompensation = owner
	}
	if root := strings.TrimSpace(os.Getenv("PLATFORM_INDEX_WORKLOAD_SECRET_ROOT")); root != "" {
		if knowledgeModule == nil || sqlStore == nil || identityStore == nil || auditStore == nil || contextSigner == nil {
			log.Fatal("knowledge index worker requires SQL IAM, audit and context signer")
		}
		persistence := knowledgePersistence{db: sqlStore.DB(), iam: identityStore, execution: sqlStore, audit: auditStore, indexCompensation: indexCompensation}
		secrets := mountedIndexWorkloadSecrets{Root: root}
		if err := secrets.validateRoot(); err != nil {
			log.Fatal("knowledge index workload secret directory unavailable")
		}
		if err := knowledgeModule.SetWorker(persistence.indexWorker(contextSigner, capabilityModule, secrets)); err != nil {
			log.Fatal("configure knowledge index worker failed")
		}
	}
	// Fail closed if a production composition accidentally drops a trusted
	// module or reintroduces a legacy process as an in-process module.  The
	// manifest is data-only; future remote adapters can replace individual
	// module implementations without changing this process boundary.
	// 如果生产组合意外遗漏可信模块，或把遗留进程重新注册到本进程，立即失败。
	// 清单只描述组合边界，未来替换为远程 Adapter 时无需改动模块契约。
	if sqlStore != nil {
		if err := modules.ValidateRegistered(bootstrap.DefaultSingleProcessManifest()); err != nil {
			log.Fatal(err)
		}
	}
	config.Modules = modules
	publicModules := modules.Handler()
	if identityStore != nil {
		publicModules = bootstrap.BrowserSessionBoundary(publicModules, identityBrowserSessionCheck(identityStore))
	}
	config.PublicHandler = bootstrap.BrowserBoundary(publicModules, config.Runtime.BrowserGatewayToken, config.Runtime.InternalToken)
	var processDependencies []bootstrap.Dependency
	if sqlStore != nil {
		// The SQL pool is a process dependency, not an execution-module detail.
		// Bootstrap checks it before module Start and closes it after every module
		// has drained, preserving one-pool ownership for the modular monolith.
		processDependencies = append(processDependencies, bootstrap.NewSQLDependency(sqlStore.DB()))
	}
	if config.Runtime.EventBusMode == "kafka" {
		processDependencies = append(processDependencies, bootstrap.NewKafkaDependency(splitCSV(config.Runtime.KafkaBrokers)))
	}
	if len(processDependencies) > 0 {
		config.Bootstrap = bootstrap.NewBootstrap(config.Runtime, processDependencies...)
	}
	app := bootstrap.New(config)
	if err := app.Run(ctx); err != nil {
		log.Fatal(err)
	}
}

// conversationPolicyAdapter bridges the conversation product boundary to the
// platform-owned immutable policy resolver without coupling the module to SQL.
// conversationPolicyAdapter 把会话产品边界连接到平台不可变策略解析器，避免
// Conversation 模块直接依赖 SQL 实现。
type conversationPolicyAdapter struct{ resolver policyasset.Resolver }

// identityCatalogInstallationResolver exposes only published, active
// installations in the authenticated application scope to Identity.
// identityCatalogInstallationResolver 仅向 Identity 暴露可信应用范围内已发布且活动的安装。
type identityCatalogInstallationResolver struct{ reader catalog.AvailableAgentReader }

// identityEnrollmentCatalog exposes only requestable, active installations in
// the fixed enrollment scope. Browser input never chooses a tenant or endpoint.
type identityEnrollmentCatalog struct{ reader catalog.AvailableAgentReader }

func (r identityEnrollmentCatalog) ListRequestableEnrollmentAgents(ctx context.Context, scope identity.EnrollmentScope) ([]identity.EnrollmentAgent, error) {
	if r.reader == nil || strings.TrimSpace(scope.TenantID) == "" || strings.TrimSpace(scope.DepartmentID) == "" || strings.TrimSpace(scope.ApplicationID) == "" {
		return nil, identity.ErrEnrollmentUnavailable
	}
	items, err := r.reader.ListAvailableAgents(ctx, scope.TenantID, scope.DepartmentID, scope.ApplicationID)
	if err != nil {
		return nil, err
	}
	result := make([]identity.EnrollmentAgent, 0, len(items))
	for _, item := range items {
		result = append(result, identity.EnrollmentAgent{
			AgentID: item.AgentID, AgentInstanceID: item.InstallationID, Name: item.Name,
			SemanticVersion: item.SemanticVersion,
		})
	}
	return result, nil
}

func (r identityCatalogInstallationResolver) ResolveAgentInstallation(ctx context.Context, scope sharedkernel.Scope, installationID string) (identity.AgentInstallation, error) {
	return permissionresources.NewInstallationResolver(r.reader).ResolveAgentInstallation(ctx, scope, installationID)
}
func (a conversationPolicyAdapter) ResolveAgentPolicy(ctx context.Context, scope sharedkernel.Scope, versionID string) (map[string]any, error) {
	if a.resolver == nil {
		return nil, policyasset.ErrPolicyNotFound
	}
	snapshot, err := a.resolver.Resolve(ctx, scope, versionID)
	if err != nil {
		return nil, err
	}
	return snapshot.ExecutionInput()
}

type policyBootstrap struct {
	TenantID           string                      `json:"tenant_id"`
	DepartmentID       string                      `json:"department_id"`
	ApplicationID      string                      `json:"application_id"`
	AgentID            string                      `json:"agent_id"`
	AgentVersionID     string                      `json:"agent_version_id"`
	ModelProfileID     string                      `json:"model_profile_id"`
	PromptVersionID    string                      `json:"prompt_version_id"`
	ToolPolicyID       string                      `json:"tool_policy_id"`
	MemoryPolicyID     string                      `json:"memory_policy_id"`
	KnowledgePolicyID  string                      `json:"knowledge_policy_id"`
	RuntimePolicyID    string                      `json:"runtime_policy_id"`
	RuleBundleVersion  string                      `json:"rule_bundle_version,omitempty"`
	RuleBundleChecksum string                      `json:"rule_bundle_checksum,omitempty"`
	Revision           uint64                      `json:"revision"`
	Hash               string                      `json:"hash"`
	Model              policyasset.ModelPolicy     `json:"model"`
	Prompt             policyasset.PromptPolicy    `json:"prompt"`
	Tool               policyasset.ToolPolicy      `json:"tool"`
	Memory             policyasset.MemoryPolicy    `json:"memory"`
	Knowledge          policyasset.KnowledgePolicy `json:"knowledge"`
	Runtime            policyasset.RuntimePolicy   `json:"runtime"`
	Rule               policyasset.RulePolicy      `json:"rule"`
}

func seedPolicySnapshots(ctx context.Context, resolver *policyasset.SQLResolver, raw string) error {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	var entries []policyBootstrap
	if err := json.Unmarshal([]byte(raw), &entries); err != nil {
		return fmt.Errorf("invalid PLATFORM_POLICY_BOOTSTRAP_JSON: %w", err)
	}
	for _, entry := range entries {
		scope := sharedkernel.Scope{TenantID: entry.TenantID, DepartmentID: entry.DepartmentID, ApplicationID: entry.ApplicationID, AgentID: entry.AgentID, AgentVersionID: entry.AgentVersionID, PrincipalID: "platform-bootstrap"}
		if err := resolver.Upsert(ctx, scope, policyasset.Snapshot{ModelProfileID: entry.ModelProfileID, PromptVersionID: entry.PromptVersionID, ToolPolicyID: entry.ToolPolicyID, MemoryPolicyID: entry.MemoryPolicyID, KnowledgePolicyID: entry.KnowledgePolicyID, RuntimePolicyID: entry.RuntimePolicyID, RuleBundleVersion: entry.RuleBundleVersion, RuleBundleChecksum: entry.RuleBundleChecksum, Revision: entry.Revision, Hash: entry.Hash, Model: entry.Model, Prompt: entry.Prompt, Tool: entry.Tool, Memory: entry.Memory, Knowledge: entry.Knowledge, Runtime: entry.Runtime, Rule: entry.Rule}); err != nil {
			return err
		}
	}
	return nil
}

func envOrDefault(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

func envInt(name string, fallback int) int {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed <= 0 {
		return fallback
	}
	return parsed
}

func envDuration(name string, fallback time.Duration) time.Duration {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback
	}
	parsed, err := time.ParseDuration(value)
	if err != nil || parsed <= 0 {
		return fallback
	}
	return parsed
}

func envBool(name string, fallback bool) bool {
	value := strings.TrimSpace(strings.ToLower(os.Getenv(name)))
	if value == "" {
		return fallback
	}
	switch value {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return fallback
	}
}

func splitCSV(raw string) []string {
	parts := strings.Split(raw, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		if value := strings.TrimSpace(part); value != "" {
			result = append(result, value)
		}
	}
	return result
}
