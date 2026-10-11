package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/lexagent/platform/internal/audit"
	"github.com/lexagent/platform/internal/execution"
	"github.com/lexagent/platform/internal/identity"
	"github.com/lexagent/platform/internal/knowledge"
	"github.com/lexagent/platform/internal/sharedkernel"
)

// knowledgePersistence composes module-owned ports on the same platform DB.
// It contains no direct SQL against Identity, execution, audit or knowledge.
// Source/index management uses policy.manage; retrieval retains the separate
// caller AND workload knowledge.search boundary of capability execution.
type knowledgePersistence struct {
	db                *sql.DB
	iam               *identity.SQLStore
	execution         *execution.SQLStore
	audit             audit.TxRecorder
	indexCompensation *knowledge.IndexCompensation
}

func (p knowledgePersistence) authorize(ctx context.Context, tx *sql.Tx, actor sharedkernel.Scope, s knowledge.ProjectionScope) error {
	if p.db == nil || p.iam == nil || p.audit == nil || actor.TraceID == "" || actor.TenantID != s.TenantID || actor.DepartmentID != s.DepartmentID || actor.ApplicationID != s.ApplicationID || s.KnowledgeID == "" {
		return identity.ErrPermissionDenied
	}
	return p.iam.AuthorizeManagementTx(ctx, tx, actor, identity.PermissionQuery{Action: "policy.manage", Scope: identity.ManagementScope{Type: "application", TenantID: s.TenantID, DepartmentID: s.DepartmentID, ApplicationID: s.ApplicationID}})
}

func (p knowledgePersistence) record(tx *sql.Tx, actor sharedkernel.Scope, s knowledge.ProjectionScope, action string, value any) error {
	if p.audit == nil {
		return errors.New("knowledge audit unavailable")
	}
	// Summaries contain only version/identifier receipts, never source bodies,
	// embeddings, prompts, lease tokens or authentication credentials.
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(append([]byte(action+":"+s.TenantID+":"+s.DepartmentID+":"+s.ApplicationID+":"+s.KnowledgeID+":"), raw...))
	return p.audit.RecordTx(tx, audit.Event{ID: "knowledge-" + hex.EncodeToString(digest[:]), TenantID: s.TenantID, DepartmentID: s.DepartmentID, ApplicationID: s.ApplicationID, ActorType: actor.PrincipalType, ActorID: actor.PrincipalID, TraceID: actor.TraceID, AggregateType: "knowledge", AggregateID: s.KnowledgeID, Action: action, Outcome: "success", Summary: string(raw), CreatedAt: time.Now().UTC()})
}

func (p knowledgePersistence) source(actor sharedkernel.Scope) knowledge.PostgresSource {
	return knowledge.PostgresSource{DB: p.db, GuardChangeTx: func(ctx context.Context, tx *sql.Tx, s knowledge.ProjectionScope, c knowledge.SourceChange) error {
		if c.ActorPrincipalID != actor.PrincipalID {
			return identity.ErrPermissionDenied
		}
		return p.authorize(ctx, tx, actor, s)
	}, RecordChange: func(ctx context.Context, tx *sql.Tx, s knowledge.ProjectionScope, r knowledge.SourceReceipt) error {
		if r.ActorPrincipalID != actor.PrincipalID {
			return identity.ErrPermissionDenied
		}
		if err := p.authorize(ctx, tx, actor, s); err != nil {
			return err
		}
		return p.record(tx, actor, s, "knowledge.source.changed", r)
	}}
}

func (p knowledgePersistence) index(actor sharedkernel.Scope) knowledge.IndexCoordinator {
	return knowledge.IndexCoordinator{Source: p.source(actor), Projection: knowledge.PostgresProjection{DB: p.db}, GuardPublishTx: func(ctx context.Context, tx *sql.Tx, s knowledge.ProjectionScope) error {
		return p.authorize(ctx, tx, actor, s)
	}, RecordPublish: func(ctx context.Context, tx *sql.Tx, s knowledge.ProjectionScope, generation string, sourceRevision, indexRevision int64) error {
		if err := p.authorize(ctx, tx, actor, s); err != nil {
			return err
		}
		return p.record(tx, actor, s, "knowledge.index.published", struct {
			Generation     string `json:"generation"`
			SourceRevision int64  `json:"source_revision"`
			IndexRevision  int64  `json:"index_revision"`
		}{generation, sourceRevision, indexRevision})
	}}
}

func (p knowledgePersistence) checkpoints(s knowledge.ProjectionScope) knowledge.PostgresTaskCheckpoints {
	return knowledge.PostgresTaskCheckpoints{DB: p.db, GuardTx: func(ctx context.Context, tx *sql.Tx, actor sharedkernel.Scope, token string, revision uint64) error {
		if err := p.authorize(ctx, tx, actor, s); err != nil {
			return err
		}
		if p.execution == nil {
			return errors.New("knowledge execution guard unavailable")
		}
		return p.execution.CheckTaskLeaseTx(ctx, tx, actor, token, revision)
	}, RecordTx: func(_ context.Context, tx *sql.Tx, actor sharedkernel.Scope, r knowledge.CheckpointReceipt) error {
		if r.KnowledgeID != s.KnowledgeID || r.RunID != actor.RunID {
			return identity.ErrPermissionDenied
		}
		return p.record(tx, actor, s, "knowledge.index.checkpoint", r)
	}}
}
