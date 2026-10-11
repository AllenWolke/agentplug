package main

import (
	"context"
	"errors"

	"github.com/lexagent/platform/internal/catalog"
	"github.com/lexagent/platform/internal/identity"
	"github.com/lexagent/platform/internal/knowledge"
	"github.com/lexagent/platform/internal/policyasset"
	"github.com/lexagent/platform/internal/sharedkernel"
)

type knowledgeControl struct {
	persistence knowledgePersistence
	targets     catalog.AvailableAgentReader
	policies    policyasset.Resolver
}

func (c knowledgeControl) Ready(ctx context.Context) error {
	if c.persistence.db == nil || c.persistence.iam == nil || c.persistence.audit == nil {
		return knowledge.ErrCheckpointUnavailable
	}
	return c.persistence.db.PingContext(ctx)
}

func knowledgeControlError(err error) error {
	if errors.Is(err, identity.ErrPermissionDenied) || errors.Is(err, identity.ErrScopeMismatch) || errors.Is(err, identity.ErrPrincipalNotFound) {
		return knowledge.ErrManagementDenied
	}
	return err
}

func (c knowledgeControl) Change(ctx context.Context, actor sharedkernel.Scope, scope knowledge.ProjectionScope, command knowledge.SourceChange) (knowledge.SourceReceipt, error) {
	result, err := c.persistence.source(actor).Change(ctx, scope, command)
	return result, knowledgeControlError(err)
}

func (c knowledgeControl) Snapshot(ctx context.Context, actor sharedkernel.Scope, scope knowledge.ProjectionScope, maximum int) (knowledge.SourceSnapshot, error) {
	if c.persistence.db == nil {
		return knowledge.SourceSnapshot{}, knowledge.ErrCheckpointUnavailable
	}
	// Hold current IAM continuity around the owned source snapshot. The source
	// still owns its repeatable-read transaction; no foreign table is queried.
	tx, err := c.persistence.db.BeginTx(ctx, nil)
	if err != nil {
		return knowledge.SourceSnapshot{}, err
	}
	defer tx.Rollback()
	if err := c.persistence.authorize(ctx, tx, actor, scope); err != nil {
		return knowledge.SourceSnapshot{}, knowledgeControlError(err)
	}
	result, err := c.persistence.source(actor).Snapshot(ctx, scope, maximum)
	if err != nil {
		return knowledge.SourceSnapshot{}, err
	}
	if err := c.persistence.authorize(ctx, tx, actor, scope); err != nil {
		return knowledge.SourceSnapshot{}, knowledgeControlError(err)
	}
	if err := tx.Commit(); err != nil {
		return knowledge.SourceSnapshot{}, err
	}
	return result, nil
}
