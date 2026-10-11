package main

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/lexagent/platform/internal/capability"
	"github.com/lexagent/platform/internal/execution"
	"github.com/lexagent/platform/internal/knowledge"
	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sharedkernel"
)

// executeIssuedIndexTask obtains task credentials from the composition root.
// Neither credentials nor request-scoped model callbacks belong in job data.
func (p knowledgePersistence) executeIssuedIndexTask(ctx context.Context, run platformruntime.Run, scope knowledge.ProjectionScope, config knowledge.IndexConfig, incremental bool, signer execution.MachineRunContextSigner, module *capability.Module, credential capability.TaskWorkloadCredential, ttl time.Duration) error {
	models, closeModels, err := renewingIndexModels(ctx, run.Scope, func(current context.Context) (capability.TaskEmbeddingSession, error) {
		return p.openIndexTaskModels(current, run, scope, signer, module, credential)
	})
	if err != nil {
		return err
	}
	defer closeModels()
	return p.executeIndexTask(ctx, run, scope, config, incremental, models, ttl)
}

// Each batch opens a fresh, independently authorized session before calling
// the model. Check never issues a context: callers may hold IAM/lease locks.
// Current checks and model calls may run concurrently, while replacement and
// close wait for users of the previous session. No expired-context fallback.
func renewingIndexModels(ctx context.Context, scope sharedkernel.Scope, open func(context.Context) (capability.TaskEmbeddingSession, error)) (knowledgeIndexEmbeddings, func(), error) {
	if ctx == nil || open == nil || scope.ValidateTrusted() != nil {
		return knowledgeIndexEmbeddings{}, nil, knowledge.ErrInvalidProjection
	}
	lifetime, cancel := context.WithCancel(ctx)
	valid := func(s capability.TaskEmbeddingSession) bool {
		return s.Scope == scope && s.Call != nil && s.Check != nil && s.Close != nil
	}
	initial, err := open(lifetime)
	if err != nil {
		cancel()
		return knowledgeIndexEmbeddings{}, nil, err
	}
	if !valid(initial) {
		if initial.Close != nil {
			initial.Close()
		}
		cancel()
		return knowledgeIndexEmbeddings{}, nil, knowledge.ErrInvalidProjection
	}
	pinned, err := json.Marshal(initial.Policy)
	if err != nil {
		initial.Close()
		cancel()
		return knowledgeIndexEmbeddings{}, nil, err
	}
	var mu sync.RWMutex
	var renew sync.Mutex
	current := initial
	var once sync.Once
	closeModels := func() {
		once.Do(func() {
			cancel()
			mu.Lock()
			defer mu.Unlock()
			current.Close()
		})
	}
	models := knowledgeIndexEmbeddings{scope: scope, request: capability.KnowledgeSearchRequest{Policy: initial.Policy}}
	models.request.ModelCheck = func(callCtx context.Context, operation string) error {
		if err := lifetime.Err(); err != nil {
			return err
		}
		if operation != "embed" {
			return knowledge.ErrInvalidProjection
		}
		mu.RLock()
		defer mu.RUnlock()
		return current.Check(callCtx, operation)
	}
	models.request.ModelCall = func(callCtx context.Context, operation string, input map[string]any) (map[string]any, error) {
		if err := lifetime.Err(); err != nil {
			return nil, err
		}
		if err := callCtx.Err(); err != nil {
			return nil, err
		}
		if operation != "embed" {
			return nil, knowledge.ErrInvalidProjection
		}
		renew.Lock()
		defer renew.Unlock()
		// Bind issuance to both worker lifetime and batch cancellation.
		batch, stop := context.WithCancel(callCtx)
		stopLifetime := context.AfterFunc(lifetime, stop)
		defer stopLifetime()
		defer stop()
		// The new session survives this batch for subsequent transactional
		// checks; only the model call uses the shorter batch context.
		next, err := open(lifetime)
		if err != nil {
			return nil, err
		}
		if err := batch.Err(); err != nil {
			if next.Close != nil {
				next.Close()
			}
			return nil, err
		}
		raw, marshalErr := json.Marshal(next.Policy)
		if !valid(next) || marshalErr != nil || string(raw) != string(pinned) {
			if next.Close != nil {
				next.Close()
			}
			return nil, knowledge.ErrInvalidProjection
		}
		mu.Lock()
		if err := lifetime.Err(); err != nil {
			mu.Unlock()
			next.Close()
			return nil, err
		}
		previous := current
		current = next
		previous.Close()
		mu.Unlock()
		mu.RLock()
		defer mu.RUnlock()
		return current.Call(batch, operation, input)
	}
	return models, closeModels, nil
}
