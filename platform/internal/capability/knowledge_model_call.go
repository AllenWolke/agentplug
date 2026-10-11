package capability

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/lexagent/platform/internal/modelgateway"
	"github.com/lexagent/platform/internal/modelgovernance"
	"github.com/lexagent/platform/internal/sharedkernel"
)

// Per-request platform callback. Never serialized or exposed to business Agents.
// Calls share the original execution identity and common billing pipeline.
type KnowledgeModelCall func(context.Context, string, map[string]any) (map[string]any, error)

type knowledgeRecoveryOnlyKey struct{}

// A cache hit must pass the same current execution/resource/model-selection
// boundaries as an invocation. This callback performs no provider call or
// reservation: a reused result consumes no new model tokens.
type KnowledgeModelCheck func(context.Context, string) error

func (m *Module) knowledgeModelCheck(parent *http.Request, original envelope, lifetime context.Context) KnowledgeModelCheck {
	return func(ctx context.Context, operation string) error {
		if err := lifetime.Err(); err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if m.publicKey == nil || m.modelAccess == nil || m.modelGateway == nil {
			return &KnowledgeModelError{Status: 503, Code: "MODEL_GOVERNANCE_UNAVAILABLE"}
		}
		op := original
		path := "/internal/model/generate"
		switch operation {
		case "generate":
		case "embed":
			path = "/internal/model/embed"
			selected, err := op.Policy.Model.ForEmbedding()
			if err != nil {
				return &KnowledgeModelError{Status: 403, Code: "MODEL_SELECTION_MISMATCH"}
			}
			op.Policy.Model = selected
			if _, ok := m.modelGateway.(modelgateway.UsageEmbeddingPort); !ok {
				return &KnowledgeModelError{Status: 503, Code: "MODEL_GOVERNANCE_UNAVAILABLE"}
			}
		default:
			return &KnowledgeModelError{Status: 400, Code: "INVALID_MODEL_OPERATION"}
		}
		stageCtx, cancel := context.WithCancel(lifetime)
		defer cancel()
		stop := context.AfterFunc(ctx, cancel)
		defer stop()
		r := parent.Clone(stageCtx)
		copiedURL := *parent.URL
		r.URL = &copiedURL
		r.URL.Path, r.URL.RawPath, r.URL.RawQuery, r.URL.Fragment = path, "", "", ""
		r.RequestURI = path
		var err error
		op.ResourceAccess, err = resourceAccessForRoute(path, op)
		if err != nil || m.checkCurrentCapability(r, op) != nil {
			return &KnowledgeModelError{Status: 403, Code: "CAPABILITY_DENIED"}
		}
		c := op.Context
		scope := sharedkernel.Scope{TenantID: c.TenantID, DepartmentID: c.DepartmentID, ApplicationID: c.ApplicationID, AgentInstanceID: c.AgentInstanceID, AgentID: c.AgentID, PrincipalID: c.ActorID, PrincipalType: c.PrincipalType, InstallationID: c.InstallationID, AgentVersionID: c.AgentVersionID, SessionID: c.SessionID, RunID: c.TaskID, ParentRunID: c.ParentRunID, AuthorizationEpoch: c.AuthorizationEpoch, TraceID: c.TraceID}
		selected, err := m.modelAccess.ResolveModel(stageCtx, scope, op.Policy.Model.ModelVersionID)
		if err != nil {
			if errors.Is(err, modelgovernance.ErrModelAccessDenied) || errors.Is(err, modelgovernance.ErrNotFound) || errors.Is(err, modelgovernance.ErrForbidden) {
				return &KnowledgeModelError{Status: 403, Code: "MODEL_ACCESS_DENIED"}
			}
			return &KnowledgeModelError{Status: 503, Code: "MODEL_GOVERNANCE_UNAVAILABLE"}
		}
		if selected.ModelVersionID != op.Policy.Model.ModelVersionID || selected.ProviderID == "" || selected.ProviderKey == "" || selected.ModelID == "" || selected.ModelKey == "" || !sameModelSelection(strings.ToLower(strings.TrimSpace(op.Policy.Model.Provider)), op.Policy.Model.Model, selected) {
			return &KnowledgeModelError{Status: 403, Code: "MODEL_SELECTION_MISMATCH"}
		}
		if selected.TrustZone == modelgovernance.TrustExternal && !op.Policy.Model.AllowExternal {
			return &KnowledgeModelError{Status: 403, Code: "EXTERNAL_MODEL_DENIED"}
		}
		if err := stageCtx.Err(); err != nil {
			return err
		}
		if m.checkCurrentCapability(r, op) != nil {
			return &KnowledgeModelError{Status: 403, Code: "CAPABILITY_DENIED"}
		}
		return nil
	}
}

type KnowledgeModelError struct {
	Status int
	Code   string
}

func (e *KnowledgeModelError) Error() string {
	return "governed knowledge model stage failed: " + e.Code
}

type modelCallResponse struct {
	header http.Header
	status int
	body   bytes.Buffer
}

func (w *modelCallResponse) Header() http.Header { return w.header }
func (w *modelCallResponse) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
	}
}
func (w *modelCallResponse) Write(data []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	if w.body.Len()+len(data) > 16<<20 {
		return 0, ErrKnowledgePortUnavailable
	}
	return w.body.Write(data)
}

// Checkpoint JSON round trips may reorder object fields without changing the
// approved command. Bind receipts to its JSON value, while preserving every
// request field, array order, scope, policy and exact stage fingerprint.
func knowledgeModelCommandKey(original envelope, path string, fingerprint []byte) (string, error) {
	decoder := json.NewDecoder(bytes.NewReader(original.Input))
	decoder.UseNumber()
	var input any
	if decoder.Decode(&input) != nil || decoder.Decode(new(any)) != io.EOF {
		return "", &KnowledgeModelError{Status: 400, Code: "INVALID_MODEL_INPUT"}
	}
	canonical, err := json.Marshal(input)
	if err != nil {
		return "", &KnowledgeModelError{Status: 400, Code: "INVALID_MODEL_INPUT"}
	}
	binding, err := json.Marshal([]string{capabilityScopeHash(original.Context), original.Policy.Hash, string(canonical), path, string(fingerprint)})
	if err != nil {
		return "", &KnowledgeModelError{Status: 400, Code: "INVALID_MODEL_INPUT"}
	}
	return fmt.Sprintf("knowledge-model:%x", sha256.Sum256(binding)), nil
}

func (m *Module) knowledgeModelCall(parent *http.Request, original envelope, lifetime context.Context) KnowledgeModelCall {
	return func(ctx context.Context, operation string, input map[string]any) (map[string]any, error) {
		if lifetime.Err() != nil {
			return nil, lifetime.Err()
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if m.modelAccess == nil || m.modelGateway == nil {
			return nil, &KnowledgeModelError{Status: 503, Code: "MODEL_GOVERNANCE_UNAVAILABLE"}
		}
		path := ""
		switch operation {
		case "generate":
			path = "/internal/model/generate"
		case "embed":
			path = "/internal/model/embed"
		default:
			return nil, &KnowledgeModelError{Status: 400, Code: "INVALID_MODEL_OPERATION"}
		}
		encoded, err := json.Marshal(input)
		if err != nil || len(encoded) > maxBody {
			return nil, &KnowledgeModelError{Status: 400, Code: "INVALID_MODEL_INPUT"}
		}
		var detached map[string]any
		if json.Unmarshal(encoded, &detached) != nil || detached == nil {
			return nil, &KnowledgeModelError{Status: 400, Code: "INVALID_MODEL_INPUT"}
		}
		delete(detached, "idempotency_key")
		delete(detached, "skill_bindings")
		if operation == "generate" {
			if bindings, ok := parent.Context().Value(skillModelBindingsKey{}).(map[string]SkillModelBinding); ok && len(bindings) > 0 {
				detached["skill_bindings"] = bindings
			}
			detached["prompt_template_hash"] = original.Policy.Prompt.TemplateHash
		}
		fingerprint, _ := json.Marshal(detached)
		key, err := knowledgeModelCommandKey(original, path, fingerprint)
		if err != nil {
			return nil, err
		}
		legacyBinding, _ := json.Marshal([]string{capabilityScopeHash(original.Context), original.Policy.Hash, string(original.Input), path, string(fingerprint)})
		legacyKey := fmt.Sprintf("knowledge-model:%x", sha256.Sum256(legacyBinding))
		if legacyKey != key {
			// An exact pre-upgrade wire retry may already own a receipt. Preserve
			// that key instead of making a second provider call. Both execution
			// paths below still enforce current access and the model fingerprint.
			if store, available := m.modelStore.(modelReceiptReadStore); available {
				_, found, lookupErr := store.LookupModelInvocation(ctx, capabilityScopeHash(original.Context), key)
				if lookupErr != nil {
					return nil, ErrKnowledgePortUnavailable
				}
				if !found {
					_, legacyFound, lookupErr := store.LookupModelInvocation(ctx, capabilityScopeHash(original.Context), legacyKey)
					if lookupErr != nil {
						return nil, ErrKnowledgePortUnavailable
					}
					if legacyFound {
						key = legacyKey
					}
				}
			}
		}
		detached["idempotency_key"] = key
		encoded, _ = json.Marshal(detached)
		op := original
		op.Input = encoded
		stageCtx, cancel := context.WithCancel(lifetime)
		defer cancel()
		stop := context.AfterFunc(ctx, cancel)
		defer stop()
		r := parent.Clone(stageCtx)
		copiedURL := *parent.URL
		r.URL = &copiedURL
		r.URL.Path = path
		r.URL.RawPath = ""
		r.URL.RawQuery = ""
		r.URL.Fragment = ""
		r.RequestURI = (&url.URL{Path: path}).RequestURI()
		if m.publicKey != nil {
			op.ResourceAccess, err = resourceAccessForRoute(path, op)
			if err != nil || m.checkCurrentCapability(r, op) != nil {
				return nil, &KnowledgeModelError{Status: 403, Code: "CAPABILITY_DENIED"}
			}
		}
		capture := &modelCallResponse{header: make(http.Header)}
		recoveryOnly, _ := parent.Context().Value(knowledgeRecoveryOnlyKey{}).(bool)
		if recoveryOnly {
			m.modelReceiptAuthorized(capture, r, op, operation == "embed")
		} else {
			m.generateAuthorized(capture, r, op)
		}
		var result struct {
			ErrorCode string         `json:"error_code"`
			Data      map[string]any `json:"data"`
		}
		decoder := json.NewDecoder(bytes.NewReader(capture.body.Bytes()))
		decoder.UseNumber()
		if decoder.Decode(&result) != nil {
			return nil, ErrKnowledgePortUnavailable
		}
		if capture.status != http.StatusOK {
			return nil, &KnowledgeModelError{Status: capture.status, Code: result.ErrorCode}
		}
		if result.Data == nil {
			return nil, ErrKnowledgePortUnavailable
		}
		if recoveryOnly {
			if result.Data["version"] != "model-receipt/v1" || result.Data["idempotency_key"] != detached["idempotency_key"] || result.Data["status"] != "completed" {
				return nil, &KnowledgeModelError{Status: 409, Code: "KNOWLEDGE_RECONCILIATION_REQUIRED"}
			}
			receipt, valid := result.Data["receipt"].(map[string]any)
			if !valid || receipt == nil {
				return nil, ErrKnowledgePortUnavailable
			}
			result.Data = receipt
		}
		result.Data["invocation_id"] = fmt.Sprintf("%x", sha256.Sum256([]byte(capabilityScopeHash(original.Context)+":"+detached["idempotency_key"].(string))))
		return result.Data, nil
	}
}
