package capability

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/lexagent/platform/internal/modelgateway"
	"github.com/lexagent/platform/internal/policyasset"
	"github.com/lexagent/platform/internal/sharedkernel"
)

var ErrKnowledgePortUnavailable = errors.New("governed knowledge port unavailable")

// Shape check only. Routed versions additionally require the trusted current
// ModelReceiptCheck callback; this function never grants model access itself.
func KnowledgeModelVersionAllowed(p policyasset.Snapshot, version string, embedding, verifiedRouting bool) bool {
	if version == "" {
		return false
	}
	if embedding {
		model, err := p.Model.ForEmbedding()
		return err == nil && version == model.ModelVersionID
	}
	if p.Model.Routing == nil || !verifiedRouting {
		return version == p.Model.ModelVersionID
	}
	if p.Model.ValidateRouting() != nil || p.Model.Routing.ExecutionContextSHA256 != policyasset.RoutingExecutionContextSHA256(p) {
		return false
	}
	for _, candidate := range p.Model.Routing.Candidates {
		if candidate.ModelVersionID == version {
			return true
		}
	}
	return false
}

// KnowledgeSearchPort permits composition-owned implementations without
// exporting authentication envelopes or giving business Agents storage access.
type KnowledgeSearchPort interface {
	SearchKnowledge(context.Context, sharedkernel.Scope, KnowledgeSearchRequest) (map[string]any, error)
}

type KnowledgeSearchRequest struct {
	Query                string
	SkillContext         string `json:"skill_context,omitempty"`
	Answer               bool
	KnowledgeScope       string
	TopK                 int
	AsOf                 string
	CacheMode            string
	RequestID            string
	IdempotencyKey       string
	Documents            []policyasset.KnowledgeDocumentBinding
	Policy               policyasset.Snapshot
	ModelCall            KnowledgeModelCall                                               `json:"-"`
	ModelCheck           KnowledgeModelCheck                                              `json:"-"`
	ModelReceiptCheck    KnowledgeModelReceiptCheck                                       `json:"-"`
	ModelCacheBinding    func(context.Context) (string, error)                            `json:"-"`
	ModelInputFits       func([]modelgateway.Message, bool) bool                          `json:"-"`
	ModelSchemaInputFits func([]modelgateway.Message, bool, json.RawMessage, string) bool `json:"-"`
	ModelParallelism     func(context.Context) (int, error)                               `json:"-"`
	ObservePerformance   func(context.Context, KnowledgeQueryObservation)                 `json:"-"`
}

// Only the platform's in-process native knowledge implementation supplies
// these measured counters. This callback is never part of an HTTP envelope.
type KnowledgeQueryObservation struct {
	StartedAt, FinishedAt   time.Time
	CacheMode               string
	Lookups, Hits, Failures int64
	Err                     error
}

type governedKnowledgeProvider struct{ backend KnowledgeSearchPort }

func NewGovernedKnowledgeProvider(backend KnowledgeSearchPort) KnowledgeProvider {
	return governedKnowledgeProvider{backend: backend}
}

func (p governedKnowledgeProvider) Search(ctx context.Context, caller harnessContext, input knowledgeQuery) (map[string]any, error) {
	if p.backend == nil {
		return nil, ErrKnowledgePortUnavailable
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	scope := sharedkernel.Scope{TenantID: caller.TenantID, DepartmentID: caller.DepartmentID, ApplicationID: caller.ApplicationID, AgentInstanceID: caller.AgentInstanceID, AgentID: caller.AgentID, PrincipalType: caller.PrincipalType, PrincipalID: caller.ActorID, InstallationID: caller.InstallationID, AgentVersionID: caller.AgentVersionID, SessionID: caller.SessionID, RunID: caller.TaskID, ParentRunID: caller.ParentRunID, AuthorizationEpoch: caller.AuthorizationEpoch, TraceID: caller.TraceID}
	if scope.ValidateTrusted() != nil || !input.GovernedDocuments || input.Policy.Validate() != nil || input.Policy.ValidateDetails() != nil || !input.Policy.AllowsKnowledgeScope(input.Scope) || strings.TrimSpace(input.Query) == "" || len(input.Query) > 16384 || input.TopK < 1 || input.TopK > 100 || len(input.Documents) == 0 {
		return nil, errKnowledgeDocumentAuthority
	}
	published := make(map[string][]byte)
	for _, document := range input.Policy.Knowledge.DocumentBindings {
		if document.KnowledgeScope == input.Scope {
			published[document.ObjectID()], _ = json.Marshal(document)
		}
	}
	seen := map[string]bool{}
	for _, document := range input.Documents {
		raw, err := json.Marshal(document)
		if err != nil || document.KnowledgeScope != input.Scope || seen[document.ObjectID()] || !bytes.Equal(raw, published[document.ObjectID()]) {
			return nil, errKnowledgeDocumentAuthority
		}
		seen[document.ObjectID()] = true
	}
	request := KnowledgeSearchRequest{Query: input.Query, Answer: input.Answer, SkillContext: input.SkillContext, KnowledgeScope: input.Scope, TopK: input.TopK, AsOf: input.AsOf, CacheMode: input.CacheMode, RequestID: caller.RequestID, IdempotencyKey: caller.IdempotencyKey, Documents: input.Documents, Policy: input.Policy}
	// Providers receive detached values: retaining or mutating a slice/map may
	// not modify the policy/document facts used for final authorization.
	raw, err := json.Marshal(request)
	var detached KnowledgeSearchRequest
	if err != nil || json.Unmarshal(raw, &detached) != nil {
		return nil, ErrKnowledgePortUnavailable
	}
	detached.ModelCall = input.ModelCall
	detached.ModelCheck = input.ModelCheck
	detached.ModelReceiptCheck = input.ModelReceiptCheck
	detached.ModelCacheBinding = input.ModelCacheBinding
	detached.ModelInputFits = input.ModelInputFits
	detached.ModelSchemaInputFits = input.ModelSchemaInputFits
	detached.ModelParallelism = input.ModelParallelism
	detached.ObservePerformance = input.ObservePerformance
	return p.backend.SearchKnowledge(ctx, scope, detached)
}
