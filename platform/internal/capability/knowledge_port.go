package capability

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"

	"github.com/lexagent/platform/internal/policyasset"
	"github.com/lexagent/platform/internal/sharedkernel"
)

var ErrKnowledgePortUnavailable = errors.New("governed knowledge port unavailable")

// KnowledgeSearchPort permits composition-owned implementations without
// exporting authentication envelopes or giving business Agents storage access.
type KnowledgeSearchPort interface {
	SearchKnowledge(context.Context, sharedkernel.Scope, KnowledgeSearchRequest) (map[string]any, error)
}

type KnowledgeSearchRequest struct {
	Query          string
	SkillContext   string `json:"skill_context,omitempty"`
	Answer         bool
	KnowledgeScope string
	TopK           int
	AsOf           string
	CacheMode      string
	RequestID      string
	IdempotencyKey string
	Documents      []policyasset.KnowledgeDocumentBinding
	Policy         policyasset.Snapshot
	ModelCall      KnowledgeModelCall  `json:"-"`
	ModelCheck     KnowledgeModelCheck `json:"-"`
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
	return p.backend.SearchKnowledge(ctx, scope, detached)
}
