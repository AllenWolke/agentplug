package main

import (
	"context"
	"slices"

	"github.com/lexagent/platform/internal/identity"
	"github.com/lexagent/platform/internal/knowledge"
	"github.com/lexagent/platform/internal/policyasset"
	"github.com/lexagent/platform/internal/sharedkernel"
)

type selectedKnowledgeSource interface {
	SnapshotDocuments(context.Context, knowledge.ProjectionScope, []string) (knowledge.SourceSnapshot, error)
}

// Per-query composition value. Its scope and publication originate in the
// authenticated capability port, never in user-supplied owner/allowlist fields.
type sourceKnowledgeAuthority struct {
	source      selectedKnowledgeSource
	iam         capabilityExecutionAuthority
	scope       sharedkernel.Scope
	knowledgeID string
	asOf        string
	documents   []policyasset.KnowledgeDocumentBinding
}

func sourceACLAllows(acl knowledge.DocumentACL, principal string) bool {
	return principal != "" && (acl.ApplicationVisible || acl.OwnerPrincipalID == principal || slices.Contains(acl.Readers, principal))
}

func (a sourceKnowledgeAuthority) ResolveCurrentDocuments(ctx context.Context, scope sharedkernel.Scope, knowledgeID string) ([]knowledge.DocumentFact, error) {
	if a.source == nil || a.iam.identity == nil || scope != a.scope || scope.ValidateTrusted() != nil || knowledgeID == "" || knowledgeID != a.knowledgeID {
		return nil, knowledge.ErrKnowledgeAuthorityUnavailable
	}
	checkEpoch := func() error {
		if a.iam.AuthorizeCurrentRunEpoch(ctx, scope) != nil {
			return knowledge.ErrKnowledgeAuthorityChanged
		}
		return nil
	}
	if err := checkEpoch(); err != nil {
		return nil, err
	}
	plan, err := a.iam.FilterKnowledgeDocuments(ctx, scope, knowledgeID, a.documents)
	if err != nil || plan.Legacy {
		return nil, knowledge.ErrKnowledgeAuthorityUnavailable
	}
	ids := []string{}
	allowed := map[string]policyasset.KnowledgeDocumentBinding{}
	for _, document := range plan.Documents {
		if document.ProviderID != "platform-knowledge" || document.KnowledgeBaseID != knowledgeID {
			continue
		}
		if _, duplicate := allowed[document.ProviderDocumentID]; duplicate {
			return nil, knowledge.ErrInvalidProjection
		}
		ids = append(ids, document.ProviderDocumentID)
		allowed[document.ProviderDocumentID] = document
	}
	if len(ids) == 0 {
		return []knowledge.DocumentFact{}, nil
	}
	projectionScope := knowledge.ProjectionScope{TenantID: scope.TenantID, DepartmentID: scope.DepartmentID, ApplicationID: scope.ApplicationID, KnowledgeID: knowledgeID}
	snapshot, err := a.source.SnapshotDocuments(ctx, projectionScope, ids)
	if err != nil {
		return nil, err
	}
	// Reload both IAM decisions after reading source facts. A changed machine
	// binding must satisfy the source ACL under its current principal as well.
	current, err := a.iam.FilterKnowledgeDocuments(ctx, scope, knowledgeID, a.documents)
	if err != nil || current.Legacy {
		return nil, knowledge.ErrKnowledgeAuthorityUnavailable
	}
	resolver, ok := a.iam.identity.(identity.WorkloadIdentityResolver)
	if !ok {
		return nil, knowledge.ErrKnowledgeAuthorityUnavailable
	}
	binding, err := resolver.ResolveWorkloadIdentity(ctx, scope)
	if err != nil || binding.Status != "active" || binding.TenantID != scope.TenantID || binding.DepartmentID != scope.DepartmentID || binding.ApplicationID != scope.ApplicationID || binding.InstallationID != scope.InstallationID || binding.AgentID != scope.AgentID || binding.AgentVersionID != scope.AgentVersionID {
		return nil, knowledge.ErrKnowledgeAuthorityUnavailable
	}
	currentIDs := map[string]bool{}
	for _, document := range current.Documents {
		currentIDs[document.ObjectID()] = true
	}
	facts := []knowledge.DocumentFact{}
	seen := map[string]bool{}
	for _, document := range snapshot.Documents {
		published, ok := allowed[document.ID]
		if !ok || seen[document.ID] || document.SourceRevision > snapshot.Revision {
			return nil, knowledge.ErrSourceCorrupt
		}
		seen[document.ID] = true
		fact := document.Fact()
		if !currentIDs[published.ObjectID()] || document.Deleted || published.DocumentVersion != fact.Version || published.OwnerID != document.ACL.OwnerPrincipalID || !sourceACLAllows(document.ACL, scope.PrincipalID) || !sourceACLAllows(document.ACL, binding.PrincipalID) {
			continue
		}
		applicable, err := knowledge.BusinessDate(document.Metadata, a.asOf)
		if err != nil {
			return nil, err
		}
		if !applicable {
			continue
		}
		facts = append(facts, fact)
	}
	if err := checkEpoch(); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return facts, nil
}
