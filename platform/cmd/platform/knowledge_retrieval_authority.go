package main

import (
	"context"
	"slices"
	"time"

	"github.com/lexagent/platform/internal/capability"
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
	// Reuse the common IAM transaction only for this local read. Its callback
	// pins caller authority and all IAM mutations through source filtering;
	// the next pipeline boundary must acquire fresh facts again. Delegated
	// runs keep the existing ancestry protocol rather than assuming a local
	// installation run grant or replacing their root authorization stamp.
	if reader, ok := a.iam.identity.(interface {
		WithCurrentAuthorizationSnapshotContext(context.Context, sharedkernel.Scope, string, func(context.Context, uint64, identity.PermissionSnapshot) error) error
	}); ok && scope.ParentRunID == "" {
		expected, err := expectedExecutionEpoch(ctx, a.iam.execution, scope)
		if err != nil {
			return nil, knowledge.ErrKnowledgeAuthorityChanged
		}
		var facts []knowledge.DocumentFact
		err = reader.WithCurrentAuthorizationSnapshotContext(ctx, scope, "run", func(readCtx context.Context, epoch uint64, caller identity.PermissionSnapshot) error {
			if epoch != expected {
				return knowledge.ErrKnowledgeAuthorityChanged
			}
			snapshots, err := a.iam.authorizedResourceSnapshotsWithCaller(readCtx, scope,
				capability.CapabilityResourceAccess{Action: "knowledge.search", ResourceType: "knowledge", ResourceID: knowledgeID}, &caller)
			if err != nil {
				return err
			}
			facts, err = a.resolveCurrentDocuments(readCtx, scope, knowledgeID, &snapshots, expected)
			return err
		})
		if err != nil {
			return nil, err
		}
		return facts, nil
	}
	return a.resolveCurrentDocuments(ctx, scope, knowledgeID, nil, 0)
}

func (a sourceKnowledgeAuthority) resolveCurrentDocuments(ctx context.Context, scope sharedkernel.Scope, knowledgeID string, fenced *authorizedResourceSnapshots, expectedEpoch uint64) ([]knowledge.DocumentFact, error) {
	checkEpoch := func() error {
		if fenced != nil {
			// The durable execution epoch was read before entering this read
			// transaction. Do not open another execution connection here. This
			// local source read sends no model request or business response;
			// the pipeline/gateway retain their independent live lease fences.
			epoch, err := a.iam.identity.CurrentAuthorizationEpoch(ctx, scope, "run")
			if err != nil || epoch != expectedEpoch {
				return knowledge.ErrKnowledgeAuthorityChanged
			}
			return nil
		}
		if a.iam.AuthorizeCurrentRunEpoch(ctx, scope) != nil {
			return knowledge.ErrKnowledgeAuthorityChanged
		}
		return nil
	}
	if fenced == nil {
		if err := checkEpoch(); err != nil {
			return nil, err
		}
	}
	filter := func() (capability.KnowledgeDocumentPlan, error) {
		if fenced != nil {
			return knowledgeDocumentsFromSnapshots(*fenced, scope, knowledgeID, a.documents, time.Now().UTC())
		}
		return a.iam.FilterKnowledgeDocuments(ctx, scope, knowledgeID, a.documents)
	}
	plan, err := filter()
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
	// Outside a joined transaction reload both identities. Inside it, IAM
	// mutations are blocked; still reevaluate natural expiry after source I/O.
	current, err := filter()
	if err != nil || current.Legacy {
		return nil, knowledge.ErrKnowledgeAuthorityUnavailable
	}
	var binding identity.WorkloadBinding
	if fenced != nil {
		binding = fenced.binding
	} else {
		resolver, ok := a.iam.identity.(identity.WorkloadIdentityResolver)
		if !ok {
			return nil, knowledge.ErrKnowledgeAuthorityUnavailable
		}
		binding, err = resolver.ResolveWorkloadIdentity(ctx, scope)
	}
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
	// Recompute the current epoch even under the read fence: validity can
	// expire without a database mutation. The joined API never advances an
	// epoch inside a local read transaction, so stale facts fail closed.
	if err := checkEpoch(); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return facts, nil
}
