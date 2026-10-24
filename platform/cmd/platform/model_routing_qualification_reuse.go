package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"reflect"

	"github.com/lexagent/platform/internal/catalog"
	"github.com/lexagent/platform/internal/evaluationproduct"
	"github.com/lexagent/platform/internal/policyasset"
)

type routingReuseCatalog interface {
	GetVersion(context.Context, string) (catalog.Version, error)
}

type routingReusePolicies interface {
	GetSnapshot(context.Context, policyasset.Scope) (policyasset.Snapshot, error)
}

func releaseJSON(raw json.RawMessage) (any, error) {
	var value any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return nil, fmt.Errorf("one release JSON value required")
	}
	if _, ok := value.(map[string]any); !ok {
		return nil, fmt.Errorf("release object required")
	}
	return value, nil
}

// The policy publisher explicitly attests the reviewed code delta and native
// regression evidence. This is not automatic code-equivalence inference.
// The platform additionally checks original published artifacts, contracts and
// all behavior-bearing policy values, then uses the unchanged native verifier
// against the actual old execution identities. Verdicts are never relabelled.
func (v modelRoutingPublicationValidator) reviewedQualificationTarget(ctx context.Context, scope policyasset.Scope, p policyasset.ModelPolicy) (evaluationproduct.RoutingQualificationTarget, error) {
	target := evaluationproduct.RoutingQualificationTarget{AgentID: scope.AgentID,
		AgentVersionID: scope.AgentVersionID, ExecutionContextSHA256: p.Routing.ExecutionContextSHA256}
	r := p.Routing.QualificationReuse
	if r == nil {
		return target, nil
	}
	invalid := func() (evaluationproduct.RoutingQualificationTarget, error) {
		return evaluationproduct.RoutingQualificationTarget{}, policyasset.ErrInvalidAsset
	}
	if r.Validate() != nil || v.reuseCatalog == nil || v.reusePolicies == nil || r.SourceAgentVersionID == scope.AgentVersionID {
		return invalid()
	}
	sourceVersion, err := v.reuseCatalog.GetVersion(ctx, r.SourceAgentVersionID)
	if err != nil {
		return invalid()
	}
	currentVersion, err := v.reuseCatalog.GetVersion(ctx, scope.AgentVersionID)
	if err != nil {
		return invalid()
	}
	if sourceVersion.ID != r.SourceAgentVersionID || currentVersion.ID != scope.AgentVersionID ||
		sourceVersion.DefinitionID == "" || currentVersion.DefinitionID == "" || r.Source == nil && sourceVersion.DefinitionID != currentVersion.DefinitionID ||
		sourceVersion.Status != catalog.DefinitionPublished || currentVersion.Status != catalog.DefinitionPublished ||
		sourceVersion.ArtifactDigest != r.SourceArtifactDigest || currentVersion.ArtifactDigest != r.TargetArtifactDigest ||
		sourceVersion.ApprovedBy == "" || currentVersion.ApprovedBy == "" {
		return invalid()
	}
	for index, pair := range [][2]json.RawMessage{{sourceVersion.Manifest, currentVersion.Manifest},
		{sourceVersion.InputSchema, currentVersion.InputSchema}, {sourceVersion.OutputSchema, currentVersion.OutputSchema}} {
		a, aerr := releaseJSON(pair[0])
		b, berr := releaseJSON(pair[1])
		if aerr != nil || berr != nil {
			return invalid()
		}
		// Only the manifest's release version may change. Schemas remain exact.
		if index == 0 {
			object := a.(map[string]any)
			other, ok := b.(map[string]any)
			if !ok || object["agent_id"] != scope.AgentID || other["agent_id"] != scope.AgentID {
				return invalid()
			}
			delete(object, "version")
			delete(other, "version")
		}
		if !reflect.DeepEqual(a, b) {
			return invalid()
		}
	}
	sourceScope := scope
	sourceScope.AgentVersionID = r.SourceAgentVersionID
	if r.Source != nil {
		sourceScope = r.Source.Scope
		if sourceScope.AgentID != scope.AgentID {
			return invalid()
		}
	}
	source, err := v.reusePolicies.GetSnapshot(ctx, sourceScope)
	if err != nil {
		return invalid()
	}
	current, err := v.reusePolicies.GetSnapshot(ctx, scope)
	if err != nil {
		return invalid()
	}
	current.Model = p
	if policyasset.RoutingExecutionContextSHA256(source) != r.SourceExecutionContextSHA256 ||
		policyasset.RoutingExecutionContextSHA256(current) != p.Routing.ExecutionContextSHA256 ||
		policyasset.RoutingBehaviorContextSHA256(source) != r.BehaviorContextSHA256 {
		return invalid()
	}
	if r.Source == nil {
		if policyasset.RoutingBehaviorContextSHA256(current) != r.BehaviorContextSHA256 {
			return invalid()
		}
	} else if v.verifyQualificationExport(ctx, scope, p, source, current) != nil {
		return invalid()
	}
	target.AgentVersionID, target.ExecutionContextSHA256 = r.SourceAgentVersionID, r.SourceExecutionContextSHA256
	return target, nil
}
