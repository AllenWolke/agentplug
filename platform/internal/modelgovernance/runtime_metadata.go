package modelgovernance

import (
	"context"

	"github.com/lexagent/platform/internal/modelgateway"
	"github.com/lexagent/platform/internal/sqlutil"
)

// GetApprovedProvider adapts the SQL-owned Provider catalog to the runtime
// model gateway. Only non-secret metadata and the opaque SecretRef cross this
// port; credential material is resolved by a separate SecretResolver.
func (s *SQLStore) GetApprovedProvider(ctx context.Context, id string) (modelgateway.ProviderMetadata, error) {
	if s == nil || s.db == nil || !validGovernanceID(id, 128) {
		return modelgateway.ProviderMetadata{}, ErrInvalidRequest
	}
	var result modelgateway.ProviderMetadata
	var providerType string
	err := s.db.QueryRowContext(ctx, sqlutil.Bind(`SELECT id,provider_key,type,trust_zone,endpoint_ref,secret_ref,status FROM platform_model_provider WHERE id=?`), id).
		Scan(&result.ID, &result.Key, &providerType, &result.TrustZone, &result.EndpointRef, &result.SecretRef, &result.Status)
	if err != nil {
		return modelgateway.ProviderMetadata{}, mapNotFound(err)
	}
	if result.ID != id || !validGovernanceID(result.ID, 128) || !providerKeyPattern.MatchString(result.Key) ||
		result.Status != StatusApproved || !providerTypeMatchesTrust(providerType, result.TrustZone) ||
		!isEndpointReference(result.EndpointRef) || validateSecretRef(result.SecretRef) != nil {
		return modelgateway.ProviderMetadata{}, ErrModelAccessDenied
	}
	return result, nil
}

// GetApprovedModel resolves one immutable approved version through its owning
// definition and Provider. The definition must remain writable (draft) in this
// catalog's current lifecycle; disabled or inconsistent joins fail closed.
func (s *SQLStore) GetApprovedModel(ctx context.Context, versionID string) (modelgateway.ModelMetadata, error) {
	if s == nil || s.db == nil || !validGovernanceID(versionID, 128) {
		return modelgateway.ModelMetadata{}, ErrInvalidRequest
	}
	var result modelgateway.ModelMetadata
	var versionStatus, definitionStatus, providerStatus, kind string
	var joinedProviderID string
	err := s.db.QueryRowContext(ctx, sqlutil.Bind(`
SELECT mv.id,mv.status,md.id,md.provider_id,md.model_key,md.kind,md.lifecycle_status,p.id,p.status
FROM platform_model_version mv
JOIN platform_model_definition md ON md.id=mv.definition_id
JOIN platform_model_provider p ON p.id=md.provider_id
WHERE mv.id=?`), versionID).Scan(
		&result.VersionID, &versionStatus, &result.ID, &result.ProviderID, &result.Key, &kind, &definitionStatus, &joinedProviderID, &providerStatus,
	)
	if err != nil {
		return modelgateway.ModelMetadata{}, mapNotFound(err)
	}
	// The joined Provider ID must equal the Provider ID held by the model definition.
	if result.VersionID != versionID || !validGovernanceID(result.ID, 128) || !validGovernanceID(result.ProviderID, 128) ||
		!providerKeyPattern.MatchString(result.Key) || (kind != ModelKindChat && kind != ModelKindEmbedding) ||
		versionStatus != StatusApproved || providerStatus != StatusApproved || definitionStatus != StatusDraft || joinedProviderID != result.ProviderID {
		return modelgateway.ModelMetadata{}, ErrModelAccessDenied
	}
	result.Status = versionStatus
	result.Kind = kind
	return result, nil
}

var _ modelgateway.ProviderMetadataPort = (*SQLStore)(nil)
var _ modelgateway.ModelMetadataPort = (*SQLStore)(nil)
