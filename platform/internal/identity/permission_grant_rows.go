package identity

import (
	"context"
	"encoding/json"
)

// Every invocation receives a fresh SQL projection. Only parsing identical
// bytes is reused; authoritative columns override conflicting JSON metadata.
func parsePermissionGrantRows(raw []byte) ([]Grant, error) {
	var rows []struct {
		Grant
		Metadata json.RawMessage `json:"permission_json"`
	}
	if err := json.Unmarshal(raw, &rows); err != nil {
		return nil, err
	}
	grants := make([]Grant, 0, len(rows))
	for _, row := range rows {
		g := row.Grant
		if len(row.Metadata) != 0 {
			var metadata Grant
			if err := json.Unmarshal(row.Metadata, &metadata); err != nil {
				return nil, err
			}
			g.Validity, g.ResourceType, g.ResourceID, g.DataScope, g.SourceID, g.PresetCode, g.PresetVersion, g.DelegationID = metadata.Validity, metadata.ResourceType, metadata.ResourceID, metadata.DataScope, metadata.SourceID, metadata.PresetCode, metadata.PresetVersion, metadata.DelegationID
			g.DepartmentAgentActionVersion = metadata.DepartmentAgentActionVersion
			g.AgentUsePackageID, g.AgentUsePackageRevision, g.AgentUseRequirementsDigest = metadata.AgentUsePackageID, metadata.AgentUsePackageRevision, metadata.AgentUseRequirementsDigest
		}
		grants = append(grants, g)
	}
	return grants, nil
}

func clonePermissionGrantRows(rows []Grant) []Grant {
	if rows == nil {
		return nil
	}
	cloned := make([]Grant, len(rows))
	for i, g := range rows {
		cloned[i] = clonePermissionGrant(g)
	}
	return cloned
}

func decodePermissionGrantRows(ctx context.Context, raw []byte) ([]Grant, error) {
	if cache, ok := ctx.Value(permissionDecodeKey{}).(*permissionDecodeCache); ok && cache != nil {
		return cache.grantRows.Decode(raw)
	}
	return parsePermissionGrantRows(raw)
}
