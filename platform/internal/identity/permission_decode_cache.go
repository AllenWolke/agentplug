package identity

import (
	"context"
	"encoding/json"
	"slices"

	"github.com/lexagent/platform/internal/jsonvaluecache"
)

type permissionDecodeKey struct{}
type permissionDecodeCache struct {
	roles     *jsonvaluecache.Cache[RoleDefinition]
	roleRows  *jsonvaluecache.Cache[[]RoleDefinition]
	grants    *jsonvaluecache.Cache[Grant]
	grantRows *jsonvaluecache.Cache[[]Grant]
}

// Reuse parsing only after each transaction reads fresh authoritative bytes.
// This context never contains a permission decision or a snapshot of SQL facts.
func (s *SQLStore) withPermissionDecode(ctx context.Context) context.Context {
	if s == nil || s.permissionDecode == nil {
		return ctx
	}
	return context.WithValue(ctx, permissionDecodeKey{}, s.permissionDecode)
}

func clonePermissionGrant(g Grant) Grant {
	g.DataScope.IDs = slices.Clone(g.DataScope.IDs)
	if g.StartsAt != nil {
		v := *g.StartsAt
		g.StartsAt = &v
	}
	if g.ExpiresAt != nil {
		v := *g.ExpiresAt
		g.ExpiresAt = &v
	}
	return g
}

func newPermissionDecodeCache() *permissionDecodeCache {
	return &permissionDecodeCache{
		roles: jsonvaluecache.New(64, 1<<20, func(raw []byte) (RoleDefinition, error) {
			var v RoleDefinition
			err := json.Unmarshal(raw, &v)
			return v, err
		}, clonePermissionRole),
		roleRows:  jsonvaluecache.New(64, 4<<20, parsePermissionRoleRows, clonePermissionRoleRows),
		grants:    jsonvaluecache.New(256, 4<<20, func(raw []byte) (Grant, error) { var v Grant; err := json.Unmarshal(raw, &v); return v, err }, clonePermissionGrant),
		grantRows: jsonvaluecache.New(32, 4<<20, parsePermissionGrantRows, clonePermissionGrantRows),
	}
}

func clonePermissionRole(value RoleDefinition) RoleDefinition {
	value.Actions = slices.Clone(value.Actions)
	value.ScopeTypes = slices.Clone(value.ScopeTypes)
	return value
}

func parsePermissionRoleRows(raw []byte) ([]RoleDefinition, error) {
	var rows []RoleDefinition
	if err := json.Unmarshal(raw, &rows); err != nil {
		return nil, err
	}
	if rows == nil {
		rows = []RoleDefinition{}
	}
	return rows, nil
}

func clonePermissionRoleRows(value []RoleDefinition) []RoleDefinition {
	rows := slices.Clone(value)
	for i := range rows {
		rows[i] = clonePermissionRole(rows[i])
	}
	return rows
}

func decodePermissionRoleRows(ctx context.Context, raw []byte) ([]RoleDefinition, error) {
	if cache, ok := ctx.Value(permissionDecodeKey{}).(*permissionDecodeCache); ok && cache != nil {
		return cache.roleRows.Decode(raw)
	}
	return parsePermissionRoleRows(raw)
}

func decodePermissionRole(ctx context.Context, raw []byte) (RoleDefinition, error) {
	if cache, ok := ctx.Value(permissionDecodeKey{}).(*permissionDecodeCache); ok && cache != nil {
		return cache.roles.Decode(raw)
	}
	var value RoleDefinition
	err := json.Unmarshal(raw, &value)
	return value, err
}
func decodePermissionGrant(ctx context.Context, raw []byte) (Grant, error) {
	if cache, ok := ctx.Value(permissionDecodeKey{}).(*permissionDecodeCache); ok && cache != nil {
		return cache.grants.Decode(raw)
	}
	var value Grant
	err := json.Unmarshal(raw, &value)
	return value, err
}
