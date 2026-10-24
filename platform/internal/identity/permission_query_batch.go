package identity

// EvaluatePermissions evaluates one freshly acquired snapshot for a bounded
// set of queries. Each query still checks principal, roles, scope, validity,
// package version, assignment authority, explicit deny and self-review.
// Only DataScope validation and explicit-ID indexing are reused inside this
// call. The next call must acquire a fresh snapshot; no authority is cached.
func EvaluatePermissions(snapshot PermissionSnapshot, queries []PermissionQuery) ([]PermissionDecision, error) {
	if len(queries) > 10000 {
		return nil, ErrInvalidResource
	}
	decisions := make([]PermissionDecision, 0, len(queries))

	for _, query := range queries {
		decision, err := EvaluatePermission(snapshot, query)
		if err != nil {
			return nil, err
		}
		decisions = append(decisions, decision)
	}
	return decisions, nil
}

type permissionDataScope struct {
	err error
	ids map[string]struct{}
}
type permissionDataScopes map[int]permissionDataScope

func (scopes permissionDataScopes) compile(index int, scope DataScope) permissionDataScope {
	if value, ok := scopes[index]; ok {
		return value
	}
	value := permissionDataScope{err: scope.Validate()}
	if scopes != nil {
		if value.err == nil && scope.Type == "explicit_set" {
			value.ids = make(map[string]struct{}, len(scope.IDs))
			for _, id := range scope.IDs {
				value.ids[id] = struct{}{}
			}
		}
		scopes[index] = value
	}
	return value
}
