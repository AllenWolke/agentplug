package identity

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"
	"time"
)

func TestPermissionParseReuseDoesNotCacheExpiryOrCallerMutation(t *testing.T) {
	ctx := context.WithValue(context.Background(), permissionDecodeKey{}, newPermissionDecodeCache())
	raw := []byte(`{"data_scope":{"type":"explicit_set","ids":["doc"]},"starts_at":"2026-10-15T00:00:00Z","expires_at":"2026-10-16T00:00:00Z"}`)
	first, err := decodePermissionGrant(ctx, raw)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 15, 1, 0, 0, 0, time.UTC)
	if !first.Effective(now) {
		t.Fatal("current value missing")
	}
	first.DataScope.IDs[0] = "foreign"
	*first.ExpiresAt = now.Add(48 * time.Hour)
	second, err := decodePermissionGrant(ctx, raw)
	if err != nil || second.DataScope.IDs[0] != "doc" || second.Effective(now.Add(25*time.Hour)) {
		t.Fatal("cached parse became stale authority", second, err)
	}
	if _, err := decodePermissionGrant(ctx, []byte(`{"data_scope":`)); err == nil {
		t.Fatal("corrupt replacement reused old parse")
	}
	changed, err := decodePermissionGrant(ctx, []byte(`{"data_scope":{"type":"owner"}}`))
	if err != nil || changed.DataScope.Type != "owner" {
		t.Fatal(changed, err)
	}
}

func TestRoleArrayDecodeClonesNestedListsAndReadsChangedBytes(t *testing.T) {
	ctx := context.WithValue(context.Background(), permissionDecodeKey{}, newPermissionDecodeCache())
	raw := []byte(`[{"role_code":"reader","scope_types":["application"],"actions":["knowledge.search"]}]`)
	first, err := decodePermissionRoleRows(ctx, raw)
	if err != nil {
		t.Fatal(err)
	}
	first[0].Actions[0], first[0].ScopeTypes[0], first[0].Name = "authorization.change", "global", "changed"
	second, err := decodePermissionRoleRows(ctx, raw)
	if err != nil || second[0].Actions[0] != "knowledge.search" || second[0].ScopeTypes[0] != "application" || second[0].Name != "" {
		t.Fatal("caller mutated a later role parse", second, err)
	}
	changed, err := decodePermissionRoleRows(ctx, []byte(`[{"role_code":"reader","actions":["run"]}]`))
	if err != nil || changed[0].Actions[0] != "run" {
		t.Fatal("new authoritative bytes reused stale roles", changed, err)
	}
	if _, err := decodePermissionRoleRows(ctx, []byte(`[{"actions":true}]`)); err == nil {
		t.Fatal("corrupt replacement reused a warmed value")
	}
}

func TestRoleArrayDecodePreservesOriginalHeaderSemantics(t *testing.T) {
	ctx := context.WithValue(context.Background(), permissionDecodeKey{}, newPermissionDecodeCache())
	for _, raw := range []string{`[]`, `null`, `[null]`, `[{"role_code":"x","actions":["run"]}]`, `{}`, `[true]`, `[{"actions":1}]`, `[] []`} {
		t.Run(raw, func(t *testing.T) {
			// The original header decoded an array and appended each role to an
			// already non-nil empty result. Compare that behavior independently.
			want := []RoleDefinition{}
			var rows []json.RawMessage
			original := json.Unmarshal([]byte(raw), &rows)
			if original == nil {
				for _, row := range rows {
					var value RoleDefinition
					if original = json.Unmarshal(row, &value); original != nil {
						break
					}
					want = append(want, value)
				}
			}
			for _, useCache := range []bool{false, true} {
				readCtx := context.Background()
				if useCache {
					readCtx = ctx
				}
				for i := 0; i < 2; i++ {
					got, err := decodePermissionRoleRows(readCtx, []byte(raw))
					if (original == nil) != (err == nil) || original == nil && !reflect.DeepEqual(want, got) {
						t.Fatal("role-array contract changed", got, err, original)
					}
				}
			}
		})
	}
}

func TestRoleParseReuseDoesNotShareActionLists(t *testing.T) {
	ctx := context.WithValue(context.Background(), permissionDecodeKey{}, newPermissionDecodeCache())
	raw := []byte(`{"role_code":"reader","scope_types":["application"],"actions":["knowledge.search"]}`)
	first, err := decodePermissionRole(ctx, raw)
	if err != nil {
		t.Fatal(err)
	}
	first.Actions[0] = "authorization.change"
	first.ScopeTypes[0] = "global"
	second, err := decodePermissionRole(ctx, raw)
	if err != nil || second.Actions[0] != "knowledge.search" || second.ScopeTypes[0] != "application" {
		t.Fatal(second, err)
	}
}
