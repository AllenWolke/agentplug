package identity

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"testing"
)

func TestBuiltinCatalogV1CannotSilentlyExpand(t *testing.T) {
	roles := []RoleDefinition{}
	for _, role := range BuiltinRoleDefinitions() {
		if role.Version == 1 {
			roles = append(roles, role)
		}
	}
	presets := []IdentityPreset{}
	for _, preset := range BuiltinIdentityPresets() {
		if preset.Version == 1 {
			presets = append(presets, preset)
		}
	}
	// These hashes pin the published v1 role/preset contract, independently
	// of new action metadata or future, explicitly numbered catalog versions.
	for _, tc := range []struct {
		name  string
		value any
		want  string
	}{
		{"roles", roles, "8fa34d2f5aefc24850c24d1277ea9e360bec98c747c38a51a3b19cedf1bc149c"},
		{"presets", presets, "15d93f403b5e049a9b170f4f916285606bdb956653b843b4fe83cf7487eab32f"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := json.Marshal(tc.value)
			if err != nil || fmt.Sprintf("%x", sha256.Sum256(raw)) != tc.want {
				t.Fatal("published v1 changed: create an explicit new version", err)
			}
		})
	}
}

func TestActionCatalogHasCompleteConservativeMetadata(t *testing.T) {
	actions := BuiltinPermissionActions()
	seen := map[string]PermissionAction{}
	for _, action := range actions {
		if action.Code == "" || seen[action.Code].Code != "" || len(action.ScopeTypes) == 0 {
			t.Fatal("invalid action directory", action)
		}
		seen[action.Code] = action
		if action.Management {
			if action.ResourceType != "" || action.DefaultDataScope != nil {
				t.Fatal("management metadata implies a business Grant", action)
			}
		} else if action.ResourceType == "" || action.DefaultDataScope == nil || action.DefaultDataScope.Validate() != nil || slices.Contains(action.ScopeTypes, "global") {
			t.Fatal("business metadata has missing or broad defaults", action)
		}
		if action.SensitivityLevel == "" || action.Sensitive == (action.SensitivityLevel == "normal") {
			t.Fatal("sensitivity metadata disagrees", action)
		}
	}
	if len(actions) != 46 {
		t.Fatal("incomplete action catalog", len(actions))
	}
	for _, role := range BuiltinRoleDefinitions() {
		for _, code := range role.Actions {
			if seen[code].Code == "" {
				t.Fatal("role refers to undefined action", role.Code, code)
			}
		}
	}
	for _, preset := range BuiltinIdentityPresets() {
		for _, code := range preset.ResourceActions {
			action := seen[code]
			if action.Code == "" || action.Management || action.ResourceType != "agent_installation" || action.Sensitive {
				t.Fatal("unsupported or sensitive preset default", preset.Code, code)
			}
		}
	}
	managementIndex := slices.IndexFunc(actions, func(action PermissionAction) bool { return action.Code == "organization.manage" })
	if managementIndex < 0 {
		t.Fatal("missing organization management action")
	}
	actions[managementIndex].ScopeTypes[0] = "corrupted"
	actions[len(actions)-1].DefaultDataScope.Type = "approved_organization"
	if BuiltinPermissionActions()[managementIndex].ScopeTypes[0] != "global" || BuiltinPermissionActions()[len(actions)-1].DefaultDataScope.Type != "owner" {
		t.Fatal("caller mutated the shared catalog")
	}
}

func TestPermissionDirectoryHTTPUsesTheServerCatalog(t *testing.T) {
	snapshot, _ := permissionFixture()
	store := &permissionHTTPStore{memoryStore: &memoryStore{principal: snapshot.Principal}, snapshot: snapshot}
	handler := NewModule(store, "private-token").Handler()
	for _, tc := range []struct {
		path     string
		expected any
	}{
		{"/permission-actions", BuiltinPermissionActions()},
		{"/role-definitions", BuiltinRoleDefinitions()},
		{"/identity-presets", BuiltinIdentityPresets()},
	} {
		t.Run(tc.path, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, tc.path, nil)
			setBrowserIdentityHeaders(r, store.principal, "d", "a")
			r.Header.Del("Authorization")
			r.Header.Set("X-Internal-Token", "private-token")
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)
			var body struct {
				Items json.RawMessage `json:"items"`
			}
			if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &body) != nil {
				t.Fatal("directory failed", w.Code, w.Body)
			}
			want, _ := json.Marshal(tc.expected)
			var actualValue, expectedValue any
			if json.Unmarshal(body.Items, &actualValue) != nil || json.Unmarshal(want, &expectedValue) != nil || !reflect.DeepEqual(actualValue, expectedValue) {
				t.Fatal("API uses a different catalog", w.Body)
			}
		})
	}
}

func TestEveryPresetIsExplicitAndSeparatesHumanMachineAppointment(t *testing.T) {
	for _, preset := range BuiltinIdentityPresets() {
		t.Run(preset.Code, func(t *testing.T) {
			scope := ManagementScope{Type: preset.ScopeTypes[len(preset.ScopeTypes)-1]}
			if scope.Type != "global" {
				scope.TenantID = "tenant"
			}
			if scope.Type == "department" || scope.Type == "application" || scope.Type == "agent_installation" {
				scope.DepartmentID = "department"
			}
			if scope.Type == "application" || scope.Type == "agent_installation" {
				scope.ApplicationID = "application"
			}
			if scope.Type == "agent_installation" {
				scope.ResourceID = "selected-installation"
			}
			selection := PresetSelection{Code: preset.Code, Version: preset.Version, Scope: scope, ResourceIDs: []string{"selected-installation"}}
			bindings, grants, err := ExpandIdentityPreset(preset, preset.SubjectType, "subject", "source", selection)
			if preset.AppointmentOnly {
				if err == nil {
					t.Fatal("ordinary preset flow appointed an administrator")
				}
				return
			}
			if err != nil || len(grants) != len(preset.ResourceActions) {
				t.Fatal("supported preset could not expand", err, bindings, grants)
			}
			if preset.SubjectType == PrincipalServicePrincipal && len(bindings) != 0 || preset.SubjectType == PrincipalUser && (len(bindings) != 1 || bindings[0].RoleCode != preset.RoleCode || bindings[0].RoleVersion != preset.RoleVersion) {
				t.Fatal("wrong version or human/machine role separation", bindings)
			}
			for _, grant := range grants {
				if grant.ResourceID != "selected-installation" || grant.PresetVersion != preset.Version || grant.PresetCode != preset.Code || grant.SourceID != "source" {
					t.Fatal("preset expanded future/unselected resources", grant)
				}
			}
			selection.Version++
			if _, _, err := ExpandIdentityPreset(preset, preset.SubjectType, "subject", "source", selection); err == nil {
				t.Fatal("unpublished version accepted")
			}
			selection.Version = preset.Version
			otherKind := PrincipalServicePrincipal
			if preset.SubjectType == PrincipalServicePrincipal {
				otherKind = PrincipalUser
			}
			if _, _, err := ExpandIdentityPreset(preset, otherKind, "subject", "source", selection); err == nil {
				t.Fatal("wrong principal type accepted")
			}
		})
	}
}
