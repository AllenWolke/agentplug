package identity

import "testing"

func TestPresetExpansionUsesSelectedResourcesAndImmutableVersion(t *testing.T) {
	var p IdentityPreset
	for _, v := range BuiltinIdentityPresets() {
		if v.Code == "operator" {
			p = v
		}
	}
	selection := PresetSelection{Code: "operator", Version: 1, Scope: ManagementScope{Type: "application", TenantID: "t", DepartmentID: "d", ApplicationID: "a"}, ResourceIDs: []string{"i"}}
	bindings, grants, err := ExpandIdentityPreset(p, PrincipalUser, "u", "request-1", selection)
	if err != nil || len(bindings) != 1 || len(grants) != 5 {
		t.Fatal(bindings, grants, err)
	}
	for _, g := range grants {
		if g.ResourceID != "i" || g.PresetVersion != 1 || g.Action == "history.export" || g.Action == "history.share" {
			t.Fatal("unsafe preset grant", g)
		}
	}
	selection.ResourceIDs = nil
	_, grants, err = ExpandIdentityPreset(p, PrincipalUser, "u", "request-2", selection)
	if err != nil || len(grants) != 0 {
		t.Fatal("identity only preset failed", err)
	}
	selection.Version = 2
	if _, _, err := ExpandIdentityPreset(p, PrincipalUser, "u", "request-3", selection); err == nil {
		t.Fatal("latest version implied")
	}
	selection.Version = 1
	if _, _, err := ExpandIdentityPreset(p, PrincipalServicePrincipal, "machine", "request-4", selection); err == nil {
		t.Fatal("machine accepted human preset")
	}
	selection.ResourceIDs = []string{"i", "i"}
	if _, _, err := ExpandIdentityPreset(p, PrincipalUser, "u", "request-5", selection); err == nil {
		t.Fatal("duplicate selected resource accepted")
	}
}
