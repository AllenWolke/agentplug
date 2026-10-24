package identity

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSQLPersonalPermissionRequestHTTPMatchesLiveProjection(t *testing.T) {
	f := newAdministratorFixture(t)
	f.store.SetPermissionResourceResolver(enrollmentFixtureResolver{})
	handler := NewModule(f.store, "private-fixture-token").Handler()
	call := func(actor int, method, path string, body any) *httptest.ResponseRecorder {
		t.Helper()
		raw, _ := json.Marshal(body)
		r := httptest.NewRequest(method, path, strings.NewReader(string(raw)))
		principal, err := f.store.GetPrincipal(f.ctx, PrincipalUser, f.actors[actor].PrincipalID)
		if err != nil {
			t.Fatal(err)
		}
		setBrowserIdentityHeaders(r, principal, f.actors[actor].DepartmentID, f.actors[actor].ApplicationID)
		r.Header.Set("Authorization", "Bearer private-fixture-token")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	for _, actor := range []int{0, 2} {
		projection := call(actor, http.MethodGet, "/me/permissions", nil)
		var value struct {
			Allowed *bool `json:"personal_permission_requests_allowed"`
		}
		if projection.Code != 200 || json.Unmarshal(projection.Body.Bytes(), &value) != nil || value.Allowed == nil || *value.Allowed != (actor == 2) {
			t.Fatal("live projection mismatch", projection.Code, projection.Body.String())
		}
		create := call(actor, http.MethodPost, "/permission-requests", permissionApplicationCommand(f, "http-personal-request"))
		if actor == 0 {
			if create.Code != http.StatusForbidden || !strings.Contains(create.Body.String(), "SYSTEM_ADMIN_PERSONAL_REQUEST_DISABLED") {
				t.Fatal("missing system-account denial", create.Code, create.Body.String())
			}
		} else if create.Code != http.StatusCreated {
			t.Fatal("ordinary request failed", create.Code, create.Body.String())
		}
	}
}
