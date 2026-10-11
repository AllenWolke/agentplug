package identity

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lexagent/platform/internal/sharedkernel"
)

type explanationObjectFixture struct {
	objects map[string]DataObject
	failure error
}

func (r explanationObjectFixture) ResolvePermissionTask(_ context.Context, _ sharedkernel.Scope, _ ManagementScope, id string) (DataObject, error) {
	if r.failure != nil {
		return DataObject{}, r.failure
	}
	object, ok := r.objects[id]
	if !ok {
		return DataObject{}, sql.ErrNoRows
	}
	return object, nil
}

func TestSQLPermissionExplanationTrustedObjectsAndExistenceBoundary(t *testing.T) {
	f := newAdministratorFixture(t)
	f.store.SetPermissionResourceResolver(permissionTestResourceResolver{})
	actor := f.actors[2]
	app := ManagementScope{Type: "application", TenantID: actor.TenantID, DepartmentID: actor.DepartmentID, ApplicationID: actor.ApplicationID}
	scope := app
	scope.Type, scope.ResourceID = "agent_installation", "installation-test"
	own := DataObject{ID: "own-task", OwnerID: actor.PrincipalID, Scope: scope}
	assigned := DataObject{ID: "assigned-task", OwnerID: "another-owner", Scope: scope}
	hidden := DataObject{ID: "hidden-task", OwnerID: "another-owner", Scope: scope, AssignedTo: []string{actor.PrincipalID}}
	foreign := own
	foreign.ID, foreign.Scope.ApplicationID = "foreign-task", "outside-app"
	resolver := explanationObjectFixture{objects: map[string]DataObject{own.ID: own, assigned.ID: assigned, hidden.ID: hidden, foreign.ID: foreign}}
	f.store.SetPermissionTaskResolver(resolver)
	tx, err := f.db.BeginTx(f.ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	for _, role := range []string{"operator", "reviewer"} {
		if err = insertRoleBinding(f.ctx, tx, RoleBinding{ID: "object-" + role, SubjectID: actor.PrincipalID, RoleCode: role, RoleVersion: 1, Scope: app, Status: "active", Revision: 1, SourceID: "object-fixture"}); err != nil {
			t.Fatal(err)
		}
	}
	for _, spec := range []struct{ action, data string }{{"history.read", "owner"}, {"business.review", "assigned_task"}} {
		if err = insertPermissionGrant(f.ctx, tx, Grant{ID: "object-" + spec.action, SubjectType: PrincipalUser, SubjectID: actor.PrincipalID, TenantID: actor.TenantID, DepartmentID: actor.DepartmentID, ApplicationID: actor.ApplicationID,
			AgentInstanceID: scope.ResourceID, ResourceType: "agent_installation", ResourceID: scope.ResourceID, Action: spec.action, Effect: "allow", Status: "active", Revision: 1, SourceID: "object-fixture", DataScope: DataScope{Type: spec.data}}, f.now); err != nil {
			t.Fatal(err)
		}
	}
	for _, object := range []DataObject{own, assigned} {
		if err = insertTaskAssignment(f.ctx, tx, TaskAssignment{ID: "object-assignment-" + object.ID, SubjectID: actor.PrincipalID, TaskID: object.ID, Action: "business.review", Scope: scope, Status: "active", Revision: 1, SourceID: "object-fixture", TaskObject: &object}); err != nil {
			t.Fatal(err)
		}
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	principal, err := f.store.GetPrincipal(f.ctx, PrincipalUser, actor.PrincipalID)
	if err != nil {
		t.Fatal(err)
	}
	request := func(user Principal, action, objectID string, claims any) *httptest.ResponseRecorder {
		raw := map[string]any{"action": action, "scope": scope, "resource_type": "agent_installation", "resource_id": scope.ResourceID, "object_id": objectID}
		if claims != nil {
			raw["object"] = claims
		}
		body, _ := json.Marshal(raw)
		r := httptest.NewRequest(http.MethodPost, "/permissions:explain", strings.NewReader(string(body)))
		setBrowserIdentityHeaders(r, user, actor.DepartmentID, actor.ApplicationID)
		r.Header.Set("Authorization", "Bearer fixture-internal")
		w := httptest.NewRecorder()
		NewModule(f.store, "fixture-internal").Handler().ServeHTTP(w, r)
		return w
	}
	for _, tc := range []struct {
		action, id, reason string
		allowed            bool
	}{
		{"history.read", own.ID, "EXPLICIT_ALLOW", true},
		{"business.review", own.ID, "SELF_REVIEW_DENIED", false},
		{"business.review", assigned.ID, "EXPLICIT_ALLOW", true},
	} {
		w := request(principal, tc.action, tc.id, nil)
		var out PermissionExplanation
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &out) != nil || out.Allowed != tc.allowed || out.Reason != tc.reason || out.ObjectID != tc.id {
			t.Fatal("trusted object explanation", tc.reason, w.Code)
		}
		if strings.Contains(w.Body.String(), "owner_id") || strings.Contains(w.Body.String(), "participants") || strings.Contains(w.Body.String(), "another-owner") {
			t.Fatal("explanation exposed business participant facts")
		}
	}
	// Existing-but-inaccessible, missing and foreign objects are indistinguishable.
	var missingBody string
	for _, id := range []string{"missing-task", hidden.ID, foreign.ID} {
		w := request(principal, "business.review", id, nil)
		if w.Code != http.StatusNotFound {
			t.Fatal("object existence boundary", id, w.Code)
		}
		if missingBody == "" {
			missingBody = w.Body.String()
		} else if missingBody != w.Body.String() {
			t.Fatal("hidden object response differs from nonexistent object")
		}
	}
	if w := request(principal, "business.review", hidden.ID, map[string]any{"owner_id": actor.PrincipalID, "assigned_to": []string{actor.PrincipalID}}); w.Code != http.StatusBadRequest {
		t.Fatal("client ownership claims accepted", w.Code)
	}
	// A scoped authorization reader can diagnose a data denial without receiving
	// business content or default business execution privileges.
	q := PermissionQuery{Action: "history.read", Scope: scope, ResourceType: "agent_installation", ResourceID: scope.ResourceID}
	out, err := f.store.ExplainPermissionObject(f.ctx, f.actors[0], PrincipalUser, actor.PrincipalID, q, hidden.ID)
	if err != nil || out.Allowed || out.Reason != "DATA_SCOPE_MISMATCH" || len(out.Grants) != 0 {
		t.Fatal("administrator data denial explanation", out, err)
	}
	f.store.SetPermissionTaskResolver(explanationObjectFixture{failure: errors.New("business source unavailable")})
	if w := request(principal, "history.read", own.ID, nil); w.Code != http.StatusServiceUnavailable {
		t.Fatal("failed object source returned previous allow", w.Code)
	}
	f.store.SetPermissionTaskResolver(nil)
	if w := request(principal, "history.read", own.ID, nil); w.Code != http.StatusServiceUnavailable {
		t.Fatal("missing object source returned previous allow", w.Code)
	}
}
