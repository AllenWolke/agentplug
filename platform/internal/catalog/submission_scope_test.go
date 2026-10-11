package catalog

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestWorkspaceSubmissionDoesNotConferGlobalAccessOrAnotherPublisher(t *testing.T) {
	for _, tc := range []struct {
		name, query, publisher string
		status                 int
	}{
		{"own workspace and publisher", "?tenant_id=t&department_id=d&application_id=a", "alice", 201},
		{"global submission still denied", "", "alice", 403},
		{"other workspace denied", "?tenant_id=t&department_id=d&application_id=other", "alice", 403},
		{"partial workspace rejected", "?tenant_id=t", "alice", 400},
		{"duplicate workspace rejected", "?tenant_id=t&tenant_id=t&department_id=d&application_id=a", "alice", 400},
		{"other publisher denied", "?tenant_id=t&department_id=d&application_id=a", "bob", 403},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := &memoryStore{}
			module := NewModule(submittedMemoryStore{store}, "runtime")
			module.SetControlAuthorizer(controlAuthorizerFunc(func(_ context.Context, actor ControlActor, action ControlAction, scope ControlScope) error {
				if action != ControlSubmit || scope != (ControlScope{TenantID: "t", DepartmentID: "d", ApplicationID: "a"}) {
					return ErrCatalogForbidden
				}
				return nil
			}))
			body := strings.Replace(definitionRequestJSON("def", "agent", "Agent"), `"publisher_id":"platform"`, `"publisher_id":"`+tc.publisher+`"`, 1)
			r := httptest.NewRequest(http.MethodPost, "/definitions"+tc.query, strings.NewReader(body))
			for k, v := range map[string]string{"Authorization": "Bearer runtime", "X-Internal-Token": "runtime", "X-Browser-Module": "1", "X-Principal-Type": "user", "X-Principal-ID": "alice", "X-Tenant-ID": "t", "X-Department-ID": "d", "X-Application-ID": "a"} {
				r.Header.Set(k, v)
			}
			w := httptest.NewRecorder()
			module.Handler().ServeHTTP(w, r)
			if w.Code != tc.status {
				t.Fatalf("status=%d expected=%d body=%s", w.Code, tc.status, w.Body.String())
			}
		})
	}
}
