package identity

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lexagent/platform/internal/sharedkernel"
)

type authorizationReceiptHTTPFixture struct {
	*permissionHTTPStore
	reads, writes int
	readError     error
}

func (f *authorizationReceiptHTTPFixture) QueryAuthorizationReceipt(_ context.Context, actor sharedkernel.Scope, key, plan string) (AuthorizationChangeReceipt, error) {
	f.reads++
	if actor.PrincipalID != f.principal.ID || key != "fixture-original-command" || plan != strings.Repeat("a", 64) {
		panic("unexpected native receipt identity")
	}
	return AuthorizationChangeReceipt{ID: "native-change", ActorID: actor.PrincipalID, SubjectID: "target", Revision: 2, PlanDigest: plan}, f.readError
}

func (f *authorizationReceiptHTTPFixture) CommitAuthorizationChange(context.Context, sharedkernel.Scope, AuthorizationChangeCommand) (AuthorizationChangeReceipt, error) {
	f.writes++
	return AuthorizationChangeReceipt{}, ErrPermissionDenied
}

func TestAuthorizationReceiptReadKeepsAuthenticationAndStrictQueryBoundary(t *testing.T) {
	for _, mode := range []string{"allowed", "unauthenticated", "non-browser", "old-repository", "duplicate", "unknown-query", "bad-digest", "malformed-query", "wrong-method", "revoked", "not-found"} {
		t.Run(mode, func(t *testing.T) {
			snapshot, _ := permissionFixture()
			base := &permissionHTTPStore{memoryStore: &memoryStore{principal: snapshot.Principal}, snapshot: snapshot}
			fixture := &authorizationReceiptHTTPFixture{permissionHTTPStore: base}
			module := NewModule(fixture, "private-token")
			path := "/authorization-changes/receipt?idempotency_key=fixture-original-command&plan_digest=" + strings.Repeat("a", 64)
			method, expected := http.MethodGet, http.StatusOK
			switch mode {
			case "unauthenticated":
				expected = http.StatusUnauthorized
			case "non-browser":
				expected = http.StatusForbidden
			case "old-repository":
				module = NewModule(base, "private-token")
				expected = http.StatusServiceUnavailable
			case "duplicate":
				path += "&idempotency_key=another"
				expected = http.StatusBadRequest
			case "unknown-query":
				path += "&tenant_id=foreign"
				expected = http.StatusBadRequest
			case "bad-digest":
				path = strings.Replace(path, strings.Repeat("a", 64), "wrong", 1)
				expected = http.StatusBadRequest
			case "malformed-query":
				path += "&bad=%ZZ"
				expected = http.StatusBadRequest
			case "wrong-method":
				method = http.MethodPost
				expected = http.StatusMethodNotAllowed
			case "revoked":
				fixture.readError = ErrPermissionDenied
				expected = http.StatusForbidden
			case "not-found":
				fixture.readError = ErrAuthorizationReceiptNotFound
				expected = http.StatusNotFound
			}
			request := httptest.NewRequest(method, path, nil)
			if mode != "non-browser" {
				setBrowserIdentityHeaders(request, base.principal, "d", "a")
			}
			request.Header.Del("Authorization")
			request.Header.Del("X-Internal-Token")
			if mode != "unauthenticated" {
				request.Header.Set("X-Internal-Token", "private-token")
			}
			response := httptest.NewRecorder()
			module.Handler().ServeHTTP(response, request)
			if response.Code != expected || fixture.writes != 0 || base.previews != 0 {
				t.Fatalf("code=%d expected=%d reads=%d writes=%d previews=%d", response.Code, expected, fixture.reads, fixture.writes, base.previews)
			}
			if mode == "allowed" && (response.Header().Get("Cache-Control") != "no-store" || !strings.Contains(response.Body.String(), "native-change")) {
				t.Fatal("native response/cache boundary missing")
			}
			if mode != "allowed" && mode != "revoked" && mode != "not-found" && fixture.reads != 0 {
				t.Fatal("invalid request reached native lookup")
			}
		})
	}
}
