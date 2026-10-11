package conversation

import (
	"context"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
)

type replayHistoryStore struct {
	*moduleStore
	resource SessionResource
}

func (s replayHistoryStore) GetSessionResource(context.Context, Scope, string) (SessionResource, error) {
	return s.resource, nil
}
func (s replayHistoryStore) ListAuthorized(context.Context, Scope, Query, HistoryAccessPlan) (Page, error) {
	return Page{}, ErrForbidden
}
func (s replayHistoryStore) GetExportSessionID(context.Context, Scope, string) (string, error) {
	return "", ErrForbidden
}

type replayDecision struct {
	matched bool
	err     error
	calls   int
}

func (d *replayDecision) MatchRunReplay(context.Context, Scope, string, RunStartRequest) (bool, error) {
	d.calls++
	return d.matched, d.err
}

type replayPermission struct {
	allowRun bool
	calls    []string
}

func (p *replayPermission) ReadPlan(context.Context, Scope) (HistoryAccessPlan, error) {
	return HistoryAccessPlan{}, ErrForbidden
}
func (p *replayPermission) Authorize(_ context.Context, _ Scope, _ SessionResource, action string) error {
	p.calls = append(p.calls, action)
	if action == "run" && p.allowRun {
		return nil
	}
	return ErrForbidden
}

func TestAcceptedRunReplayRequiresCurrentRunGrantAndNeverDispatches(t *testing.T) {
	for _, tc := range []struct {
		name           string
		matched, allow bool
		err            error
		status         int
		action         string
	}{
		{"accepted replay", true, true, nil, 202, "run"},
		{"revoked run", true, false, nil, 403, "run"},
		{"different command", false, true, ErrRunReplayConflict, 409, ""},
		{"database unavailable", false, true, errors.New("SQL unavailable"), 500, ""},
		{"new continuation", false, true, nil, 403, "history.continue"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := replayHistoryStore{moduleStore: newModuleStore(), resource: SessionResource{ID: "session", OwnerID: "alice", PrincipalType: "user", InstallationID: "install", AgentID: "qa", AgentVersionID: "v1", MessageCount: 1}}
			module := NewModule(store, "module-token", false)
			starter := &stubRunStarter{}
			resolver := &replayDecision{matched: tc.matched, err: tc.err}
			permission := &replayPermission{allowRun: tc.allow}
			module.SetRunStarter(starter)
			module.SetRunReplayResolver(resolver)
			module.SetAccessControl(permission)
			r := httptest.NewRequest("POST", "/sessions/session/runs", strings.NewReader(`{"run_id":"accepted","idempotency_key":"key","request":{"question":"original"}}`))
			requestHeaders(r, "alice")
			r.Header.Set("X-Browser-Module", "1")
			w := httptest.NewRecorder()
			module.Handler().ServeHTTP(w, r)
			lookups := 1
			if !tc.allow {
				lookups = 0
			}
			if w.Code != tc.status || starter.called || resolver.calls != lookups {
				t.Fatalf("replay status/dispatch: status=%d body=%s starter=%v lookup=%d", w.Code, w.Body, starter.called, resolver.calls)
			}
			wantActions := []string{"run"}
			if tc.allow && tc.err == nil {
				wantActions = append(wantActions, tc.action)
			}
			if len(permission.calls) != len(wantActions) {
				t.Fatal("wrong current authority", permission.calls)
			}
			for i, action := range wantActions {
				if permission.calls[i] != action {
					t.Fatal("wrong current action", permission.calls)
				}
			}
			if w.Code == 202 && (!strings.Contains(w.Body.String(), `"run_id":"accepted"`) || strings.Contains(w.Body.String(), "question")) {
				t.Fatal("replay leaked business data", w.Body)
			}
		})
	}
}

func TestBusinessReplayHashUsesExactCanonicalInput(t *testing.T) {
	a, err := BusinessRequestHash([]byte(`{"question":"original","count":9007199254740993,"policy_snapshot":{"hash":"old"}}`))
	if err != nil {
		t.Fatal(err)
	}
	b, err := BusinessRequestHash([]byte(`{"policy_snapshot":{"hash":"untrusted"},"count":9007199254740993,"question":"original"}`))
	if err != nil || a != b {
		t.Fatal("ignored policy/reordering changed semantic command", err)
	}
	c, err := BusinessRequestHash([]byte(`{"question":"original","count":9007199254740992}`))
	if err != nil || a == c {
		t.Fatal("large integer was rounded during comparison", err)
	}
	for _, body := range []string{`null`, `[]`, `"question"`, `{} {}`, `{"protocol_version":"agent-execution/v2"}`} {
		if _, err := BusinessRequestHash([]byte(body)); !errors.Is(err, ErrInvalidQuery) {
			t.Fatal("invalid replay input accepted", body, err)
		}
	}
}
