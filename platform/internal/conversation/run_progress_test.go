package conversation

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"testing"
)

type progressResolverFixture struct {
	calls int
	err   error
}

func (f *progressResolverFixture) ResolveRunProgress(context.Context, Scope, Summary) (*RunProgress, error) {
	f.calls++
	return &RunProgress{RunID: "run", Status: "waiting", Revision: 4, WaitingReview: true}, f.err
}

type progressAccessFixture struct{ allow bool }

func (f progressAccessFixture) ReadPlan(context.Context, Scope) (HistoryAccessPlan, error) {
	return HistoryAccessPlan{}, nil
}
func (f progressAccessFixture) Authorize(_ context.Context, _ Scope, _ SessionResource, action string) error {
	if f.allow && action == "history.read" {
		return nil
	}
	return ErrForbidden
}

func TestSessionProgressIsAuthorizedBeforeReadAndOutageKeepsHistory(t *testing.T) {
	store := replayHistoryStore{moduleStore: newModuleStore(), resource: SessionResource{ID: "session", OwnerID: "alice", PrincipalType: "user"}}
	store.sessions["session"] = Summary{ID: "session", Kind: "qa", OwnerID: "alice", Title: "original question"}
	resolver := &progressResolverFixture{}
	module := NewModule(store, "module-token", false)
	module.SetRunProgressResolver(resolver)
	read := func() (int, Summary) {
		r := httptest.NewRequest("GET", "/sessions/session", nil)
		requestHeaders(r, "alice")
		w := httptest.NewRecorder()
		module.Handler().ServeHTTP(w, r)
		var s Summary
		_ = json.Unmarshal(w.Body.Bytes(), &s)
		return w.Code, s
	}
	module.SetAccessControl(progressAccessFixture{allow: false})
	if code, _ := read(); code != 403 || resolver.calls != 0 {
		t.Fatal("unauthorized progress was read", code, resolver.calls)
	}
	module.SetAccessControl(progressAccessFixture{allow: true})
	if code, s := read(); code != 200 || s.RunProgress == nil || !s.RunProgress.WaitingReview {
		t.Fatal("authorized progress missing", code, s)
	}
	resolver.err = errors.New("execution unavailable")
	if code, s := read(); code != 200 || s.Title != "original question" || s.RunProgress != nil || !s.RunProgressUnavailable {
		t.Fatal("outage erased history or invented progress", code, s)
	}
}
