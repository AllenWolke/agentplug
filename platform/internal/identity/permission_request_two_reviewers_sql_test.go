package identity

import (
	"context"
	"database/sql"
	"errors"
	"sync"
	"testing"

	"github.com/lexagent/platform/internal/sharedkernel"
)

func TestSQLPermissionRequestTwoAdministratorsOnlyOneSubsetCommits(t *testing.T) {
	f := newAdministratorFixture(t)
	f.store.SetPermissionResourceResolver(enrollmentFixtureResolver{})
	f.store.SetAuthorizationChangeRecorder(func(context.Context, *sql.Tx, sharedkernel.Scope, AuthorizationChangeReceipt) error { return nil })
	r, err := f.store.CreatePermissionRequest(f.ctx, f.actors[2], permissionApplicationCommand(f, "two-reviewers"))
	if err != nil {
		t.Fatal(err)
	}
	commands := make([]PermissionRequestDecision, 2)
	for i := range commands {
		commands[i] = applicationDecision(f, r, []string{"reviewer-one", "reviewer-two"}[i])
		commands[i].ApprovedItemIDs = []string{[]string{"run", "export"}[i]}
		plan, err := f.store.PreviewPermissionRequestDecision(f.ctx, f.actors[i], commands[i])
		if err != nil {
			t.Fatal(err)
		}
		commands[i].PlanDigest, commands[i].PlanExpiresAt = plan.Digest, plan.ExpiresAt
	}
	type result struct {
		reviewer int
		err      error
	}
	start := make(chan struct{})
	results := make(chan result, 2)
	var wg sync.WaitGroup
	for i := range commands {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			<-start
			_, err := f.store.DecidePermissionRequest(f.ctx, f.actors[index], commands[index])
			results <- result{index, err}
		}(i)
	}
	close(start)
	wg.Wait()
	close(results)
	winner, conflicts := -1, 0
	for result := range results {
		if result.err == nil {
			if winner != -1 {
				t.Fatal("two administrators committed the same request")
			}
			winner = result.reviewer
		} else if errors.Is(result.err, ErrIdentityConflict) {
			conflicts++
		} else {
			t.Fatal(result.err)
		}
	}
	if winner < 0 || conflicts != 1 {
		t.Fatal("expected one commit and one CAS conflict", winner, conflicts)
	}
	current, err := f.store.GetPermissionRequest(f.ctx, f.actors[2], r.ID)
	if err != nil || current.Revision != 2 || current.Status != "approved" || current.ReviewerID != f.actors[winner].PrincipalID {
		t.Fatal("request disagrees with winning reviewer", current, err)
	}
	for _, item := range current.Items {
		want := "rejected"
		if item.ID == commands[winner].ApprovedItemIDs[0] {
			want = "approved"
		}
		if item.Outcome != want {
			t.Fatal("item outcome differs from winning subset", item)
		}
	}
	snapshot, err := f.store.PermissionSnapshot(f.ctx, PrincipalUser, r.SubjectID)
	wantAction := []string{"run", "history.export"}[winner]
	if err != nil || snapshot.Principal.Revision != 2 || len(snapshot.Bindings) != 0 || len(snapshot.Grants) != 1 || snapshot.Grants[0].Action != wantAction {
		t.Fatal("extra or partial authorization survived", snapshot, err)
	}
	replay, err := f.store.DecidePermissionRequest(f.ctx, f.actors[winner], commands[winner])
	if err != nil || replay.Request.Revision != current.Revision || replay.Request.ReviewerID != current.ReviewerID {
		t.Fatal("winning receipt not replayable", replay, err)
	}
	if _, err := f.store.DecidePermissionRequest(f.ctx, f.actors[1-winner], commands[1-winner]); !errors.Is(err, ErrIdentityConflict) {
		t.Fatal("loser later acquired a conflicting receipt", err)
	}
}
