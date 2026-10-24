package execution

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"

	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sharedkernel"
)

type heldCancellationPage struct {
	*platformruntime.Store
	ids   []string
	reads []string
}

func (s *heldCancellationPage) ListPendingCancellationHeadersAfter(_ context.Context, after string, limit int) ([]platformruntime.Run, error) {
	var rows []platformruntime.Run
	for _, id := range s.ids {
		if id <= after {
			continue
		}
		r, err := s.Store.Get(id)
		if err != nil {
			return nil, err
		}
		if r.Status == platformruntime.StatusCancelling {
			rows = append(rows, platformruntime.Run{ID: id, Status: r.Status, Revision: r.Revision})
		}
		if len(rows) == limit {
			break
		}
	}
	return rows, nil
}
func (s *heldCancellationPage) GetContext(_ context.Context, id string) (platformruntime.Run, error) {
	s.reads = append(s.reads, id)
	return s.Store.Get(id)
}

func TestAutomaticRecoveryHoldsPreserveHistoryAndDoNotStarveNewCancellation(t *testing.T) {
	ctx := context.Background()
	repository := &heldCancellationPage{Store: platformruntime.NewStore()}
	before := map[string]platformruntime.Run{}
	ids := []string{}
	for n := 0; n < 34; n++ {
		id := fmt.Sprintf("history-%02d", n)
		scope := testScope(id).domain()
		scope.SessionID = id
		created, err := repository.Create(platformruntime.CreateRequest{ID: id, Scope: scope, AgentVersionID: scope.AgentVersionID, IdempotencyKey: id, Fingerprint: id})
		if err != nil {
			t.Fatal(err)
		}
		run, err := repository.BeginCancellation(id, created.Run.Revision)
		if err != nil {
			t.Fatal(err)
		}
		repository.ids = append(repository.ids, id)
		if n < 33 {
			ids = append(ids, id)
			before[id] = run
		}
	}
	holds, err := sharedkernel.NewRecoveryHolds(ids)
	if err != nil {
		t.Fatal(err)
	}
	for restart := 0; restart < 2; restart++ {
		d := NewDispatcher(repository, "owned", 1)
		m := NewModuleWithDispatcher("owned", repository, d)
		if err := m.SetAutomaticRecoveryHolds(holds); err != nil {
			t.Fatal(err)
		}
		if m.SetAutomaticRecoveryHolds(sharedkernel.RecoveryHolds{}) == nil {
			t.Fatal("holds replaced after configuration")
		}
		for n := 0; n < 6; n++ {
			d.reconcileCancellations(ctx)
		}
		for id, original := range before {
			current, err := repository.Get(id)
			if err != nil || !reflect.DeepEqual(current, original) {
				t.Fatal("historical cancellation changed", err)
			}
			if err = d.confirmCancellation(ctx, current); !errors.Is(err, sharedkernel.ErrAutomaticRecoveryHeld) {
				t.Fatal("direct stop bypassed hold", err)
			}
		}
	}
	fresh, err := repository.Get("history-33")
	if err != nil || fresh.Status != platformruntime.StatusCancelled {
		t.Fatal("new cancellation starved", err)
	}
	if !reflect.DeepEqual(repository.reads, []string{"history-33"}) {
		t.Fatal("held request bodies were loaded or restarted")
	}
}
