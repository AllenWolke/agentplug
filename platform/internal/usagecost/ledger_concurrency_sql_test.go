package usagecost

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/sqlutil"
)

func TestSQLUsageConcurrentFirstEventsRemainExactlyOnce(t *testing.T) {
	store := openModelBudgetSQLStore(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for round := 0; round < 3; round++ {
		scope := Scope{TenantID: fmt.Sprintf("usage-concurrent-%d-%d", time.Now().UnixNano(), round),
			DepartmentID: "department", ApplicationID: "application", AgentID: "validation", AgentVersionID: "v1", RunID: "run"}
		start := make(chan struct{})
		failures := make(chan error, 20)
		var workers sync.WaitGroup
		for index := 0; index < 20; index++ {
			workers.Add(1)
			go func(index int) {
				defer workers.Done()
				<-start
				event := Event{ID: fmt.Sprintf("%s-step-%d", scope.TenantID, index), Scope: scope,
					Provider: "mock", Model: "fixture", InputTokens: 3, OutputTokens: 2, CostMicros: 1}
				for replay := 0; replay < 2; replay++ {
					if _, err := store.Apply(ctx, event); err != nil {
						failures <- err
						return
					}
				}
			}(index)
		}
		close(start)
		workers.Wait()
		close(failures)
		for err := range failures {
			t.Errorf("concurrent event was rejected: sqlstate=%s error_type=%T", sqlutil.SQLState(err), err)
		}
		snapshot, err := store.GetSnapshot(ctx, scope)
		if err != nil || snapshot.UsedMicros != 20 || snapshot.InputTokens != 60 || snapshot.OutputTokens != 40 {
			t.Fatalf("lost or double-counted events: snapshot=%+v error_type=%T", snapshot, err)
		}
	}
}
