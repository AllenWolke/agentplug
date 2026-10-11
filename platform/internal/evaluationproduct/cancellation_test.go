package evaluationproduct

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
)

type cancellationCoordinatorFixture struct {
	complete bool
	err      error
	stops    int
}

func (c *cancellationCoordinatorFixture) RequestChildStops(context.Context, Resource) error {
	c.stops++
	return c.err
}
func (c *cancellationCoordinatorFixture) CancellationComplete(context.Context, Resource) (bool, error) {
	return c.complete, c.err
}

func TestProductCancellationRequiresChildSettlementBeforeTerminalCAS(t *testing.T) {
	ctx := context.Background()
	store := newMemoryStore()
	scope := Scope{TenantID: "cancel-tenant", DepartmentID: "cancel-dept", ApplicationID: "cancel-app"}
	data, _ := json.Marshal(RunData{ExecutionState: "cancelling", LeaseToken: "private-lease"})
	row := Resource{ID: "cancel-batch", Kind: KindRun, Scope: scope, Revision: 4, Status: "cancelling", CreatedBy: "alice", Data: data}
	if err := store.Create(ctx, row); err != nil {
		t.Fatal(err)
	}
	port := &cancellationCoordinatorFixture{}
	m := NewModule(store, "module-secret", nil, nil)
	m.SetCancellationCoordinator(port)
	if err := m.reconcileCancellation(ctx, row); err != nil {
		t.Fatal(err)
	}
	read, _ := store.Get(ctx, scope, KindRun, row.ID)
	if read.Status != "cancelling" || read.Revision != 4 {
		t.Fatal("pending children became terminal")
	}
	port.err = errors.New("evidence unavailable")
	if err := m.reconcileCancellation(ctx, row); err == nil {
		t.Fatal("missing evidence was accepted")
	}
	read, _ = store.Get(ctx, scope, KindRun, row.ID)
	if read.Status != "cancelling" {
		t.Fatal("unknown settlement became terminal")
	}
	port.err = nil
	port.complete = true
	if err := m.reconcileCancellation(ctx, row); err != nil {
		t.Fatal(err)
	}
	read, _ = store.Get(ctx, scope, KindRun, row.ID)
	var persisted RunData
	json.Unmarshal(read.Data, &persisted)
	if read.Status != "cancelled" || read.Revision != 5 || persisted.LeaseToken != "private-lease" {
		t.Fatal("completion omitted CAS or rewrote ownership evidence")
	}
	if err := m.reconcileCancellation(ctx, row); !errors.Is(err, ErrConflict) {
		t.Fatal("stale completion bypassed CAS")
	}
}

func TestProductHistoricalCancellationProjectionDoesNotRewriteHistory(t *testing.T) {
	data, _ := json.Marshal(RunData{ExecutionState: "cancelled"})
	row := Resource{Kind: KindRun, Status: "cancelled", Revision: 7, Data: data}
	port := &cancellationCoordinatorFixture{}
	m := NewModule(newMemoryStore(), "secret", nil, nil)
	m.SetCancellationCoordinator(port)
	projected := m.projectCancellation(context.Background(), row)
	if projected.Status != "cancelling" || row.Status != "cancelled" || projected.Revision != row.Revision || port.stops != 0 {
		t.Fatal("projection lied, mutated history, or executed control")
	}
	port.complete = true
	if got := m.projectCancellation(context.Background(), row); got.Status != "cancelled" {
		t.Fatal("verified completion remained pending")
	}
}
