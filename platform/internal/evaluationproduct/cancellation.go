package evaluationproduct

import (
	"context"
	"encoding/json"
	"log"
	"time"
)

// These ports are installed by the platform composition root. Completion
// checks never invoke tools; reconciliation can only request governed stops.
type CancellationCoordinator interface {
	RequestChildStops(context.Context, Resource) error
	CancellationComplete(context.Context, Resource) (bool, error)
}

type cancellationQueue interface {
	PendingCancellationRuns(context.Context, string, int) ([]Resource, error)
}

func (m *Module) SetCancellationCoordinator(port CancellationCoordinator) { m.cancellation = port }

func cancellationCursor(row Resource) string {
	return row.Scope.TenantID + "|" + row.Scope.DepartmentID + "|" + row.Scope.ApplicationID + "|" + row.ID
}

func (m *Module) reconcileCancellations(ctx context.Context) {
	defer m.cancelWG.Done()
	queue, ok := m.store.(cancellationQueue)
	if !ok {
		log.Print("evaluation_cancellation_queue_unavailable")
		return
	}
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	cursor := ""
	for ctx.Err() == nil {
		pageCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		rows, err := queue.PendingCancellationRuns(pageCtx, cursor, 16)
		if err == nil && len(rows) == 0 {
			cursor = ""
		}
		for _, row := range rows {
			if pageCtx.Err() != nil {
				break
			}
			cursor = cancellationCursor(row)
			if err := m.reconcileCancellation(pageCtx, row); err != nil {
				log.Print("evaluation_cancellation_pending")
			}
		}
		cancel()
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (m *Module) reconcileCancellation(ctx context.Context, row Resource) error {
	if m.cancellation == nil || row.Kind != KindRun || row.Status != "cancelling" {
		return ErrUnavailable
	}
	if err := m.cancellation.RequestChildStops(ctx, row); err != nil {
		return err
	}
	complete, err := m.cancellation.CancellationComplete(ctx, row)
	if err != nil {
		return err
	}
	if !complete {
		return nil
	}
	var data RunData
	if json.Unmarshal(row.Data, &data) != nil || data.ExecutionState != "cancelling" {
		return ErrInvalid
	}
	expected := row.Revision
	row.Status, data.ExecutionState = "cancelled", "cancelled"
	row.Revision++
	row.UpdatedAt = time.Now().UTC()
	row.Data, _ = json.Marshal(data)
	return m.store.UpdateCAS(ctx, row.Scope, KindRun, row.ID, expected, row)
}

// Older heads recorded only the worker stop intent as "cancelled". Preserve
// their history, but expose a conservative read projection until the exact
// recorded children and required inverse receipts are confirmed.
func (m *Module) projectCancellation(ctx context.Context, row Resource) Resource {
	if row.Status != "cancelled" || m.cancellation == nil {
		return row
	}
	complete, err := m.cancellation.CancellationComplete(ctx, row)
	if err == nil && complete {
		return row
	}
	row.Status = "cancelling"
	var data RunData
	if json.Unmarshal(row.Data, &data) == nil {
		data.ExecutionState = "cancelling"
		data.ErrorCode = "CANCELLATION_SETTLEMENT_PENDING"
		row.Data, _ = json.Marshal(data)
	}
	return row
}
