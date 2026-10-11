package evaluationproduct

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// cancellationObserver checks what the interrupted worker can actually read.
// 在通知边界读取持久化状态，验证子 Run 不会将主动取消误判为进程退出。
type cancellationObserver struct {
	store Store
	calls int
	err   error
}

func (*cancellationObserver) Enqueue(context.Context, Scope, Resource) error { return nil }

func (d *cancellationObserver) Cancel(ctx context.Context, scope Scope, id string, revision uint64) error {
	d.calls++
	row, err := d.store.Get(ctx, scope, KindRun, id)
	if err != nil {
		return err
	}
	var data RunData
	if json.Unmarshal(row.Data, &data) != nil || row.Status != "cancelling" || data.ExecutionState != "cancelling" || row.Revision != revision {
		return errors.New("worker interrupted before durable cancellation")
	}
	if ctx.Err() != nil {
		return errors.New("cancellation notification inherited client disconnection")
	}
	return d.err
}

func TestModuleCancellationPersistsBeforeWorkerNotification(t *testing.T) {
	for _, notificationUnavailable := range []bool{false, true} {
		name := "notified"
		if notificationUnavailable {
			name = "notification_unavailable"
		}
		t.Run(name, func(t *testing.T) {
			store := newMemoryStore()
			scope := Scope{TenantID: "tenant-a", DepartmentID: "dept-a", ApplicationID: "app-a"}
			data, _ := json.Marshal(RunData{ExecutionState: "running", LeaseToken: "lease-test", LeaseUntil: time.Now().Add(time.Minute)})
			if err := store.Create(context.Background(), Resource{ID: "cancel-order", Kind: KindRun, Scope: scope, Status: "running", Revision: 3, CreatedBy: "alice", Data: data}); err != nil {
				t.Fatal(err)
			}
			dispatcher := &cancellationObserver{store: store}
			want := http.StatusAccepted
			if notificationUnavailable {
				dispatcher.err = errors.New("notification unavailable")
				want = http.StatusAccepted
			}
			module := NewModule(store, "module-secret", allowAuthorizer(func(context.Context, Actor, Action, Scope) error { return nil }), dispatcher)
			response := request(module, http.MethodPost, "/runs/cancel-order/cancel", `{"expected_revision":3}`, "alice", true)
			if response.Code != want || dispatcher.calls != 1 {
				t.Fatalf("cancel status=%d want=%d notification calls=%d", response.Code, want, dispatcher.calls)
			}
			row := decodeResource(t, response)
			if row.Status != "cancelling" || row.Revision != 4 {
				t.Fatalf("lost persisted cancellation identity: %+v", row)
			}
			stored, err := store.Get(context.Background(), scope, KindRun, row.ID)
			if err != nil {
				t.Fatal(err)
			}
			var persisted RunData
			if err := json.Unmarshal(stored.Data, &persisted); err != nil || persisted.ExecutionState != "cancelling" || persisted.LeaseToken != "lease-test" {
				t.Fatal("cancellation changed ownership evidence or omitted the durable fence", err)
			}
			if strings.Contains(response.Body.String(), "lease-test") {
				t.Fatal("cancellation response leaked the private ownership token")
			}
			repeated := request(module, http.MethodPost, "/runs/cancel-order/cancel", `{"expected_revision":3}`, "alice", true)
			if repeated.Code != http.StatusConflict || dispatcher.calls != 1 {
				t.Fatal("stale cancellation repeated the interrupt", repeated.Code, dispatcher.calls)
			}
		})
	}
}

type cancellationConflictStore struct{ *memoryStore }

func (*cancellationConflictStore) UpdateCAS(context.Context, Scope, Kind, string, uint64, Resource) error {
	return ErrConflict
}

func TestModuleCancellationCASConflictDoesNotInterruptWorker(t *testing.T) {
	store := &cancellationConflictStore{newMemoryStore()}
	scope := Scope{TenantID: "tenant-a", DepartmentID: "dept-a", ApplicationID: "app-a"}
	data, _ := json.Marshal(RunData{ExecutionState: "running"})
	if err := store.Create(context.Background(), Resource{ID: "cancel-conflict", Kind: KindRun, Scope: scope, Status: "running", Revision: 3, CreatedBy: "alice", Data: data}); err != nil {
		t.Fatal(err)
	}
	dispatcher := &cancellationObserver{store: store}
	module := NewModule(store, "module-secret", allowAuthorizer(func(context.Context, Actor, Action, Scope) error { return nil }), dispatcher)
	response := request(module, http.MethodPost, "/runs/cancel-conflict/cancel", `{"expected_revision":3}`, "alice", true)
	if response.Code != http.StatusConflict || dispatcher.calls != 0 {
		t.Fatal("CAS conflict interrupted an unmodified live worker", response.Code, dispatcher.calls)
	}
	row, err := store.Get(context.Background(), scope, KindRun, "cancel-conflict")
	if err != nil || row.Status != "running" || row.Revision != 3 {
		t.Fatal("conflicted cancellation modified durable state", err)
	}
}

type cancellationDisconnectStore struct {
	*memoryStore
	disconnect context.CancelFunc
}

func (s *cancellationDisconnectStore) UpdateCAS(ctx context.Context, scope Scope, kind Kind, id string, expected uint64, row Resource) error {
	if err := s.memoryStore.UpdateCAS(ctx, scope, kind, id, expected, row); err != nil {
		return err
	}
	s.disconnect()
	return nil
}

func TestModuleCancellationNotificationSurvivesClientDisconnect(t *testing.T) {
	ctx, disconnect := context.WithCancel(context.Background())
	defer disconnect()
	store := &cancellationDisconnectStore{memoryStore: newMemoryStore(), disconnect: disconnect}
	scope := Scope{TenantID: "tenant-a", DepartmentID: "dept-a", ApplicationID: "app-a"}
	data, _ := json.Marshal(RunData{ExecutionState: "running"})
	if err := store.Create(ctx, Resource{ID: "cancel-disconnect", Kind: KindRun, Scope: scope, Status: "running", Revision: 3, CreatedBy: "alice", Data: data}); err != nil {
		t.Fatal(err)
	}
	dispatcher := &cancellationObserver{store: store}
	module := NewModule(store, "module-secret", allowAuthorizer(func(context.Context, Actor, Action, Scope) error { return nil }), dispatcher)
	req := httptest.NewRequest(http.MethodPost, "/runs/cancel-disconnect/cancel", strings.NewReader(`{"expected_revision":3}`)).WithContext(ctx)
	req.Header.Set("Authorization", "Bearer module-secret")
	req.Header.Set("X-Tenant-ID", scope.TenantID)
	req.Header.Set("X-Department-ID", scope.DepartmentID)
	req.Header.Set("X-Application-ID", scope.ApplicationID)
	req.Header.Set("X-Principal-Type", "user")
	req.Header.Set("X-Principal-ID", "alice")
	req.Header.Set("X-Browser-Module", "1")
	response := httptest.NewRecorder()
	module.Handler().ServeHTTP(response, req)
	if ctx.Err() == nil || response.Code != http.StatusAccepted || dispatcher.calls != 1 {
		t.Fatal("client disconnection prevented a committed cancellation notification", response.Code, dispatcher.calls)
	}
}
