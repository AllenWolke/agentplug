package execution

import (
	"context"
	"encoding/json"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/agentgateway"
	"github.com/lexagent/platform/internal/contract"
	platformruntime "github.com/lexagent/platform/internal/runtime"
)

type stoppingDispatchGateway struct {
	started chan struct{}
	calls   atomic.Int32
	cancels atomic.Int32
}

func (g *stoppingDispatchGateway) Invoke(ctx context.Context, _ agentgateway.Target, _ contract.ExecuteRequest) (contract.ExecuteResponse, error) {
	if g.calls.Add(1) == 1 {
		close(g.started)
	}
	<-ctx.Done()
	return contract.ExecuteResponse{}, ctx.Err()
}

func (g *stoppingDispatchGateway) Resume(ctx context.Context, target agentgateway.Target, request contract.ExecuteRequest) (contract.ExecuteResponse, error) {
	return g.Invoke(ctx, target, request)
}

func (g *stoppingDispatchGateway) Cancel(_ context.Context, _ agentgateway.Target, request contract.ExecuteRequest) (contract.ExecuteResponse, error) {
	g.cancels.Add(1)
	return statusMatrixResponse(request.Scope.RunID, "cancelled"), nil
}

func TestWorkerShutdownRetainsDurableCommandWithoutBusinessCancellation(t *testing.T) {
	for _, transport := range []string{"gateway", "compatibility"} {
		for _, operation := range []string{"invoke", "resume"} {
			for _, shutdown := range []string{"close", "owner_cancel"} {
				t.Run(transport+"/"+operation+"/"+shutdown, func(t *testing.T) {
					id := "worker-stop-" + transport + "-" + operation + "-" + shutdown
					store := platformruntime.NewStore()
					var raw []byte
					if transport == "gateway" {
						raw = gatewayRequest(t, testScope(id), "invoke")
					} else {
						raw = legacyExecuteRequest(t, id, "invoke", nil)
					}
					created, err := store.Create(platformruntime.CreateRequest{ID: id, Scope: testScope(id).domain(), AgentVersionID: "v1", IdempotencyKey: id, Fingerprint: "worker-lifecycle", RequestJSON: raw, AgentEndpoint: "http://agent.example"})
					if err != nil {
						t.Fatal(err)
					}
					if operation == "resume" {
						running, err := store.Transition(id, platformruntime.StatusAccepted, platformruntime.StatusRunning, created.Run.Revision)
						if err != nil {
							t.Fatal(err)
						}
						if _, err = store.Transition(id, platformruntime.StatusRunning, platformruntime.StatusWaiting, running.Revision); err != nil {
							t.Fatal(err)
						}
						if _, err = store.PrepareResume(id, []byte(`{"decision":"approve"}`)); err != nil {
							t.Fatal(err)
						}
					}
					gateway := &stoppingDispatchGateway{started: make(chan struct{})}
					var dispatcher *Dispatcher
					if transport == "gateway" {
						dispatcher = NewDispatcherWithGateway(store, "secret", gateway, 1)
					} else {
						dispatcher = NewDispatcher(store, "secret", 1)
						dispatcher.client = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
							if gateway.calls.Add(1) == 1 {
								close(gateway.started)
							}
							<-request.Context().Done()
							return nil, request.Context().Err()
						})}
					}
					owner, cancelOwner := context.WithCancel(context.Background())
					defer cancelOwner()
					dispatcher.Start(owner)
					select {
					case <-gateway.started:
					case <-time.After(2 * time.Second):
						t.Fatal("worker did not dispatch")
					}
					if shutdown == "owner_cancel" {
						cancelOwner()
						select {
						case <-dispatcher.stopped:
						case <-time.After(2 * time.Second):
							t.Fatal("owner cancellation did not stop worker")
						}
					} else {
						closeCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
						defer cancel()
						if err = dispatcher.Close(closeCtx); err != nil {
							t.Fatal(err)
						}
					}
					got, err := store.Get(id)
					if err != nil {
						t.Fatal(err)
					}
					if got.Status != platformruntime.StatusRunning || got.LeaseToken == "" || gateway.calls.Load() != 1 || gateway.cancels.Load() != 0 {
						t.Fatalf("shutdown changed business intent or replayed: status=%s calls=%d cancels=%d", got.Status, gateway.calls.Load(), gateway.cancels.Load())
					}
					if operation == "resume" && string(got.ResumeInputJSON) != `{"decision":"approve"}` {
						t.Fatal("approved resume command lost")
					}
					if string(got.RequestJSON) != string(raw) {
						t.Fatal("durable input changed")
					}
					events, err := store.Events(id, 0)
					if err != nil {
						t.Fatal(err)
					}
					for _, event := range events {
						switch event.Type {
						case "attempt_failed", "cancel_requested", "task_cancelled", "task_completed":
							encoded, _ := json.Marshal(event)
							t.Fatalf("shutdown fabricated business outcome: %s", encoded)
						}
					}
				})
			}
		}
	}
}

func TestWorkerStopGuardDoesNotTreatRunCancellationAsShutdown(t *testing.T) {
	dispatcher := NewDispatcher(platformruntime.NewStore(), "secret", 1)
	owner, stopOwner := context.WithCancel(context.Background())
	defer stopOwner()
	worker := context.WithValue(owner, dispatcherWorkerLifecycleKey{}, owner)
	execution, cancel := context.WithCancel(worker)
	cancel()
	if dispatcher.workerStopping(execution) {
		t.Fatal("execution cancellation bypassed stopping policy")
	}
	deadline, stopDeadline := context.WithDeadline(worker, time.Now().Add(-time.Second))
	defer stopDeadline()
	if dispatcher.workerStopping(deadline) {
		t.Fatal("task timeout became worker shutdown")
	}
	stopOwner()
	if !dispatcher.workerStopping(execution) {
		t.Fatal("worker owner cancellation not recognized")
	}
}
