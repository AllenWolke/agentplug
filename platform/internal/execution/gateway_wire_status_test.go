package execution

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/agentgateway"
	executionv2 "github.com/lexagent/platform/internal/agentgateway/proto"
	"github.com/lexagent/platform/internal/contract"
	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sharedkernel"
	"google.golang.org/grpc"
)

type wireStatusAgent struct {
	executionv2.UnimplementedAgentExecutionServiceServer
	status  string
	invokes atomic.Int32
	cancels atomic.Int32
}

func (a *wireStatusAgent) Invoke(_ context.Context, request *executionv2.ExecuteRequest) (*executionv2.ExecuteResponse, error) {
	a.invokes.Add(1)
	response := statusMatrixResponse(request.Scope.RunId, a.status)
	wire := &executionv2.ExecuteResponse{ProtocolVersion: response.ProtocolVersion, RunId: response.RunID, Status: response.Status}
	if response.Error != nil {
		wire.Error = &executionv2.AppError{Code: response.Error.Code, Message: response.Error.Message, Retryable: response.Error.Retryable}
	}
	return wire, nil
}

func (a *wireStatusAgent) Cancel(_ context.Context, request *executionv2.ExecuteRequest) (*executionv2.ExecuteResponse, error) {
	a.cancels.Add(1)
	return &executionv2.ExecuteResponse{ProtocolVersion: contract.ProtocolVersion, RunId: request.Scope.RunId, Status: "cancelled"}, nil
}

// Exercise the real wire transports and adapter before asserting the durable
// platform state. / 穿过真实传输与适配器，再检查平台持久化状态。
func TestGatewayWireStatusMatrix(t *testing.T) {
	for _, protocol := range []string{"http", "grpc"} {
		for _, item := range []struct {
			status string
			want   platformruntime.Status
			stop   bool
		}{
			{"accepted", platformruntime.StatusCancelled, true},
			{"running", platformruntime.StatusCancelled, true},
			{"", platformruntime.StatusCancelled, true},
			{"waiting", platformruntime.StatusWaiting, false},
			{"succeeded", platformruntime.StatusSucceeded, false},
			{"failed", platformruntime.StatusFailed, false},
			{"cancelled", platformruntime.StatusCancelled, false},
		} {
			name := item.status
			if name == "" {
				name = "empty"
			}
			t.Run(protocol+"/"+name, func(t *testing.T) {
				var invokes, cancels atomic.Int32
				var grpcAgent *wireStatusAgent
				var endpoint string
				if protocol == "http" {
					server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer fresh-governed-context-token-") {
							t.Error("missing signed execution token")
						}
						var request contract.ExecuteRequest
						if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
							t.Error(err)
							w.WriteHeader(http.StatusBadRequest)
							return
						}
						status := item.status
						if strings.HasSuffix(r.URL.Path, "/cancel") {
							cancels.Add(1)
							status = "cancelled"
						} else {
							if r.URL.Path != "/internal/agent-execution/v2/invoke" || request.Operation != "invoke" {
								t.Error("platform worker must re-sign an invoke command for the strict SDK endpoint")
								w.WriteHeader(http.StatusBadRequest)
								return
							}
							invokes.Add(1)
						}
						w.Header().Set("Content-Type", "application/json")
						_ = json.NewEncoder(w).Encode(statusMatrixResponse(request.Scope.RunID, status))
					}))
					t.Cleanup(server.Close)
					endpoint = server.URL
				} else {
					listener, err := net.Listen("tcp", "127.0.0.1:0")
					if err != nil {
						t.Fatal(err)
					}
					server := grpc.NewServer()
					grpcAgent = &wireStatusAgent{status: item.status}
					executionv2.RegisterAgentExecutionServiceServer(server, grpcAgent)
					go func() { _ = server.Serve(listener) }()
					t.Cleanup(func() {
						server.Stop()
						_ = listener.Close()
					})
					endpoint = "grpc://" + listener.Addr().String()
				}

				scope := testScope("wire-" + protocol + "-" + name)
				store := platformruntime.NewStore()
				created, err := store.Create(platformruntime.CreateRequest{
					ID: scope.RunID, Scope: scope.domain(), AgentVersionID: "v1",
					IdempotencyKey: "idem-" + name, Fingerprint: "fp",
					RequestJSON: gatewayRequest(t, scope, "run"), AgentEndpoint: endpoint,
				})
				if err != nil {
					t.Fatal(err)
				}
				gateway := agentgateway.RemoteAdapter{Transport: agentgateway.RoutingTransport{
					HTTP: agentgateway.NewHTTPTransport(nil), GRPC: agentgateway.GRPCTransport{},
				}, Timeout: 2 * time.Second}
				dispatcher := NewDispatcherWithGateway(store, "secret", gateway, 1)
				dispatcher.SetSecurity(machineRunContextSignerFunc(func(context.Context, sharedkernel.Scope, contract.ExecuteRequest) (string, error) {
					return "fresh-governed-context-token-000000000000000000000000", nil
				}), func(context.Context, sharedkernel.Scope) error { return nil })
				// The HTTP/gRPC fixture returns envelopes without invoking providers.
				dispatcher.stopQuiescence = func(_ context.Context, owner sharedkernel.Scope) error {
					if owner != scope.domain() {
						return errors.New("fixture effect scope mismatch")
					}
					return nil
				}
				if err := dispatcher.dispatch(context.Background(), created.Run); err != nil {
					t.Fatal(err)
				}
				got, err := store.Get(scope.RunID)
				if err != nil || got.Status != item.want {
					t.Fatalf("status=%+v err=%v want=%s", got, err, item.want)
				}
				if grpcAgent != nil {
					invokes.Store(grpcAgent.invokes.Load())
					cancels.Store(grpcAgent.cancels.Load())
				}
				wantCancels := int32(0)
				if item.stop {
					wantCancels = 1
				}
				if invokes.Load() != 1 || cancels.Load() != wantCancels {
					t.Fatalf("wire calls invoke=%d cancel=%d wantCancel=%d", invokes.Load(), cancels.Load(), wantCancels)
				}
				events, err := store.Events(scope.RunID, 0)
				if err != nil {
					t.Fatal(err)
				}
				completed := 0
				for _, event := range events {
					if event.Type == "task_completed" {
						completed++
					}
				}
				if (completed == 1) != (item.status == "succeeded") {
					t.Fatalf("wrong completed events=%d for status=%q", completed, item.status)
				}
			})
		}
	}
}
