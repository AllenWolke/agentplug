package execution

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/agentgateway"
	"github.com/lexagent/platform/internal/contract"
	platformruntime "github.com/lexagent/platform/internal/runtime"
)

// Exercise actual HTTP bodies, rather than comparing only an in-memory decoder.
func TestDispatcherHTTPPreservesOriginalAndResumeNumericEvidence(t *testing.T) {
	for _, gateway := range []bool{false, true} {
		for _, resume := range []bool{false, true} {
			name := map[bool]string{false: "compatibility", true: "gateway"}[gateway] + map[bool]string{false: "-invoke", true: "-resume"}[resume]
			t.Run(name, func(t *testing.T) {
				scope := testScope("numeric-" + name)
				var seen []byte
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					seen, _ = io.ReadAll(r.Body)
					w.Header().Set("Content-Type", "application/json")
					_ = json.NewEncoder(w).Encode(contract.ExecuteResponse{ProtocolVersion: contract.ProtocolVersion, RunID: scope.RunID, Status: "succeeded"})
				}))
				defer server.Close()
				var request contract.ExecuteRequest
				if err := contract.DecodeJSONPreservingNumbers(gatewayRequest(t, scope, "invoke"), &request); err != nil {
					t.Fatal(err)
				}
				request.Input["facts_check"] = map[string]any{"coverage": json.Number("1.0"), "large_id": json.Number("9007199254740993"), "threshold": json.Number("1e+3")}
				raw, err := json.Marshal(request)
				if err != nil {
					t.Fatal(err)
				}
				store := platformruntime.NewStore()
				created, err := store.Create(platformruntime.CreateRequest{ID: scope.RunID, Scope: scope.domain(), AgentVersionID: scope.AgentVersionID, IdempotencyKey: request.IdempotencyKey, Fingerprint: "numeric-fixture", RequestJSON: raw, AgentEndpoint: server.URL})
				if err != nil {
					t.Fatal(err)
				}
				run := created.Run
				if resume {
					run.ResumeInputJSON = []byte(`{"approved":true,"threshold":-0.0}`)
					// dispatch reloads its durable command from the repository.
					// Supply the same stored resume body through its normal transition.
					claimed, err := store.AcquireLease(run.ID, "numeric-previous-worker", time.Now().UTC(), dispatcherLeaseTTL)
					if err != nil {
						t.Fatal(err)
					}
					waiting, err := store.Transition(run.ID, platformruntime.StatusAccepted, platformruntime.StatusRunning, claimed.Revision)
					if err != nil {
						t.Fatal(err)
					}
					waiting, err = store.Transition(waiting.ID, platformruntime.StatusRunning, platformruntime.StatusWaiting, waiting.Revision)
					if err != nil {
						t.Fatal(err)
					}
					run, err = store.PrepareResume(waiting.ID, run.ResumeInputJSON)
					if err != nil {
						t.Fatal(err)
					}
				}
				d := NewDispatcher(store, "fixture", 1)
				if gateway {
					d = NewDispatcherWithGateway(store, "fixture", agentgateway.RemoteAdapter{Transport: agentgateway.NewHTTPTransport(server.Client())}, 1)
				}
				if err := d.dispatch(context.Background(), run); err != nil {
					t.Fatal(err)
				}
				for _, literal := range []string{`"coverage":1.0`, `"large_id":9007199254740993`, `"threshold":1e+3`} {
					if !strings.Contains(string(seen), literal) {
						t.Fatalf("HTTP request changed %s", literal)
					}
				}
				if resume && !strings.Contains(string(seen), `"threshold":-0.0`) {
					t.Fatal("resume evidence changed")
				}
				final, err := store.Get(run.ID)
				if err != nil || final.Status != platformruntime.StatusSucceeded {
					t.Fatal("HTTP dispatch did not complete", err)
				}
			})
		}
	}
}
