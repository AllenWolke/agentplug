package execution

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sharedkernel"
)

func newWaitingQARun(t *testing.T, stages ...string) (*Module, sharedkernel.Scope) {
	return newWaitingReviewRun(t, "document-assistant", stages...)
}

func newWaitingReviewRun(t *testing.T, agentID string, stages ...string) (*Module, sharedkernel.Scope) {
	t.Helper()
	module := NewModule("secret")
	allowFixtureOwnedRunAccess(module)
	module.SetReviewAuditRecorder(func(context.Context, sharedkernel.Scope, string, string) error { return nil })
	scope := testScope("qa-human-review").domain()
	scope.AgentID = agentID
	scope.PrincipalID = "initiator"
	created, err := module.store.Create(platformruntime.CreateRequest{
		ID: scope.RunID, Scope: scope, AgentVersionID: scope.AgentVersionID,
		IdempotencyKey: "qa-review-idem", Fingerprint: "qa-review-fingerprint",
		RequestJSON:   []byte(`{"operation":"run","context_token":"signed-private-token","input":{"question":"What rule applies?"}}`),
		AgentEndpoint: "http://qa-agent.invalid",
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = module.store.Transition(scope.RunID, platformruntime.StatusAccepted, platformruntime.StatusRunning, created.Run.Revision)
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := module.store.AcquireLease(scope.RunID, "review-test-lease", time.Now().UTC(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	stage := "waiting_review"
	if len(stages) > 0 {
		stage = stages[0]
	}
	if _, err := module.store.FinalizeLeased(scope.RunID, platformruntime.StatusWaiting, claimed.Revision, claimed.LeaseToken, map[string]any{
		"stage": stage, "review": map[string]any{"schema_version": "agent-review/v1", "title": "Draft review", "summary": "draft answer", "references": []map[string]any{{"doc_id": "doc-1", "title": "Rulebook"}}},
		"references": []map[string]any{{"doc_id": "doc-1", "title": "Rulebook", "content": "private evidence"}},
	}, map[string]any{"source": "qa-agent"}); err != nil {
		t.Fatal(err)
	}
	return module, scope
}

func TestBrowserQAReviewPreviewIsScopedAndAuditGated(t *testing.T) {
	module, scope := newWaitingQARun(t)
	module.SetReviewAuthorizer(func(_ context.Context, got sharedkernel.Scope, reviewer string) error {
		if got != scope || reviewer != "reviewer" {
			return errors.New("denied")
		}
		return nil
	})
	auditCalls := 0
	module.SetReviewAuditRecorder(func(_ context.Context, got sharedkernel.Scope, actor, action string) error {
		if got != scope || actor != "reviewer" || action != "execution.review.read" {
			t.Fatal("wrong audit binding")
		}
		auditCalls++
		return nil
	})
	get := func(actor string, override map[string]string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodGet, "/platform/runs/"+scope.RunID+"/review", nil)
		for key, value := range map[string]string{
			"X-Internal-Token": "secret", "X-Browser-Module": "1", "X-Tenant-ID": scope.TenantID,
			"X-Department-ID": scope.DepartmentID, "X-Application-ID": scope.ApplicationID,
			"X-Principal-Type": "user", "X-Principal-ID": actor,
		} {
			request.Header.Set(key, value)
		}
		for key, value := range override {
			request.Header.Set(key, value)
		}
		response := httptest.NewRecorder()
		module.Handler().ServeHTTP(response, request)
		return response
	}
	for _, denied := range []*httptest.ResponseRecorder{
		get("initiator", nil), get("reviewer", map[string]string{"X-Application-ID": "other"}),
	} {
		if denied.Code == http.StatusOK || auditCalls != 0 {
			t.Fatalf("denied preview leaked status=%d body=%s", denied.Code, denied.Body.String())
		}
	}
	approved := get("reviewer", nil)
	if approved.Code != http.StatusOK || auditCalls != 1 || !strings.Contains(approved.Body.String(), "draft answer") || strings.Contains(approved.Body.String(), "signed-private-token") || strings.Contains(approved.Body.String(), "private evidence") {
		t.Fatalf("review preview status=%d audit=%d body=%s", approved.Code, auditCalls, approved.Body.String())
	}
	module.SetReviewAuditRecorder(func(context.Context, sharedkernel.Scope, string, string) error {
		return errors.New("audit unavailable")
	})
	failClosed := get("reviewer", nil)
	if failClosed.Code != http.StatusServiceUnavailable || strings.Contains(failClosed.Body.String(), "draft answer") {
		t.Fatalf("audit failure exposed draft: status=%d body=%s", failClosed.Code, failClosed.Body.String())
	}
}

func TestQAOwnerEventStreamStopsAtDurableReviewWait(t *testing.T) {
	module, scope := newWaitingQARun(t)
	request := httptest.NewRequest(http.MethodGet, "/platform/runs/"+scope.RunID+"/events?after_seq=0", nil)
	for key, value := range map[string]string{
		"X-Internal-Token": "secret", "X-Browser-Module": "1", "X-Tenant-ID": scope.TenantID,
		"X-Department-ID": scope.DepartmentID, "X-Application-ID": scope.ApplicationID,
		"X-Principal-Type": "user", "X-Principal-ID": scope.PrincipalID,
	} {
		request.Header.Set(key, value)
	}
	response := httptest.NewRecorder()
	module.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "event: waiting") {
		t.Fatalf("review wait stream status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestQAEventReplayContinuesPastHistoricalWaitAfterResume(t *testing.T) {
	module, scope := newWaitingQARun(t)
	resumed, err := module.store.PrepareResume(scope.RunID, []byte(`{"decision":"approve","reviewer_id":"reviewer"}`))
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := module.store.AcquireLease(scope.RunID, "resume-lease", time.Now().UTC(), time.Minute)
	if err != nil || claimed.Revision <= resumed.Revision {
		t.Fatalf("claim resumed run: %+v %v", claimed, err)
	}
	if _, err := module.store.FinalizeLeased(scope.RunID, platformruntime.StatusSucceeded, claimed.Revision, claimed.LeaseToken, map[string]any{"answer": "approved", "approval_status": "approved"}, map[string]any{"source": "qa-agent"}); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/platform/runs/"+scope.RunID+"/events?after_seq=0", nil)
	for key, value := range map[string]string{
		"X-Internal-Token": "secret", "X-Browser-Module": "1", "X-Tenant-ID": scope.TenantID,
		"X-Department-ID": scope.DepartmentID, "X-Application-ID": scope.ApplicationID,
		"X-Principal-Type": "user", "X-Principal-ID": scope.PrincipalID,
	} {
		request.Header.Set(key, value)
	}
	response := httptest.NewRecorder()
	module.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "event: waiting") || !strings.Contains(response.Body.String(), "event: task_completed") {
		t.Fatalf("historical wait truncated completed replay: status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestBrowserQAReviewRejectsUnrelatedWaitingState(t *testing.T) {
	module, scope := newWaitingQARun(t, "awaiting_clarification")
	module.SetReviewAuthorizer(func(context.Context, sharedkernel.Scope, string) error { return nil })
	response := browserReview(t, module, scope, "reviewer", `{"decision":"approve"}`, nil)
	if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), "REVIEW_NOT_WAITING") {
		t.Fatalf("unrelated interrupt status=%d body=%s", response.Code, response.Body.String())
	}
	run, err := module.store.Get(scope.RunID)
	if err != nil || run.Status != platformruntime.StatusWaiting || len(run.ResumeInputJSON) != 0 {
		t.Fatalf("unrelated interrupt mutated: %+v, %v", run, err)
	}
}

func TestBrowserQAReviewDecisionFailsClosedWhenAuditUnavailable(t *testing.T) {
	module, scope := newWaitingQARun(t)
	module.SetReviewAuthorizer(func(context.Context, sharedkernel.Scope, string) error { return nil })
	module.SetReviewAuditRecorder(func(context.Context, sharedkernel.Scope, string, string) error {
		return errors.New("audit unavailable")
	})
	response := browserReview(t, module, scope, "reviewer", `{"decision":"approve"}`, nil)
	if response.Code != http.StatusServiceUnavailable || !strings.Contains(response.Body.String(), "AUDIT_UNAVAILABLE") {
		t.Fatalf("audit failure status=%d body=%s", response.Code, response.Body.String())
	}
	run, err := module.store.Get(scope.RunID)
	if err != nil || run.Status != platformruntime.StatusWaiting || len(run.ResumeInputJSON) != 0 {
		t.Fatalf("audit failure mutated review: %+v, %v", run, err)
	}
}

func browserReview(t *testing.T, module *Module, scope sharedkernel.Scope, actor, body string, override map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, "/platform/runs/"+scope.RunID+"/resume", strings.NewReader(body))
	for key, value := range map[string]string{
		"X-Internal-Token": "secret", "X-Browser-Module": "1", "X-Tenant-ID": scope.TenantID,
		"X-Department-ID": scope.DepartmentID, "X-Application-ID": scope.ApplicationID,
		"X-Principal-Type": "user", "X-Principal-ID": actor,
	} {
		request.Header.Set(key, value)
	}
	for key, value := range override {
		request.Header.Set(key, value)
	}
	response := httptest.NewRecorder()
	module.Handler().ServeHTTP(response, request)
	return response
}

func TestBrowserQAReviewRequiresTrustedReviewerAndScope(t *testing.T) {
	for _, tc := range []struct {
		name     string
		actor    string
		body     string
		override map[string]string
		allow    bool
		status   int
	}{
		{"self-review", "initiator", `{"decision":"approve"}`, nil, true, http.StatusForbidden},
		{"missing-role", "reviewer", `{"decision":"approve"}`, nil, false, http.StatusForbidden},
		{"wrong-tenant", "reviewer", `{"decision":"approve"}`, map[string]string{"X-Tenant-ID": "other"}, true, http.StatusNotFound},
		{"wrong-app", "reviewer", `{"decision":"approve"}`, map[string]string{"X-Application-ID": "other"}, true, http.StatusNotFound},
		{"wrong-principal-type", "reviewer", `{"decision":"approve"}`, map[string]string{"X-Principal-Type": "service_principal"}, true, http.StatusNotFound},
		{"forged-scope", "reviewer", `{"decision":"approve","scope":{"tenant_id":"other"}}`, nil, true, http.StatusBadRequest},
		{"malformed-tail", "reviewer", `{"decision":"approve"} broken`, nil, true, http.StatusBadRequest},
		{"invalid-decision", "reviewer", `{"decision":"publish"}`, nil, true, http.StatusBadRequest},
		{"missing-rejection-reason", "reviewer", `{"decision":"reject"}`, nil, true, http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			module, scope := newWaitingQARun(t)
			module.SetReviewAuthorizer(func(_ context.Context, got sharedkernel.Scope, reviewer string) error {
				if got != scope || reviewer != "reviewer" || !tc.allow {
					return errors.New("denied")
				}
				return nil
			})
			response := browserReview(t, module, scope, tc.actor, tc.body, tc.override)
			if response.Code != tc.status {
				t.Fatalf("status=%d want=%d body=%s", response.Code, tc.status, response.Body.String())
			}
			run, err := module.store.Get(scope.RunID)
			if err != nil || run.Status != platformruntime.StatusWaiting || len(run.ResumeInputJSON) != 0 {
				t.Fatalf("denied review mutated run: %+v, %v", run, err)
			}
		})
	}
}

func TestBrowserQAReviewPersistsDecisionAndReplaysIdenticalCommand(t *testing.T) {
	for _, decision := range []string{"approve", "reject", "request_changes"} {
		t.Run(decision, func(t *testing.T) {
			module, scope := newWaitingQARun(t)
			module.SetReviewAuthorizer(func(_ context.Context, got sharedkernel.Scope, reviewer string) error {
				if got != scope || reviewer != "reviewer" {
					return errors.New("denied")
				}
				return nil
			})
			body := `{"decision":"` + decision + `","comment":"checked"}`
			response := browserReview(t, module, scope, "reviewer", body, nil)
			if response.Code != http.StatusOK {
				t.Fatalf("review status=%d body=%s", response.Code, response.Body.String())
			}
			run, err := module.store.Get(scope.RunID)
			if err != nil || run.Status != platformruntime.StatusRunning {
				t.Fatalf("review not persisted: %+v, %v", run, err)
			}
			var input map[string]string
			if err := json.Unmarshal(run.ResumeInputJSON, &input); err != nil || input["decision"] != decision || input["reviewer_id"] != "reviewer" {
				t.Fatalf("resume binding: %v, %v", input, err)
			}
			replay := browserReview(t, module, scope, "reviewer", body, nil)
			if replay.Code != http.StatusOK || !strings.Contains(replay.Body.String(), `"replayed":true`) {
				t.Fatalf("duplicate decision status=%d body=%s", replay.Code, replay.Body.String())
			}
			changed := browserReview(t, module, scope, "reviewer", `{"decision":"approve","comment":"changed"}`, nil)
			if changed.Code != http.StatusConflict {
				t.Fatalf("changed decision status=%d body=%s", changed.Code, changed.Body.String())
			}
			latest, err := module.store.Get(scope.RunID)
			if err != nil || latest.Revision != run.Revision || string(latest.ResumeInputJSON) != string(run.ResumeInputJSON) {
				t.Fatalf("replay changed durable run: %+v, %v", latest, err)
			}
			if decision == "request_changes" {
				claimed, err := module.store.AcquireLease(scope.RunID, "changes-review-lease", time.Now().UTC(), time.Minute)
				if err != nil {
					t.Fatal(err)
				}
				waiting, err := module.store.FinalizeLeased(scope.RunID, platformruntime.StatusWaiting, claimed.Revision, claimed.LeaseToken, map[string]any{"stage": "waiting_review"}, map[string]any{"source": "qa-agent"})
				if err != nil {
					t.Fatal(err)
				}
				replayedWaiting := browserReview(t, module, scope, "reviewer", body, nil)
				if replayedWaiting.Code != http.StatusOK || !strings.Contains(replayedWaiting.Body.String(), `"replayed":true`) {
					t.Fatalf("waiting replay consumed another interrupt: %d %s", replayedWaiting.Code, replayedWaiting.Body.String())
				}
				stillWaiting, err := module.store.Get(scope.RunID)
				if err != nil || stillWaiting.Status != platformruntime.StatusWaiting || stillWaiting.Revision != waiting.Revision {
					t.Fatalf("waiting replay changed Run: %+v, %v", stillWaiting, err)
				}
				newDecision := browserReview(t, module, scope, "reviewer", `{"decision":"approve"}`, nil)
				if newDecision.Code != http.StatusOK || strings.Contains(newDecision.Body.String(), `"replayed":true`) {
					t.Fatalf("new review decision not accepted: %d %s", newDecision.Code, newDecision.Body.String())
				}
			}
		})
	}
}

func TestQACompletionEventDoesNotConflateRejectionWithApproval(t *testing.T) {
	for _, approval := range []string{"approved", "rejected"} {
		t.Run(approval, func(t *testing.T) {
			module, scope := newWaitingQARun(t)
			resumed, err := module.store.PrepareResume(scope.RunID, []byte(`{"decision":"approve"}`))
			if err != nil {
				t.Fatal(err)
			}
			claimed, err := module.store.AcquireLease(scope.RunID, "final-review-lease", time.Now().UTC(), time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			if claimed.Revision <= resumed.Revision {
				t.Fatal("claim did not advance fencing revision")
			}
			dispatcher := NewDispatcher(module.store, "secret", 1)
			if err := dispatcher.finish(claimed, platformruntime.StatusSucceeded, map[string]any{"approval_status": approval, "answer": "draft"}, map[string]any{"source": "test"}); err != nil {
				t.Fatal(err)
			}
			outcome, err := module.store.GetOutcome(scope.RunID)
			if err != nil || outcome.EventType != "task_completed" || outcome.EventPayload["approval_status"] != approval || outcome.EventPayload["published"] != (approval == "approved") {
				t.Fatalf("approval event: %+v, %v", outcome, err)
			}
		})
	}
}
