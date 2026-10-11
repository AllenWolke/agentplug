package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/knowledge"
	"github.com/lexagent/platform/internal/usagecost"
)

func indexDiagnosticScopeHash(parts ...string) string {
	raw, _ := json.Marshal(parts)
	digest := sha256.Sum256(raw)
	return fmt.Sprintf("%x", digest[:])
}

func indexDiagnosticStateGroups(ctx context.Context, db *sql.DB, query, scopeHash string) string {
	rows, err := db.QueryContext(ctx, query, scopeHash)
	if err != nil {
		return "unavailable"
	}
	defer rows.Close()
	var groups []string
	for rows.Next() {
		var first, second string
		var count int
		if err := rows.Scan(&first, &second, &count); err != nil {
			return "unavailable"
		}
		groups = append(groups, fmt.Sprintf("%s/%s:%d", first, second, count))
	}
	if rows.Err() != nil {
		return "unavailable"
	}
	if len(groups) == 0 {
		return "none"
	}
	return strings.Join(groups, ",")
}

// indexWorkerTimeoutDiagnostic reports only the exact timed-out Run's durable
// state and scoped ledger counts. It never reads or emits invocation payloads,
// lease tokens, model output, notification bodies, or descendant event bodies.
func indexWorkerTimeoutDiagnostic(ctx context.Context, db *sql.DB, runID string) string {
	var tenant, department, application, agent, instance, principalType, principal, installation, version, session, status string
	var revision uint64
	var leasePresent, outcomePresent bool
	err := db.QueryRowContext(ctx, `SELECT tenant_id,department_id,application_id,agent_id,agent_instance_id,principal_type,principal_id,installation_id,agent_version_id,session_id,status,revision,(lease_token<>''),EXISTS(SELECT 1 FROM platform_execution_outcome WHERE run_id=$1) FROM platform_execution_run WHERE run_id=$1`, runID).Scan(
		&tenant, &department, &application, &agent, &instance, &principalType, &principal, &installation, &version, &session, &status, &revision, &leasePresent, &outcomePresent)
	if err != nil {
		return "persisted_state=unavailable"
	}
	modelHash := indexDiagnosticScopeHash(tenant, department, application, agent, instance, principalType, principal, installation, version, session)
	toolHash := indexDiagnosticScopeHash(tenant, department, application, agent, instance, principalType, principal, installation, version, session, runID)
	modelStates := indexDiagnosticStateGroups(ctx, db, `SELECT status,billing_state,COUNT(*) FROM platform_model_invocation WHERE scope_hash=$1 GROUP BY status,billing_state ORDER BY status,billing_state`, modelHash)
	toolStates := indexDiagnosticStateGroups(ctx, db, `SELECT status,phase,COUNT(*) FROM platform_tool_invocation WHERE scope_hash=$1 GROUP BY status,phase ORDER BY status,phase`, toolHash)
	var sessionLeaseRows, usageRows, inputTokens, outputTokens, notificationRows, internalStopReceipts, descendantRuns, descendantStopReceipts int64
	var usedMicros int64
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM platform_execution_session_lease WHERE run_id=$1`, runID).Scan(&sessionLeaseRows); err != nil {
		sessionLeaseRows = -1
	}
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*),COALESCE(SUM(input_tokens),0),COALESCE(SUM(output_tokens),0),COALESCE(SUM(cost_micros),0) FROM platform_usage_event WHERE run_id=$1`, runID).Scan(&usageRows, &inputTokens, &outputTokens, &usedMicros); err != nil {
		usageRows = -1
	}
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM platform_notification_outbox WHERE tenant_id=$1 AND department_id=$2 AND application_id=$3 AND payload_json IS JSON OBJECT AND payload_json::jsonb->>'run_id'=$4`, tenant, department, application, runID).Scan(&notificationRows); err != nil {
		notificationRows = -1
	}
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM platform_execution_event WHERE run_id=$1 AND event_type='internal_task_stopped'`, runID).Scan(&internalStopReceipts); err != nil {
		internalStopReceipts = -1
	}
	if err := db.QueryRowContext(ctx, `WITH RECURSIVE descendants(run_id,depth) AS (
 SELECT child.run_id,1 FROM platform_execution_run child WHERE child.request_json IS JSON OBJECT AND child.request_json::jsonb #>> '{scope,parent_run_id}'=$1
 UNION ALL
 SELECT child.run_id,parent.depth+1 FROM platform_execution_run child JOIN descendants parent ON child.request_json IS JSON OBJECT AND child.request_json::jsonb #>> '{scope,parent_run_id}'=parent.run_id WHERE parent.depth<16
) SELECT COUNT(DISTINCT descendants.run_id),COUNT(DISTINCT event.seq) FROM descendants LEFT JOIN platform_execution_event event ON event.run_id=descendants.run_id AND event.event_type='internal_task_stopped'`, runID).Scan(&descendantRuns, &descendantStopReceipts); err != nil {
		descendantRuns, descendantStopReceipts = -1, -1
	}
	return fmt.Sprintf("persisted_run={status:%q,revision:%d,lease_present:%t,outcome_present:%t,session_lease_rows:%d} model_scope_hash=%s model_states=%q tool_scope_hash=%s tool_states=%q usage={rows:%d,input_tokens:%d,output_tokens:%d,used_micros:%d} notification_outbox_run_rows=%d internal_stop_receipts=%d descendants={runs:%d,stop_receipts:%d}", status, revision, leasePresent, outcomePresent, sessionLeaseRows, modelHash, modelStates, toolHash, toolStates, usageRows, inputTokens, outputTokens, usedMicros, notificationRows, internalStopReceipts, descendantRuns, descendantStopReceipts)
}

func verifyRuntimeIndex(t *testing.T, ctx context.Context, db *sql.DB, client *http.Client, address string, f runtimeIndexFixture) {
	t.Helper()
	c := *client
	c.Timeout = 5 * time.Second
	invoke := func(method, path string, value any, want int, target any) {
		t.Helper()
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		r, err := http.NewRequestWithContext(ctx, method, "http://"+address+"/modules/knowledge/"+path, bytes.NewReader(raw))
		if err != nil {
			t.Fatal(err)
		}
		for key, val := range map[string]string{"X-Internal-Token": "gateway-fixture-0123456789abcdef0123456789abcdef", "X-Browser-Module": "1", "X-Principal-Type": "user", "X-Principal-ID": f.scope.PrincipalID, "X-Tenant-ID": f.scope.TenantID, "X-Department-ID": f.scope.DepartmentID, "X-Application-ID": f.scope.ApplicationID, "X-Authentication-Revision": "1", "X-Authentication-Session": f.session, "X-Trace-ID": f.scope.TraceID, "Content-Type": "application/json"} {
			r.Header.Set(key, val)
		}
		response, err := c.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		if response.StatusCode != want {
			body, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
			t.Fatalf("actual index process %s status=%d want=%d %s", path, response.StatusCode, want, body)
		}
		if target != nil && json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(target) != nil {
			t.Fatal("invalid index process response")
		}
	}
	change := map[string]any{"expected_source_revision": 0, "expected_document_version": 0, "idempotency_key": "process-source-full", "body": "Owned documentation: indexes reuse platform model governance and publish only consistent source versions.", "acl": knowledge.DocumentACL{OwnerPrincipalID: f.scope.PrincipalID}}
	invoke("PUT", "sources/docs/documents/guide", change, 200, nil)
	request := knowledge.IndexTaskRequest{InstallationID: f.scope.InstallationID, IdempotencyKey: "process-index-full", Mode: "full", Config: knowledge.IndexSettings{Dimensions: 2, WindowRunes: 512, OverlapRunes: 64, MaximumDocuments: 10, MaximumChunks: 100}}
	var receipt knowledge.IndexTaskReceipt
	invoke("POST", "indexes/docs/tasks", request, 202, &receipt)
	wait := func(id string, revision int64) knowledge.IndexTaskDetail {
		t.Helper()
		deadline := time.Now().Add(15 * time.Second)
		var last knowledge.IndexTaskDetail
		for time.Now().Before(deadline) {
			var detail knowledge.IndexTaskDetail
			invoke("GET", "indexes/docs/tasks/"+id, nil, 200, &detail)
			last = detail
			if detail.Status == "succeeded" {
				if detail.Result == nil || detail.Result.IndexRevision != revision || detail.Result.SourceRevision != revision {
					t.Fatal("process published wrong versions", detail)
				}
				return detail
			}
			if detail.Status == "failed" || detail.Status == "cancelled" {
				t.Fatal("process index failed", detail.Status)
			}
			time.Sleep(100 * time.Millisecond)
		}
		var status string
		var persistedRevision uint64
		var leasePresent, outcomePresent bool
		if err := db.QueryRowContext(ctx, `SELECT status,revision,(lease_token<>''),EXISTS(SELECT 1 FROM platform_execution_outcome WHERE run_id=$1) FROM platform_execution_run WHERE run_id=$1`, id).Scan(&status, &persistedRevision, &leasePresent, &outcomePresent); err != nil {
			status = "unavailable"
		}
		events := []string{}
		if rows, err := db.QueryContext(ctx, `SELECT event_type FROM platform_execution_event WHERE run_id=$1 ORDER BY seq`, id); err == nil {
			for rows.Next() {
				var eventType string
				if rows.Scan(&eventType) != nil {
					break
				}
				events = append(events, eventType)
			}
			_ = rows.Close()
		}
		t.Fatalf("process index worker did not publish: last_status=%q last_revision=%d persisted_status=%q persisted_revision=%d lease_present=%t outcome_present=%t execution_events=%q scoped_diagnostics={%s}", last.Status, last.Revision, status, persistedRevision, leasePresent, outcomePresent, strings.Join(events, ","), indexWorkerTimeoutDiagnostic(ctx, db, id))
		return knowledge.IndexTaskDetail{}
	}
	full := wait(receipt.RunID, 1)
	if f.calls.Load() != 1 || full.Result.EmbeddedChunks != 1 {
		t.Fatal("full index not executed once", f.calls.Load())
	}
	var replay knowledge.IndexTaskReceipt
	invoke("POST", "indexes/docs/tasks", request, 202, &replay)
	if !replay.Replayed || replay.RunID != receipt.RunID || f.calls.Load() != 1 {
		t.Fatal("process admission replay sent model")
	}
	change["expected_source_revision"] = 1
	change["expected_document_version"] = 1
	change["idempotency_key"] = "process-source-incremental"
	change["body"] = "Owned documentation updated: versions and source fences keep index publication consistent."
	invoke("PUT", "sources/docs/documents/guide", change, 200, nil)
	request.Mode = "incremental"
	request.IdempotencyKey = "process-index-incremental"
	invoke("POST", "indexes/docs/tasks", request, 202, &receipt)
	incremental := wait(receipt.RunID, 2)
	if incremental.Mode != "incremental" || f.calls.Load() != 2 {
		t.Fatal("process incremental execution not once", f.calls.Load())
	}
	used, err := usagecost.NewSQLStore(db).GetSnapshot(ctx, usagecost.Scope{TenantID: f.scope.TenantID, DepartmentID: f.scope.DepartmentID, ApplicationID: f.scope.ApplicationID, AgentID: f.scope.AgentID, AgentVersionID: f.scope.AgentVersionID, RunID: receipt.RunID})
	if err != nil || used.InputTokens != 100 || used.UsedMicros != 10000 {
		t.Fatal("process index usage settlement", err, used.InputTokens, used.UsedMicros)
	}
	// Intent/query cannot be used to discover a different collection's run.
	invoke("GET", "indexes/foreign/tasks/"+receipt.RunID, nil, 404, nil)
}
