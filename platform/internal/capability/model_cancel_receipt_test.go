package capability

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"github.com/lexagent/platform/internal/modelcapacity"
	"github.com/lexagent/platform/internal/modelgateway"
	"github.com/lexagent/platform/internal/policyasset"
	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

type cancellationReceiptGateway struct {
	captureModelGateway
	cancel context.CancelFunc
	t      *testing.T
}

type cancellationAwareCapacity struct {
	captureModelCapacity
	t *testing.T
}

func (p *cancellationAwareCapacity) ReleaseCapacity(ctx context.Context, lease modelcapacity.Lease) error {
	if ctx.Err() != nil {
		p.t.Fatal("known capacity cleanup inherited caller cancellation")
	}
	deadline, ok := ctx.Deadline()
	if !ok || time.Until(deadline) <= 0 || time.Until(deadline) > 2*time.Second {
		p.t.Fatal("capacity cleanup is not separately bounded")
	}
	return p.captureModelCapacity.ReleaseCapacity(ctx, lease)
}

func (g *cancellationReceiptGateway) Generate(ctx context.Context, scope sharedkernel.Scope, policy policyasset.Snapshot, request modelgateway.GenerateRequest) (modelgateway.GenerateResult, error) {
	g.cancel()
	if ctx.Err() != nil {
		g.t.Fatal("caller cancellation discarded an already submitted provider receipt")
	}
	deadline, ok := ctx.Deadline()
	if !ok || time.Until(deadline) > time.Minute || time.Until(deadline) <= 0 {
		g.t.Fatal("provider receipt collection must remain bounded by persisted send cutoff")
	}
	return g.captureModelGateway.Generate(ctx, scope, policy, request)
}
func TestCallerCancellationCollectsOneKnownModelReceiptWithoutDisclosure(t *testing.T) {
	capacity := &cancellationAwareCapacity{t: t}
	runCallerCancellationKnownReceipt(t, capacity, fixedModelAccess())
	if len(capacity.released) != 1 {
		t.Fatal("original capacity not released once")
	}
}

func runCallerCancellationKnownReceipt(t *testing.T, capacity modelcapacity.CapacityProvider, access modelAccessResolverFunc) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m := NewModuleWithKnowledgeAndPolicies("internal-token", "signing-secret", nil, "platform", "agent-runtime", nil, governedInvocationResolver())
	budgets := &captureModelBudgetStore{}
	gateway := &cancellationReceiptGateway{captureModelGateway: captureModelGateway{result: modelgateway.GenerateResult{Text: "private billable answer", InputTokens: 12, OutputTokens: 4}}, cancel: cancel, t: t}
	m.SetGovernedModelInvocation(access, gateway)
	m.SetModelBilling(testApprovedPriceResolver(), budgets)
	m.SetModelCapacity(capacity)
	input, _ := json.Marshal(map[string]any{"idempotency_key": "cancel-receipt", "prompt_template_hash": "prompt-hash", "messages": []map[string]string{{"role": "user", "content": "hello"}}})
	body, _ := json.Marshal(envelope{Context: capabilityContext(), Input: input})
	req := httptest.NewRequest(http.MethodPost, "/internal/model/generate", bytes.NewReader(body)).WithContext(ctx)
	mac := hmac.New(sha256.New, []byte(m.signingSecret))
	mac.Write(requestSignaturePayload(http.MethodPost, req.URL.Path, body))
	req.Header.Set("X-Internal-Token", m.internalToken)
	req.Header.Set("X-Context-Signature", fmt.Sprintf("sha256=%x", mac.Sum(nil)))
	req.Header.Set("X-Platform-Context", "Bearer "+capabilityContext().PlatformContextToken)
	w := httptest.NewRecorder()
	m.Handler().ServeHTTP(w, req)
	if strings.Contains(w.Body.String(), "private billable answer") || w.Code == http.StatusOK {
		t.Fatal("cancelled caller received provider answer")
	}
	m.reconcileBilling(context.Background())
	m.reconcileBilling(context.Background())
	store := m.modelStore.(*memoryModelInvocationStore)
	record := store.records[capabilityScopeHash(capabilityContext())+"\x00cancel-receipt"]
	if gateway.calls != 1 || record.Status != "completed" || len(budgets.settled) != 1 || record.Response["text"] != "private billable answer" {
		t.Fatalf("known receipt not settled exactly once: calls=%d status=%s settled=%d", gateway.calls, record.Status, len(budgets.settled))
	}
}

func TestSQLCancelledCallerReleasesKnownCapacityWithoutWaitingForTTL(t *testing.T) {
	dsn := os.Getenv("PUBLIC_TEST_POSTGRES_MIGRATION_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL fixture not configured")
	}
	ctx, stop := context.WithTimeout(context.Background(), 30*time.Second)
	defer stop()
	db, err := sqlutil.OpenPostgres(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	capacity := modelcapacity.NewSQLProvider(db)
	if err = capacity.EnsureSchema(ctx); err != nil {
		t.Fatal(err)
	}
	h := capabilityContext()
	scope := scopeFromHarness(h)
	id := fmt.Sprintf("cancel-native-%d", time.Now().UnixNano())
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if err = modelcapacity.RegisterPoolTx(tx, modelcapacity.Deployment{ID: id, TenantID: scope.TenantID, DepartmentID: scope.DepartmentID, ApplicationID: scope.ApplicationID, ModelVersionID: "version-a", CapacityUnits: 1}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err = modelcapacity.UpdatePoolStateTx(tx, scope, id, "ready", "ready", time.Now()); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	base := fixedModelAccess()
	access := modelAccessResolverFunc(func(c context.Context, s sharedkernel.Scope, v string) (modelgateway.Selection, error) {
		r, e := base(c, s, v)
		r.DeploymentID = id
		r.CapacityUnits = 1
		return r, e
	})
	runCallerCancellationKnownReceipt(t, capacity, access)
	var reserved, active, released int
	if err = db.QueryRowContext(ctx, sqlutil.Bind(`SELECT reserved_units FROM platform_model_capacity_pool WHERE deployment_id=?`), id).Scan(&reserved); err != nil {
		t.Fatal(err)
	}
	if err = db.QueryRowContext(ctx, sqlutil.Bind(`SELECT count(*) FILTER(WHERE status='active'),count(*) FILTER(WHERE status='released') FROM platform_model_capacity_lease WHERE deployment_id=?`), id).Scan(&active, &released); err != nil {
		t.Fatal(err)
	}
	if reserved != 0 || active != 0 || released != 1 {
		t.Fatal("known ended call still holds native capacity", reserved, active, released)
	}
	next, err := capacity.AcquireCapacity(ctx, modelcapacity.Request{Scope: scope, DeploymentID: id, Units: 1, Owner: h.ActorID, RequestID: "next-after-cancel", TTL: time.Minute})
	if err != nil {
		t.Fatal("next serial request blocked by stale lease", err)
	}
	if err = capacity.ReleaseCapacity(ctx, next); err != nil {
		t.Fatal(err)
	}
}
