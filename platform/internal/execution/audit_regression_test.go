package execution

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/agentgateway"
	"github.com/lexagent/platform/internal/contract"
	"github.com/lexagent/platform/internal/conversation"
	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sharedkernel"
)

// A queued Run can outlive its admission token, but dispatch must mint a new
// short-lived command after the current authorization check.
// 排队可超过入口令牌 TTL；投递必须在重验授权后签发当前命令，不能复用旧令牌。
func TestQueuedRunPastOriginalTTLUsesFreshSignedToken(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	scope := testScope("queued-over-token-ttl")
	request := contract.ExecuteRequest{}
	if err := json.Unmarshal(gatewayRequest(t, scope, "run"), &request); err != nil {
		t.Fatal(err)
	}
	start := time.Now().UTC().Truncate(time.Second)
	signer := conversation.Ed25519ContextTokenSigner{PrivateKey: private, Issuer: "platform", Audience: "agent-runtime", TTL: 2 * time.Minute, Clock: func() time.Time { return start }}
	request.ContextToken = ""
	oldToken, err := signer.Sign(context.Background(), scope.domain(), request)
	if err != nil {
		t.Fatal(err)
	}
	request.ContextToken = oldToken
	stored, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	store := platformruntime.NewStore()
	created, err := store.Create(platformruntime.CreateRequest{ID: scope.RunID, Scope: scope.domain(), AgentVersionID: "v1", IdempotencyKey: "queued-ttl", Fingerprint: "fp", RequestJSON: stored, AgentEndpoint: "http://agent.example"})
	if err != nil {
		t.Fatal(err)
	}
	signer.Clock = func() time.Time { return start.Add(3 * time.Minute) }
	gateway := &dispatcherGatewayStub{}
	d := NewDispatcherWithGateway(store, "secret", gateway, 1)
	d.SetSecurity(signer, func(context.Context, sharedkernel.Scope) error { return nil })
	if err := d.dispatch(context.Background(), created.Run); err != nil {
		t.Fatal(err)
	}
	if !gateway.invoked || gateway.token == oldToken {
		t.Fatal("queued Run replayed expired admission token")
	}
	claims := func(token string) map[string]any {
		t.Helper()
		parts := strings.Split(token, ".")
		if len(parts) != 3 {
			t.Fatal("invalid signed token shape")
		}
		raw, err := base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			t.Fatal(err)
		}
		var value map[string]any
		if err := json.Unmarshal(raw, &value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	oldClaims, freshClaims := claims(oldToken), claims(gateway.token)
	if oldClaims["exp"].(float64) >= float64(start.Add(3*time.Minute).Unix()) || freshClaims["iat"].(float64) != float64(start.Add(3*time.Minute).Unix()) || freshClaims["exp"].(float64) <= oldClaims["exp"].(float64) {
		t.Fatalf("dispatch did not renew bounded execution token: old=%v fresh=%v", oldClaims["exp"], freshClaims["exp"])
	}
}

type auditStatusGateway struct{ status string }

func (g auditStatusGateway) Invoke(_ context.Context, _ agentgateway.Target, r contract.ExecuteRequest) (contract.ExecuteResponse, error) {
	return contract.ExecuteResponse{ProtocolVersion: contract.ProtocolVersion, RunID: r.Scope.RunID, Status: g.status}, nil
}

// 旧令牌只用于持久化审计，投递重验授权并签发新命令；dispatch reauthorizes before signing.
func TestAuditDispatchReauthorizesAndNeverUsesPersistedToken(t *testing.T) {
	for _, denied := range []bool{false, true} {
		store := platformruntime.NewStore()
		scope := testScope("renew-audit")
		created, err := store.Create(platformruntime.CreateRequest{ID: scope.RunID, Scope: scope.domain(), AgentVersionID: "v1", IdempotencyKey: "renew-audit-idem", Fingerprint: "fp", RequestJSON: gatewayRequest(t, scope, "run"), AgentEndpoint: "http://agent.example"})
		if err != nil {
			t.Fatal(err)
		}
		gateway := &dispatcherGatewayStub{}
		d := NewDispatcherWithGateway(store, "secret", gateway, 1)
		signed := false
		d.SetSecurity(machineRunContextSignerFunc(func(_ context.Context, s sharedkernel.Scope, r contract.ExecuteRequest) (string, error) {
			if r.ContextToken != "" || s.RunID != scope.RunID {
				t.Fatal("signer received persisted bearer or wrong scope")
			}
			signed = true
			return "new-short-lived-context-token-00000000000000000000", nil
		}), func(context.Context, sharedkernel.Scope) error {
			if denied {
				return errors.New("revoked")
			}
			return nil
		})
		if err := d.dispatch(context.Background(), created.Run); err != nil {
			t.Fatal(err)
		}
		if denied && (signed || gateway.invoked || gateway.resumed) {
			t.Fatal("revoked grant caused signing or execution")
		}
		if !denied && (!signed || !gateway.invoked) {
			t.Fatal("dispatch did not sign current authorized command")
		}
	}
}

// 禁止窃取其他调度器尚未过期的租约；persisted tokens are not transferable ownership.
func TestAuditDispatcherCannotUseAnotherOwnersLease(t *testing.T) {
	store := platformruntime.NewStore()
	scope := testScope("foreign-owner")
	created, err := store.Create(platformruntime.CreateRequest{ID: scope.RunID, Scope: scope.domain(), AgentVersionID: "v1", IdempotencyKey: "foreign-owner-idem", Fingerprint: "fp", RequestJSON: gatewayRequest(t, scope, "run"), AgentEndpoint: "http://agent.example"})
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := store.AcquireLease(created.Run.ID, "other-dispatcher-private-token", time.Now(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	running, err := store.Transition(claimed.ID, platformruntime.StatusAccepted, platformruntime.StatusRunning, claimed.Revision)
	if err != nil {
		t.Fatal(err)
	}
	gateway := &dispatcherGatewayStub{}
	err = NewDispatcherWithGateway(store, "secret", gateway, 1).dispatch(context.Background(), running)
	if !errors.Is(err, platformruntime.ErrLeaseConflict) {
		t.Fatalf("expected lease conflict, got %v", err)
	}
	if gateway.invoked || gateway.resumed {
		t.Fatal("foreign owner dispatched a side effect")
	}
}

type boundedAuditGateway struct {
	active  atomic.Int32
	peak    atomic.Int32
	started chan string
	release chan struct{}
}

func (g *boundedAuditGateway) Invoke(ctx context.Context, _ agentgateway.Target, r contract.ExecuteRequest) (contract.ExecuteResponse, error) {
	n := g.active.Add(1)
	defer g.active.Add(-1)
	for old := g.peak.Load(); n > old; old = g.peak.Load() {
		if g.peak.CompareAndSwap(old, n) {
			break
		}
	}
	g.started <- r.Scope.RunID
	select {
	case <-ctx.Done():
		return contract.ExecuteResponse{}, ctx.Err()
	case <-g.release:
	}
	return contract.ExecuteResponse{ProtocolVersion: contract.ProtocolVersion, RunID: r.Scope.RunID, Status: "succeeded"}, nil
}
func (g *boundedAuditGateway) Resume(ctx context.Context, target agentgateway.Target, r contract.ExecuteRequest) (contract.ExecuteResponse, error) {
	return g.Invoke(ctx, target, r)
}

// 两个 Worker 必须同时工作且不能超过配置上限；workers must be real, bounded executors.
func TestAuditDispatcherUsesBoundedWorkerPool(t *testing.T) {
	for _, separateUsers := range []bool{false, true} {
		name := "independent-sessions"
		if separateUsers {
			name = "different-users-same-instance-and-session-label"
		}
		t.Run(name, func(t *testing.T) { exerciseBoundedWorkerPool(t, separateUsers) })
	}
}

func exerciseBoundedWorkerPool(t *testing.T, separateUsers bool) {
	store := platformruntime.NewStore()
	gateway := &boundedAuditGateway{started: make(chan string, 4), release: make(chan struct{})}
	d := NewDispatcherWithGateway(store, "secret", gateway, 2)
	for _, id := range []string{"pool-1", "pool-2", "pool-3"} {
		scope := testScope(id)
		// Worker concurrency is across independent sessions, never one checkpoint.
		// 执行池并发针对独立会话，同一 Checkpoint 必须顺序执行。
		scope.SessionID = id + "-session"
		if separateUsers {
			// Keep every instance dimension and the session label identical:
			// the authenticated principal must separate the execution lanes.
			scope.PrincipalID = "pool-user-" + id
			scope.SessionID = "same-session-label"
		}
		created, err := store.Create(platformruntime.CreateRequest{ID: id, Scope: scope.domain(), AgentVersionID: "v1", IdempotencyKey: id + "-idempotency", Fingerprint: "fp", RequestJSON: gatewayRequest(t, scope, "run"), AgentEndpoint: "http://agent.example"})
		if err != nil {
			t.Fatal(err)
		}
		d.Enqueue(created.Run)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d.Start(ctx)
	d.Start(ctx) // 重复启动不能新增执行池；repeat Start is idempotent.
	defer func() {
		close(gateway.release)
		cancel()
		select {
		case <-d.stopped:
		case <-time.After(time.Second):
			t.Error("workers did not stop")
		}
	}()
	for i := 0; i < 2; i++ {
		select {
		case <-gateway.started:
		case <-time.After(time.Second):
			t.Fatal("workers did not execute concurrently")
		}
	}
	select {
	case <-gateway.started:
		t.Fatal("worker limit exceeded")
	case <-time.After(250 * time.Millisecond):
	}
	if gateway.peak.Load() != 2 {
		t.Fatalf("peak=%d", gateway.peak.Load())
	}
}

type mixedLatencyAuditGateway struct {
	active      atomic.Int32
	peak        atomic.Int32
	slowStarted chan string
	fastDone    chan struct{}
	releaseSlow chan struct{}
}

func (g *mixedLatencyAuditGateway) Invoke(ctx context.Context, _ agentgateway.Target, request contract.ExecuteRequest) (contract.ExecuteResponse, error) {
	active := g.active.Add(1)
	defer g.active.Add(-1)
	for previous := g.peak.Load(); active > previous; previous = g.peak.Load() {
		if g.peak.CompareAndSwap(previous, active) {
			break
		}
	}
	if strings.HasPrefix(request.Scope.RunID, "slow-") {
		g.slowStarted <- request.Scope.RunID
		select {
		case <-ctx.Done():
			return contract.ExecuteResponse{}, ctx.Err()
		case <-g.releaseSlow:
		}
	} else {
		g.fastDone <- struct{}{}
	}
	return contract.ExecuteResponse{ProtocolVersion: contract.ProtocolVersion, RunID: request.Scope.RunID, Status: "succeeded"}, nil
}

func (g *mixedLatencyAuditGateway) Resume(ctx context.Context, target agentgateway.Target, request contract.ExecuteRequest) (contract.ExecuteResponse, error) {
	return g.Invoke(ctx, target, request)
}

// Three long validation Runs cannot starve a short QA Run when four Workers
// are configured. Shutdown must cancel the blocked calls and wait for them.
// 配置四个 Worker 时，三个慢任务不能饿死短任务；关闭须取消并等待阻塞调用。
func TestAuditFourWorkersServeShortQAAndCloseBlockedRuns(t *testing.T) {
	store := platformruntime.NewStore()
	gateway := &mixedLatencyAuditGateway{
		slowStarted: make(chan string, 3), fastDone: make(chan struct{}, 1), releaseSlow: make(chan struct{}),
	}
	dispatcher := NewDispatcherWithGateway(store, "secret", gateway, 4)
	for _, id := range []string{"slow-validation-1", "slow-validation-2", "slow-validation-3"} {
		scope := testScope(id)
		scope.SessionID = id + "-session"
		created, err := store.Create(platformruntime.CreateRequest{
			ID: id, Scope: scope.domain(), AgentVersionID: "v1", IdempotencyKey: id + "-idem",
			Fingerprint: "fp", RequestJSON: gatewayRequest(t, scope, "run"), AgentEndpoint: "http://agent.example",
		})
		if err != nil {
			t.Fatal(err)
		}
		dispatcher.Enqueue(created.Run)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dispatcher.Start(ctx)
	defer close(gateway.releaseSlow)
	for i := 0; i < 3; i++ {
		select {
		case <-gateway.slowStarted:
		case <-time.After(2 * time.Second):
			t.Fatal("slow validation Runs did not occupy three Workers")
		}
	}
	shortScope := testScope("short-qa")
	shortScope.SessionID = "short-qa-session"
	short, err := store.Create(platformruntime.CreateRequest{
		ID: "short-qa", Scope: shortScope.domain(), AgentVersionID: "v1", IdempotencyKey: "short-qa-idem",
		Fingerprint: "fp", RequestJSON: gatewayRequest(t, shortScope, "run"), AgentEndpoint: "http://agent.example",
	})
	if err != nil {
		t.Fatal(err)
	}
	dispatcher.Enqueue(short.Run)
	select {
	case <-gateway.fastDone:
	case <-time.After(2 * time.Second):
		t.Fatal("short QA was starved by slow validation Runs")
	}
	if peak := gateway.peak.Load(); peak != 4 {
		t.Fatalf("configured four-worker limit was not exercised: peak=%d", peak)
	}
	shutdownCtx, stop := context.WithTimeout(context.Background(), 2*time.Second)
	defer stop()
	if err := dispatcher.Close(shutdownCtx); err != nil {
		t.Fatalf("blocked calls did not cancel on close: %v", err)
	}
}
func (g auditStatusGateway) Resume(ctx context.Context, target agentgateway.Target, r contract.ExecuteRequest) (contract.ExecuteResponse, error) {
	return g.Invoke(ctx, target, r)
}

// 非终态不得被同步投递路径标为成功；only terminal success can complete a Run.
func TestAuditNonterminalAgentResponseCannotSucceed(t *testing.T) {
	for _, status := range []string{"accepted", "running", ""} {
		t.Run(status, func(t *testing.T) {
			scope := testScope("nonterminal-" + status)
			store := platformruntime.NewStore()
			created, err := store.Create(platformruntime.CreateRequest{ID: scope.RunID, Scope: scope.domain(), AgentVersionID: "v1", IdempotencyKey: "nonterminal-idem", Fingerprint: "fingerprint", RequestJSON: gatewayRequest(t, scope, "run"), AgentEndpoint: "http://agent.example"})
			if err != nil {
				t.Fatal(err)
			}
			err = NewDispatcherWithGateway(store, "secret", auditStatusGateway{status}, 1).dispatch(context.Background(), created.Run)
			if err != nil {
				t.Fatal(err)
			}
			final, err := store.Get(created.Run.ID)
			if err != nil || final.Status != platformruntime.StatusCancelling {
				t.Fatalf("final=%+v err=%v", final, err)
			}
			events, eventErr := store.Events(created.Run.ID, 0)
			if eventErr != nil || len(events) == 0 || events[len(events)-1].Type != "cancel_requested" || events[len(events)-1].Payload["code"] != "AGENT_CONTRACT_INVALID" {
				t.Fatal("invalid sync response lost protocol error or fabricated stop")
			}
		})
	}
}

// 恢复命令必须从数据库读取；stale queued snapshots cannot change the execution phase.
func TestAuditStaleAcceptedSnapshotDispatchesLatestResume(t *testing.T) {
	scope := testScope("stale-resume")
	store := platformruntime.NewStore()
	created, err := store.Create(platformruntime.CreateRequest{ID: scope.RunID, Scope: scope.domain(), AgentVersionID: "v1", IdempotencyKey: "stale-resume-idem", Fingerprint: "fingerprint", RequestJSON: gatewayRequest(t, scope, "run"), AgentEndpoint: "http://agent.example"})
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := store.AcquireLease(created.Run.ID, "owner", time.Now(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	running, err := store.Transition(claimed.ID, platformruntime.StatusAccepted, platformruntime.StatusRunning, claimed.Revision)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.Transition(running.ID, platformruntime.StatusRunning, platformruntime.StatusWaiting, running.Revision); err != nil {
		t.Fatal(err)
	}
	if _, err = store.PrepareResume(running.ID, []byte(`{"approved":true}`)); err != nil {
		t.Fatal(err)
	}
	stub := &dispatcherGatewayStub{}
	if err = NewDispatcherWithGateway(store, "secret", stub, 1).dispatch(context.Background(), created.Run); err != nil {
		t.Fatal(err)
	}
	if stub.invoked || !stub.resumed {
		t.Fatalf("invoke=%v resume=%v", stub.invoked, stub.resumed)
	}
}
