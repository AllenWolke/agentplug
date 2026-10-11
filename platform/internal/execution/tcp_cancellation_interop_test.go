package execution

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/agentgateway"
	"github.com/lexagent/platform/internal/contract"
	"github.com/lexagent/platform/internal/conversation"
	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sharedkernel"
)

// Opt in because this cross-process test requires installed FastAPI/Uvicorn.
// 显式开启跨进程测试；缺 Python 依赖时的 skip 不得计验收通过。
func TestRealSignedTCPTimeoutWaitsForPythonGraphStop(t *testing.T) {
	if os.Getenv("SDK_TCP_INTEROP_TEST") != "1" {
		t.Skip("real Python TCP fixture not enabled")
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	root, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "python", filepath.Join(root, "sdk/python/tests/tcp_cancel_interop_server.py"))
	command.Env = []string{"PATH=" + os.Getenv("PATH"), "SYSTEMROOT=" + os.Getenv("SYSTEMROOT"), "WINDIR=" + os.Getenv("WINDIR"), "TEMP=" + os.Getenv("TEMP"), "PYTHONPATH=" + filepath.Join(root, "sdk/python"), "FIXTURE_PUBLIC_KEY=" + base64.StdEncoding.EncodeToString(public)}
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	command.Stderr = io.Discard
	if err = command.Start(); err != nil {
		t.Fatal("start disposable Python fixture failed")
	}
	defer func() { _ = command.Process.Kill(); _ = command.Wait() }()
	scanner := bufio.NewScanner(stdout)
	if !scanner.Scan() {
		t.Fatal("fixture did not publish address")
	}
	var address struct {
		URL string `json:"url"`
	}
	if json.Unmarshal(scanner.Bytes(), &address) != nil || address.URL == "" {
		t.Fatal("invalid fixture address")
	}
	client := &http.Client{Timeout: time.Second}
	ready := false
	for i := 0; i < 60; i++ {
		response, err := client.Get(address.URL + "/health/live")
		if err == nil {
			_ = response.Body.Close()
			ready = response.StatusCode == 200
		}
		if ready {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if !ready {
		t.Fatal("fixture not ready")
	}
	store := platformruntime.NewStore()
	scope := testScope("real-tcp-stop")
	var request contract.ExecuteRequest
	if err = json.Unmarshal(gatewayRequest(t, scope, "invoke"), &request); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(request)
	created, err := store.Create(platformruntime.CreateRequest{ID: scope.RunID, Scope: scope.domain(), AgentVersionID: "v1", IdempotencyKey: "tcp-stop-idem", Fingerprint: "fixture", RequestJSON: raw, AgentEndpoint: address.URL})
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := store.AcquireLease(created.Run.ID, "tcp-owner", time.Now().UTC(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	running, err := store.TransitionLeased(created.Run.ID, platformruntime.StatusAccepted, platformruntime.StatusRunning, claimed.Revision, claimed.LeaseToken)
	if err != nil {
		t.Fatal(err)
	}
	gateway := agentgateway.RemoteAdapter{Transport: agentgateway.NewHTTPTransport(&http.Client{})}
	dispatcher := NewDispatcherWithGateway(store, "", gateway, 1)
	dispatcher.SetSecurity(conversation.Ed25519ContextTokenSigner{PrivateKey: private, Issuer: "platform", Audience: "agent-runtime", TTL: time.Minute}, func(context.Context, sharedkernel.Scope) error { return nil })
	if err = dispatcher.dispatchThroughGateway(ctx, created.Run, running, dispatchPolicy{MaxAttempts: 3, Timeout: 100 * time.Millisecond, Lease: time.Minute}); err != nil {
		t.Fatal(err)
	}
	readState := func() map[string]int {
		t.Helper()
		response, err := client.Get(address.URL + "/fixture/state")
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		result := map[string]int{}
		if json.NewDecoder(response.Body).Decode(&result) != nil {
			t.Fatal("invalid fixture state")
		}
		return result
	}
	observed := readState()
	pending, err := store.Get(created.Run.ID)
	if err != nil || pending.Status != platformruntime.StatusCancelling || observed["started"] != 1 || observed["stopped"] != 0 || observed["effects"] != 0 {
		t.Fatal("TCP timeout falsely finalized or repeated remote graph")
	}
	nextScope := scope.domain()
	nextScope.RunID = "real-tcp-next"
	next, err := store.Create(platformruntime.CreateRequest{ID: nextScope.RunID, Scope: nextScope, AgentVersionID: "v1", IdempotencyKey: "tcp-next", Fingerprint: "fixture"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.AcquireLease(next.Run.ID, "next", time.Now().UTC().Add(time.Hour), time.Minute); !errors.Is(err, platformruntime.ErrLeaseConflict) {
		t.Fatal("live Python graph lost session reservation")
	}
	response, err := client.Post(address.URL+"/fixture/release", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	for i := 0; i < 60; i++ {
		if readState()["stopped"] == 1 {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	dispatcher.reconcileCancellations(ctx)
	final, err := store.Get(created.Run.ID)
	observed = readState()
	if err != nil || final.Status != platformruntime.StatusCancelled || observed["started"] != 1 || observed["stopped"] != 1 || observed["controls"] < 1 || observed["effects"] != 0 {
		t.Fatal("signed TCP stop not confirmed")
	}
	if _, err = store.AcquireLease(next.Run.ID, "next", time.Now().UTC(), time.Minute); err != nil {
		t.Fatal("stop confirmation failed to release session")
	}
	// A second slow graph loses its process while cancellation is pending.
	// Its replacement lost the in-memory execution registry. It must not claim
	// that an unknown generation stopped: trusted controller evidence is required.
	// 重启实例不能证明旧世代退出，保持待取消，不重跑业务或释放租约。
	response, err = client.Post(address.URL+"/fixture/reset", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	restartScope := testScope("real-tcp-restart")
	restartScope.SessionID = "restart-session"
	var restartRequest contract.ExecuteRequest
	if err = json.Unmarshal(gatewayRequest(t, restartScope, "invoke"), &restartRequest); err != nil {
		t.Fatal(err)
	}
	restartRaw, _ := json.Marshal(restartRequest)
	restartCreated, err := store.Create(platformruntime.CreateRequest{ID: restartScope.RunID, Scope: restartScope.domain(), AgentVersionID: "v1", IdempotencyKey: "tcp-restart-idem", Fingerprint: "fixture", RequestJSON: restartRaw, AgentEndpoint: address.URL})
	if err != nil {
		t.Fatal(err)
	}
	restartClaimed, err := store.AcquireLease(restartCreated.Run.ID, "restart-owner", time.Now().UTC(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	restartRunning, err := store.TransitionLeased(restartCreated.Run.ID, platformruntime.StatusAccepted, platformruntime.StatusRunning, restartClaimed.Revision, restartClaimed.LeaseToken)
	if err != nil {
		t.Fatal(err)
	}
	if err = dispatcher.dispatchThroughGateway(ctx, restartCreated.Run, restartRunning, dispatchPolicy{MaxAttempts: 3, Timeout: 100 * time.Millisecond, Lease: time.Minute}); err != nil {
		t.Fatal(err)
	}
	restartPending, err := store.Get(restartCreated.Run.ID)
	if err != nil || restartPending.Status != platformruntime.StatusCancelling || readState()["effects"] != 0 {
		t.Fatal("restart scenario did not retain cancellation intent")
	}
	if err = command.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = command.Wait()
	replacement := exec.CommandContext(ctx, "python", filepath.Join(root, "sdk/python/tests/tcp_cancel_interop_server.py"))
	replacement.Env = append(append([]string{}, command.Env...), "FIXTURE_PORT="+strings.TrimPrefix(address.URL, "http://127.0.0.1:"))
	replacementStdout, err := replacement.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	replacement.Stderr = io.Discard
	if err = replacement.Start(); err != nil {
		t.Fatal("restart disposable Python fixture failed")
	}
	defer func() { _ = replacement.Process.Kill(); _ = replacement.Wait() }()
	replacementScanner := bufio.NewScanner(replacementStdout)
	if !replacementScanner.Scan() {
		t.Fatal("restarted fixture did not publish address")
	}
	ready = false
	for i := 0; i < 80; i++ {
		probe, probeErr := client.Get(address.URL + "/health/live")
		if probeErr == nil {
			_ = probe.Body.Close()
			ready = probe.StatusCode == 200
		}
		if ready {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if !ready {
		t.Fatal("restarted fixture not ready")
	}
	if readState()["started"] != 0 {
		t.Fatal("restarted agent re-invoked cancelled graph")
	}
	dispatcher.reconcileCancellations(ctx)
	restartedFinal, err := store.Get(restartCreated.Run.ID)
	if err != nil || restartedFinal.Status != platformruntime.StatusCancelling || restartedFinal.LeaseToken == "" || readState()["controls"] != 0 || readState()["effects"] != 0 || readState()["started"] != 0 {
		t.Fatal("replacement falsely acknowledged the lost execution generation")
	}
}
