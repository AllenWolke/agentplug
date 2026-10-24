//go:build linux

package capability

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/sqlutil"
)

// A whole process is stopped, not one sleeping goroutine. Only the registered
// PostgreSQL fixture is used; no Agent service, provider or host is paused.
func TestSQLToolStoppedProcessCannotSubmitAfterTakeover(t *testing.T) {
	dsn := os.Getenv("PUBLIC_TEST_POSTGRES_MIGRATION_DSN")
	if dsn == "" {
		t.Skip("owned PostgreSQL fixture required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	db, err := sqlutil.OpenPostgres(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store, _ := NewSQLToolInvocationStore(db)
	if err := store.EnsureSchema(ctx); err != nil {
		t.Fatal(err)
	}
	scope, call, fingerprint := strings.Repeat("8", 64), fmt.Sprintf("process-pause-%d", time.Now().UnixNano()), strings.Repeat("9", 64)
	first, _, err := store.AcquireTool(ctx, scope, call, fingerprint, "paused-worker", 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	lease, _ := json.Marshal(first.Lease)
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	child := exec.CommandContext(ctx, binary, "-test.run=^TestSQLToolPauseWorkerProcessHelper$", "-test.timeout=25s")
	child.Env = append(os.Environ(), "AGENTPLUG_PAUSE_HELPER=1", "AGENTPLUG_PAUSE_LEASE="+string(lease))
	out, err := child.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	input, err := child.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr strings.Builder
	child.Stderr = &stderr
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	waited := false
	defer func() {
		_ = child.Process.Signal(syscall.SIGCONT)
		_ = child.Process.Kill()
		if !waited {
			_ = child.Wait()
		}
	}()
	ready := make(chan struct{}, 1)
	go func() {
		scanner := bufio.NewScanner(out)
		for scanner.Scan() {
			if scanner.Text() == "PAUSE_READY" {
				select {
				case ready <- struct{}{}:
				default:
				}
			}
		}
	}()
	select {
	case <-ready:
	case <-ctx.Done():
		t.Fatal("worker startup exceeded global bound")
	}
	if err := child.Process.Signal(syscall.SIGSTOP); err != nil {
		t.Fatal(err)
	}
	// Verify the OS actually stopped the process before waiting on DB time.
	stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", child.Process.Pid))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(stat), "T (stopped)") {
		deadline := time.NewTimer(time.Second)
		defer deadline.Stop()
		for !strings.Contains(string(stat), "T (stopped)") {
			select {
			case <-deadline.C:
				t.Fatal("SIGSTOP not observed in /proc")
			case <-time.After(10 * time.Millisecond):
			}
			stat, err = os.ReadFile(fmt.Sprintf("/proc/%d/status", child.Process.Pid))
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	for {
		var expired bool
		if err := db.QueryRowContext(ctx, sqlutil.Bind(`SELECT lease_until<=clock_timestamp() FROM platform_tool_invocation WHERE scope_hash=? AND call_id=?`), scope, call).Scan(&expired); err != nil {
			t.Fatal(err)
		}
		if expired {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("lease expiry exceeded global bound")
		case <-time.After(25 * time.Millisecond):
		}
	}
	second, _, err := store.AcquireTool(ctx, scope, call, fingerprint, "replacement-worker", time.Minute)
	if err != nil || second.Lease.Fence != first.Lease.Fence+1 {
		t.Fatal("replacement did not acquire a new generation", err)
	}
	if err := store.BeginTool(ctx, second.Lease); err != nil {
		t.Fatal(err)
	}
	if err := store.FinishTool(ctx, second.Lease, map[string]any{"winner": "replacement"}); err != nil {
		t.Fatal(err)
	}
	if err := child.Process.Signal(syscall.SIGCONT); err != nil {
		t.Fatal(err)
	}
	if _, err := input.Write([]byte{1}); err != nil {
		t.Fatal(err)
	}
	_ = input.Close()
	err = child.Wait()
	waited = true
	if err != nil {
		t.Fatal("resumed stale process violated fence", err, stderr.String())
	}
	saved, found, err := store.LookupToolInvocation(ctx, scope, call)
	if err != nil || !found || saved.Status != "completed" || saved.Result["winner"] != "replacement" {
		t.Fatal("old worker changed replacement result", err)
	}
	t.Log("SIGSTOP observed; SIGCONT stale begin/finish/reject/unknown/renew rejected; replacement receipt unchanged")
}

func TestSQLToolPauseWorkerProcessHelper(t *testing.T) {
	if os.Getenv("AGENTPLUG_PAUSE_HELPER") != "1" {
		t.Skip("subprocess-only helper")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	db, err := sqlutil.OpenPostgres(ctx, os.Getenv("PUBLIC_TEST_POSTGRES_MIGRATION_DSN"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store, _ := NewSQLToolInvocationStore(db)
	var lease ToolExecutionLease
	if json.Unmarshal([]byte(os.Getenv("AGENTPLUG_PAUSE_LEASE")), &lease) != nil || lease.Token == "" {
		t.Fatal("missing owned lease")
	}
	fmt.Fprintln(os.Stdout, "PAUSE_READY")
	if _, err := io.ReadFull(os.Stdin, make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
	for _, err := range []error{store.BeginTool(ctx, lease), store.FinishTool(ctx, lease, map[string]any{"winner": "stale"}), store.RejectTool(ctx, lease), store.UnknownTool(ctx, lease)} {
		if !errors.Is(err, ErrToolInvocationConflict) {
			t.Fatal("old process changed the new generation", err)
		}
	}
	if _, err := store.RenewTool(ctx, lease, time.Minute); !errors.Is(err, ErrToolInvocationConflict) {
		t.Fatal("old process renewed", err)
	}
}
