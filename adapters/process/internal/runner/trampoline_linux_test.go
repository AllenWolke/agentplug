//go:build linux

package runner

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	agentplatform "github.com/lexagent/agent-platform-sdk-go/agentplatform"
)

// limitsProbe reports the target's own RLIMIT_CPU and RLIMIT_NPROC. It reads
// /proc/self/limits because dash's ulimit does not implement -u.
// limitsProbe 自报目标的 RLIMIT_CPU 与 RLIMIT_NPROC：dash 的 ulimit 不支持 -u，
// 因此读取 /proc/self/limits。
const limitsProbe = `printf '{"cpu":"%s","processes":"%s"}' "$(grep '^Max cpu time' /proc/self/limits | tr -s ' ' | cut -d' ' -f4)" "$(grep '^Max processes' /proc/self/limits | tr -s ' ' | cut -d' ' -f4)"`

// TestTrampolineAppliesRegisteredLimits is the running evidence that the rlimit
// envelope actually reaches the target: the target reports its own RLIMIT_CPU
// and RLIMIT_NPROC through ulimit, which must equal the registered values.
// TestTrampolineAppliesRegisteredLimits 是「rlimit 信封确实到达目标」的运行证据：
// 目标用 ulimit 自报 RLIMIT_CPU 与 RLIMIT_NPROC，必须等于登记值。
func TestTrampolineAppliesRegisteredLimits(t *testing.T) {
	sandbox := registeredSandbox()
	sandbox.MaxCPUSeconds = 7
	sandbox.MaxProcesses = 23
	r := Runner{
		Binary:  "/bin/sh",
		Args:    []string{"-c", limitsProbe},
		Sandbox: sandbox,
		Self:    os.Args[0],
	}
	response, err := r.Invoke(context.Background(), request())
	if err != nil {
		t.Fatalf("Invoke() error = %v", err)
	}
	if got := response.Output["cpu"]; got != "7" {
		t.Fatalf("target RLIMIT_CPU = %v, want 7", got)
	}
	if got := response.Output["processes"]; got != "23" {
		t.Fatalf("target RLIMIT_NPROC = %v, want 23", got)
	}
}

// TestTrampolineRunsRegisteredCommandRoundTrip proves the normal path still
// works end to end through the trampoline: stdin payload in, JSON document out.
// TestTrampolineRunsRegisteredCommandRoundTrip 证明正常路径经跳板仍端到端可用：
// stdin 载荷进、JSON 文档出。
func TestTrampolineRunsRegisteredCommandRoundTrip(t *testing.T) {
	r := Runner{Binary: "/bin/cat", Sandbox: registeredSandbox(), Self: os.Args[0]}
	response, err := r.Invoke(context.Background(), request())
	if err != nil {
		t.Fatalf("Invoke() error = %v", err)
	}
	if response.Status != "succeeded" || response.Output["message"] != "hello" {
		t.Fatalf("unexpected response: %+v", response)
	}
}

// TestTrampolineEnforcesCPUTimeBudget proves a runaway target is killed by the
// kernel once its registered CPU budget is spent, long before the wall-clock
// timeout. / TestTrampolineEnforcesCPUTimeBudget 证明失控目标在 CPU 预算耗尽时被
// 内核终止，远早于墙钟超时。
func TestTrampolineEnforcesCPUTimeBudget(t *testing.T) {
	sandbox := registeredSandbox()
	sandbox.MaxCPUSeconds = 1
	sandbox.Timeout = 30 * time.Second
	r := Runner{Binary: "/bin/sh", Args: []string{"-c", "while :; do :; done"}, Sandbox: sandbox, Self: os.Args[0]}
	started := time.Now()
	_, err := r.Invoke(context.Background(), request())
	elapsed := time.Since(started)
	if !errors.Is(err, ErrProcessFailed) {
		t.Fatalf("runaway target was not bounded by the sandbox: err=%v", err)
	}
	if elapsed > 15*time.Second {
		t.Fatalf("runaway target consumed %s; the CPU budget was not enforced", elapsed)
	}
}

// TestTrampolineReportsOutputLimitBreach proves an unlimited target cannot flood
// the adapter: output past the registered bound is refused explicitly.
// TestTrampolineReportsOutputLimitBreach 证明失控目标无法淹没 Adapter：超出登记上限的
// 输出会被明确拒绝。
func TestTrampolineReportsOutputLimitBreach(t *testing.T) {
	sandbox := registeredSandbox()
	sandbox.MaxOutputBytes = 32
	r := Runner{Binary: "/bin/sh", Args: []string{"-c", "yes x | head -c 4096"}, Sandbox: sandbox, Self: os.Args[0]}
	_, err := r.Invoke(context.Background(), request())
	if !errors.Is(err, ErrOutputLimit) {
		t.Fatalf("expected ErrOutputLimit, got %v", err)
	}
}

func request() agentplatform.ExecuteRequest {
	return agentplatform.ExecuteRequest{
		ProtocolVersion: agentplatform.ProtocolVersion,
		Operation:       "invoke",
		Scope:           agentplatform.ScopeKey{RunID: "run-sandbox"},
		Input:           map[string]any{"message": "hello"},
	}
}
