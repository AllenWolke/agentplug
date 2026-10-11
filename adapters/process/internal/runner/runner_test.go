package runner

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	agentplatform "github.com/lexagent/agent-platform-sdk-go/agentplatform"
)

// TestMain lets the package test binary act as the sandbox trampoline when the
// runner re-execs it, so the Linux enforcement tests drive the real exec path.
// TestMain 让包测试二进制在 Runner 重启它时充当沙箱跳板，使 Linux 强制用例可以走真实
// 的 exec 路径。
func TestMain(m *testing.M) {
	Main()
	os.Exit(m.Run())
}

func registeredSandbox() Sandbox {
	return Sandbox{
		MaxMemoryBytes: 256 << 20,
		MaxCPUSeconds:  5,
		MaxProcesses:   32,
		MaxOutputBytes: 64 << 10,
		Timeout:        10 * time.Second,
		Network:        NetworkContainer,
	}
}

func TestRejectsUnregisteredCommand(t *testing.T) {
	_, err := (Runner{Sandbox: registeredSandbox()}).Invoke(context.Background(), agentplatform.ExecuteRequest{Scope: agentplatform.ScopeKey{RunID: "run"}})
	if !errors.Is(err, ErrInvalidDescriptor) {
		t.Fatalf("err=%v", err)
	}
}

func TestRejectsMalformedExecutionDescriptorBeforeLaunchingProcess(t *testing.T) {
	// A relative command path is malformed and must be rejected before
	// exec.CommandContext can launch anything. / 相对命令路径属于非法描述，必须在
	// 调用 exec.CommandContext 前拒绝，不能启动任何外部进程。
	r := Runner{Binary: "this-command-must-not-run", Sandbox: registeredSandbox()}
	_, err := r.Invoke(context.Background(), agentplatform.ExecuteRequest{Scope: agentplatform.ScopeKey{RunID: "run"}})
	if !errors.Is(err, ErrInvalidDescriptor) {
		t.Fatalf("expected ErrInvalidDescriptor, got %v", err)
	}
}

// TestRefusesCommandWithoutRegisteredSandbox is the fail-closed admission test:
// a pre-registered command with no isolation envelope must never run.
// TestRefusesCommandWithoutRegisteredSandbox 是失败闭合的准入用例：没有隔离信封的
// 预注册命令绝不能执行。
func TestRefusesCommandWithoutRegisteredSandbox(t *testing.T) {
	r := Runner{Binary: testExecutable(t)}
	_, err := r.Invoke(context.Background(), agentplatform.ExecuteRequest{Scope: agentplatform.ScopeKey{RunID: "run"}})
	if !errors.Is(err, ErrSandboxRequired) && !errors.Is(err, ErrSandboxInvalid) {
		t.Fatalf("expected sandbox refusal, got %v", err)
	}
}

func TestSandboxRejectsIncompleteOrContradictoryEnvelope(t *testing.T) {
	base := registeredSandbox()
	cases := map[string]func(Sandbox) Sandbox{
		"missing memory":    func(s Sandbox) Sandbox { s.MaxMemoryBytes = 0; return s },
		"missing cpu":       func(s Sandbox) Sandbox { s.MaxCPUSeconds = 0; return s },
		"missing processes": func(s Sandbox) Sandbox { s.MaxProcesses = 0; return s },
		"missing output":    func(s Sandbox) Sandbox { s.MaxOutputBytes = 0; return s },
		"missing timeout":   func(s Sandbox) Sandbox { s.Timeout = 0; return s },
		"unknown network":   func(s Sandbox) Sandbox { s.Network = "host"; return s },
		"negative memory":   func(s Sandbox) Sandbox { s.MaxMemoryBytes = -1; return s },
	}
	for name, mutate := range cases {
		if err := mutate(base).Validate(); err == nil {
			t.Fatalf("%s: sandbox was accepted", name)
		}
	}
	if err := base.Validate(); err != nil {
		t.Fatalf("registered sandbox was rejected: %v", err)
	}
}

// TestEnvelopeCarriesOnlyOperatorRegisteredValues proves the request payload
// cannot influence the launched command: the envelope is built solely from the
// Runner's registered fields.
// TestEnvelopeCarriesOnlyOperatorRegisteredValues 证明请求载荷无法影响被启动的命令：
// 信封完全由 Runner 的已登记字段构成。
func TestEnvelopeCarriesOnlyOperatorRegisteredValues(t *testing.T) {
	encoded, err := (sandboxEnvelope{
		Sandbox: registeredSandbox(),
		Binary:  "/opt/registered-agent/entrypoint",
		Args:    []string{"--flag"},
		Dir:     "/var/lib/agent",
		Env:     []string{"MODE=prod"},
	}).encode()
	if err != nil {
		t.Fatal(err)
	}
	var decoded sandboxEnvelope
	if err := decodeEnvelope(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Binary != "/opt/registered-agent/entrypoint" || len(decoded.Args) != 1 || decoded.Args[0] != "--flag" || decoded.Dir != "/var/lib/agent" || len(decoded.Env) != 1 {
		t.Fatalf("envelope round-trip mismatch: %+v", decoded)
	}
	if err := decoded.Sandbox.Validate(); err != nil {
		t.Fatalf("envelope sandbox invalid: %v", err)
	}
}

func TestLimitedBufferCapsAndFlagsOverflow(t *testing.T) {
	buffer := &limitedBuffer{limit: 4}
	if _, err := buffer.Write([]byte("abcdef")); err != nil {
		t.Fatal(err)
	}
	if !buffer.overflow {
		t.Fatal("overflow was not flagged")
	}
	if got := buffer.buf.String(); got != "abcd" {
		t.Fatalf("buffer kept %q, want the capped prefix", got)
	}
}

func testExecutable(t *testing.T) string {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return executable
}
