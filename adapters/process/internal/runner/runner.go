package runner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	agentplatform "github.com/lexagent/agent-platform-sdk-go/agentplatform"
)

// Runner executes one pre-registered command under a registered sandbox. The
// command, its arguments and its environment come only from operator
// configuration; the request payload is written to the child's stdin and can
// never introduce an executable, an argument or an environment variable.
// Runner 在已登记沙箱下执行单个预注册命令。命令、参数与环境仅来自运维配置；请求载荷只
// 写入子进程 stdin，绝不可能引入可执行文件、参数或环境变量。
type Runner struct {
	Binary  string
	Args    []string
	Dir     string
	Env     []string
	Sandbox Sandbox
	// Self is the trampoline binary the runner re-execs. It defaults to the
	// running executable. / Self 是 Runner 用于重启的跳板二进制，默认取当前可执行文件。
	Self string
}

func (r Runner) Invoke(ctx context.Context, request agentplatform.ExecuteRequest) (agentplatform.ExecuteResponse, error) {
	if r.Binary == "" || r.Binary[0] == '-' || strings.Contains(r.Binary, "..") || !filepath.IsAbs(r.Binary) {
		return agentplatform.ExecuteResponse{}, ErrInvalidDescriptor
	}
	if request.Scope.RunID == "" {
		return agentplatform.ExecuteResponse{}, ErrInvalidDescriptor
	}
	if r.Sandbox == (Sandbox{}) {
		return agentplatform.ExecuteResponse{}, ErrSandboxRequired
	}
	if err := r.Sandbox.Validate(); err != nil {
		return agentplatform.ExecuteResponse{}, err
	}
	if err := sandboxSupported(); err != nil {
		return agentplatform.ExecuteResponse{}, err
	}
	self := strings.TrimSpace(r.Self)
	if self == "" {
		resolved, err := os.Executable()
		if err != nil {
			return agentplatform.ExecuteResponse{}, err
		}
		self = resolved
	}
	spec, err := sandboxEnvelope{
		Sandbox: r.Sandbox,
		Binary:  r.Binary,
		Args:    append([]string(nil), r.Args...),
		Dir:     r.Dir,
		Env:     append([]string(nil), r.Env...),
	}.encode()
	if err != nil {
		return agentplatform.ExecuteResponse{}, err
	}
	payload, err := json.Marshal(request.Input)
	if err != nil {
		return agentplatform.ExecuteResponse{}, err
	}
	callCtx, cancel := context.WithTimeout(ctx, r.Sandbox.Timeout)
	defer cancel()
	cmd := exec.CommandContext(callCtx, self, TrampolineArg)
	cmd.Dir = r.Dir
	// The trampoline process receives only its own envelope; the registered
	// target environment travels inside the envelope so nothing from the
	// adapter's own environment is inherited by default. / 跳板进程只拿到自己的
	// 信封；目标命令的环境随信封传递，因此默认不继承 Adapter 自身的任何环境变量。
	cmd.Env = []string{sandboxSpecEnv + "=" + spec}
	cmd.Stdin = bytes.NewReader(payload)
	stdout := &limitedBuffer{limit: r.Sandbox.MaxOutputBytes}
	stderr := &limitedBuffer{limit: 64 << 10}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	if err := cmd.Run(); err != nil {
		return agentplatform.ExecuteResponse{}, fmt.Errorf("%w: %v", ErrProcessFailed, err)
	}
	if stdout.overflow {
		return agentplatform.ExecuteResponse{}, ErrOutputLimit
	}
	var output map[string]any
	if err := json.Unmarshal(stdout.buf.Bytes(), &output); err != nil {
		return agentplatform.ExecuteResponse{}, err
	}
	return agentplatform.ExecuteResponse{
		ProtocolVersion: agentplatform.ProtocolVersion,
		RunID:           request.Scope.RunID,
		Status:          "succeeded",
		OutputSchema:    "schema://process/output/v1",
		Output:          output,
	}, nil
}

// limitedBuffer writes at most limit bytes and remembers whether the producer
// tried to write more, so a runaway target cannot exhaust adapter memory and is
// reported as an explicit limit breach. / limitedBuffer 最多写入 limit 字节并记录
// 生产者是否越界，使失控目标既无法耗尽 Adapter 内存，又会被明确判定为越界。
type limitedBuffer struct {
	buf      bytes.Buffer
	limit    int64
	overflow bool
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if b.overflow {
		return len(p), nil
	}
	remaining := b.limit - int64(b.buf.Len())
	if remaining <= 0 {
		b.overflow = true
		return len(p), nil
	}
	if int64(len(p)) > remaining {
		_, _ = b.buf.Write(p[:remaining])
		b.overflow = true
		return len(p), nil
	}
	_, _ = b.buf.Write(p)
	return len(p), nil
}
